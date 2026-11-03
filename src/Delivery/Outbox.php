<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The outbox table, on the outbox connection's writer: where a record waits,
 * its envelope encrypted, until a drain delivers it.
 *
 * A drain reads the ids of the rows that are due, unfailed and unclaimed, then
 * claims each with one conditional update that holds only while the row is
 * still all three, so of two drains racing for a row exactly one wins, on every
 * engine and without `SKIP LOCKED`. A claim counts an attempt, so an attempt
 * that kills its worker still counts, writes a lease that ends
 * `delivery.outbox.lease_seconds` from now, and writes a token of its own.
 * Every later change to the row (a renewal, a retry, a failure, the delete)
 * requires that token, so once the lease has passed and another drain owns the
 * row, the first changes nothing and is told so.
 *
 * An insert runs alone outside a transaction and in a savepoint inside one, so
 * a failed insert leaves the transaction as it was. Every read is on the
 * writer, so a lagging replica never answers. A failed row is kept, with the
 * class of its last error and never a message, until a replay requeues it.
 * Times are written in UTC by the package's clock, so leases are judged by each
 * worker's clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Outbox
{
    /** @var int Ids requeued by one statement, so a long list never exceeds what an engine binds. */
    private const int REQUEUE_CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DeliverySettings  $settings
     */
    public function __construct(

        /** The connections the outbox connection is resolved from on every call. */
        private ConnectionResolverInterface $connections,

        /** The clock every time the outbox writes or compares is read from. */
        private Clock $clock,

        /** The delivery settings the lease is read from. */
        private DeliverySettings $settings,
    ) {}

    /**
     * The outbox connection, which must be a database connection, so it has
     * transaction levels and savepoints.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \LogicException
     */
    public function connection(): Connection
    {
        $connection = $this->connections->connection(DeliveryTables::outboxConnection());

        if (!$connection instanceof Connection) {
            throw new \LogicException(sprintf('The outbox connection [%s] is not a database connection that supports transactions.', DeliveryTables::resolvedOutboxConnection()));
        }

        return $connection;
    }

    /**
     * The outbox connection's name as the connection gives it, so a name that
     * selects a connection's reader or writer is compared as the connection.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function connectionName(): string
    {
        return $this->connection()->getName() ?? DeliveryTables::resolvedOutboxConnection();
    }

    /**
     * Whether a transaction is open on the outbox connection.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function isInTransaction(): bool
    {
        return $this->connection()->transactionLevel() > 0;
    }

    /**
     * Insert a row for the record under the id, holding the payload, due now
     * and with no attempt yet: alone outside a transaction, and in a savepoint
     * of one attempt inside one, so a failed insert rolls back to it and leaves
     * the transaction as it was.
     *
     * @param  string  $id
     * @param  string  $payload
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function insert(string $id, #[\SensitiveParameter] string $payload): void
    {
        $connection = $this->connection();
        $table      = DeliveryTables::outboxTable();
        $now        = $this->stamp($this->clock->now());

        $row = [
            'id'           => $id,
            'payload'      => $payload,
            'attempts'     => 0,
            'available_at' => $now,
            'created_at'   => $now,
        ];

        if ($connection->transactionLevel() === 0) {
            $connection->table($table)->insert($row);

            return;
        }

        $connection->transaction(static function (Connection $nested) use ($table, $row): void {
            try {
                $nested->table($table)->insert($row);
            } catch (QueryException $exception) { // @phpstan-ignore catch.neverThrown
                throw FailureClassifier::masked($exception);
            }
        });
    }

    /**
     * The ids of at most the limit of rows a drain may claim: not failed, due
     * by the instant given, and with no lease or one that has passed, oldest
     * due first and then by id. No payload is read.
     *
     * @param  int  $limit
     * @param  \Carbon\CarbonImmutable  $due
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function candidates(int $limit, CarbonImmutable $due): array
    {
        // An id column reads back as a string on every engine
        /** @var list<string> */
        return $this->claimable($this->table(), $due)
            ->orderBy('available_at')
            ->orderBy('id')
            ->limit($limit)
            ->pluck('id')
            ->all();
    }

    /**
     * Claim the row under the id, while it is still not failed, due by the
     * instant given and unleased or past its lease: one conditional update that
     * writes a new token and a lease and counts an attempt, then a read of the
     * payload by that token. `null` when the update changed no row, because
     * another drain claimed it first or it changed since it was a candidate,
     * and then nothing is read.
     *
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $due
     * @return ?\SineMacula\Laravel\AuditLog\Delivery\OutboxClaim
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function claim(string $id, CarbonImmutable $due): ?OutboxClaim
    {
        $token = Str::uuid()->toString();

        $claimed = $this->claimable($this->table()->where('id', $id), $due)
            ->increment('attempts', 1, ['claimed_by' => $token, 'claimed_until' => $this->leaseEnd()]);

        if ($claimed === 0) {
            return null;
        }

        // A text column reads back as a string and an integer column as an
        // integer, on every engine
        /** @var (object{payload: string, attempts: int}&\stdClass)|null $row */
        $row = $this->table()->where('id', $id)->where('claimed_by', $token)->first(['payload', 'attempts']);

        return $row === null ? null : new OutboxClaim($id, $token, $row->payload, $row->attempts);
    }

    /**
     * Extend the claim's lease to `delivery.outbox.lease_seconds` from now, and
     * say whether the claim still owns the row. A renewal that changes no row
     * is followed by a read by the token, because MySQL counts the rows an
     * update changed rather than those it matched, and a renewal within the
     * same microsecond changes nothing; only when that read finds no row has
     * the claim lost it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    public function renew(#[\SensitiveParameter] OutboxClaim $claim): bool
    {
        return $this->owned($claim)->update(['claimed_until' => $this->leaseEnd()]) > 0
            || $this->owned($claim)->exists();
    }

    /**
     * Release the claim's row for another attempt once the instant given has
     * come, naming the class of the error that stopped this one. Returns
     * whether the claim still owned the row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \Carbon\CarbonImmutable  $availableAt
     * @param  string  $errorClass
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    public function retry(#[\SensitiveParameter] OutboxClaim $claim, CarbonImmutable $availableAt, string $errorClass): bool
    {
        return $this->owned($claim)->update([
            'available_at'     => $this->stamp($availableAt),
            'last_error_class' => self::bounded($errorClass),
            'claimed_by'       => null,
            'claimed_until'    => null,
        ]) > 0;
    }

    /**
     * Fail the claim's row now, naming the class of the error that stopped it
     * or the fixed word for why, and release it: the row is kept, and no drain
     * claims it again until a replay requeues it. Returns whether the claim
     * still owned the row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $errorClass
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    public function fail(#[\SensitiveParameter] OutboxClaim $claim, string $errorClass): bool
    {
        return $this->owned($claim)->update([
            'failed_at'        => $this->stamp($this->clock->now()),
            'last_error_class' => self::bounded($errorClass),
            'claimed_by'       => null,
            'claimed_until'    => null,
        ]) > 0;
    }

    /**
     * Delete the claim's row, once every destination has the record. Returns
     * whether a row went, which it does only while the claim owns it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function delete(#[\SensitiveParameter] OutboxClaim $claim): bool
    {
        return $this->owned($claim)->delete() > 0;
    }

    /**
     * The ids of every failed row, in order.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function failedIds(): array
    {
        // An id column reads back as a string on every engine
        /** @var list<string> */
        return $this->table()->whereNotNull('failed_at')->orderBy('id')->pluck('id')->all();
    }

    /**
     * Requeue the failed rows among the ids: each is unfailed, its attempts
     * reset, due now and unclaimed, and the class of its last error is kept. A
     * row that is not failed is left as it is. Returns how many rows were
     * requeued.
     *
     * @param  list<string>  $ids
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function requeueFailed(array $ids): int
    {
        $requeued = 0;
        $now      = $this->stamp($this->clock->now());

        foreach (array_chunk($ids, self::REQUEUE_CHUNK) as $chunk) {
            $requeued += $this->table()->whereIn('id', $chunk)->whereNotNull('failed_at')->update([
                'failed_at'     => null,
                'attempts'      => 0,
                'available_at'  => $now,
                'claimed_by'    => null,
                'claimed_until' => null,
            ]);
        }

        return $requeued;
    }

    /**
     * A query of the outbox table on the writer.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function table(): Builder
    {
        return $this->connection()->table(DeliveryTables::outboxTable())->useWritePdo();
    }

    /**
     * The query narrowed to the rows a drain may claim: not failed, due by the
     * instant given, and with no lease or one that has passed.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \Carbon\CarbonImmutable  $due
     * @return \Illuminate\Database\Query\Builder
     */
    private function claimable(Builder $query, CarbonImmutable $due): Builder
    {
        $now = $this->stamp($this->clock->now());

        return $query
            ->whereNull('failed_at')
            ->where('available_at', '<=', $this->stamp($due))
            ->where(static fn (Builder $lease): Builder => $lease->whereNull('claimed_until')->orWhere('claimed_until', '<', $now));
    }

    /**
     * A query of the claim's row, by its id and its token.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function owned(#[\SensitiveParameter] OutboxClaim $claim): Builder
    {
        return $this->table()->where('id', $claim->id)->where('claimed_by', $claim->token);
    }

    /**
     * When a lease taken or renewed now ends, as the database stores it.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function leaseEnd(): string
    {
        return $this->stamp($this->clock->now()->addSeconds($this->settings->leaseSeconds()));
    }

    /**
     * The instant as the database stores it, in UTC.
     *
     * @param  \DateTimeInterface  $instant
     * @return string
     */
    private function stamp(\DateTimeInterface $instant): string
    {
        return StoredTime::toStorage(StoredTime::format($instant));
    }

    /**
     * The error class cut to what its column holds.
     *
     * @param  string  $errorClass
     * @return string
     */
    private static function bounded(string $errorClass): string
    {
        return mb_strcut($errorClass, 0, WriteDiagnostics::CLASS_MAX_BYTES, 'UTF-8');
    }
}
