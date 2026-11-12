<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Rewraps the owners' keys onto the current wrapping key and, with rotation,
 * supersedes every live key, journalling each batch.
 *
 * The boundary is frozen at the start, so a key a concurrent write creates is
 * never superseded by the same run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Rewrapper
{
    /** @var string Why a batch is rolled back when an update does not change exactly the row it read. */
    private const string MISMATCH = 'A subject key changed while its batch was rewrapped; the batch is rolled back.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeySettings  $keys
     * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $keySigner
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \Illuminate\Database\DatabaseManager  $database
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The frame every batch runs in, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal every batch is appended to. */
        private Journal $journal,

        /** The signer each batch's replay verifies the journal with. */
        private JournalSigner $signer,

        /** The settings the journal's log id is read from. */
        private SealSettings $settings,

        /** The settings the batch size is read from. */
        private KeySettings $keys,

        /** Unwraps each key under its wrapping key and wraps it under the current one. */
        private KeyWrapper $wrapper,

        /** Verifies each key's row before its key is unwrapped. */
        private SubjectKeySigner $keySigner,

        /** The time a run's boundary is frozen at. */
        private Clock $clock,

        /** The manager the maintenance connection a dry run reads is resolved from. */
        private DatabaseManager $database,
    ) {}

    /**
     * Rewrap every key created before the run onto the current wrapping key,
     * superseding live keys with `$rotate`.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $rotate
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function rewrap(string $operationId, Authority $authority, bool $rotate, bool $dryRun): RewrapResult
    {
        $boundary = StoredTime::toStorage(StoredTime::format($this->clock->now()));

        if (!$dryRun) {
            $this->transaction->confirm();
        }

        $run = [
            'operation' => $operationId,
            'boundary'  => $boundary,
            'current'   => $this->wrapper->currentKeyId(),
            'rotate'    => $rotate,
            'limit'     => $this->keys->rewrapBatch(),
            'dry'       => $dryRun,
        ];

        $totals = ['rewrapped' => 0, 'rotated' => 0, 'skipped' => [], 'unnamed' => 0, 'batches' => 0];
        $replay = null;
        $after  = null;

        do {
            [$replay, $batch] = $dryRun
                ? [null, $this->plan($this->database->connection(StorageConnection::forMaintenance()), $after, $run)]
                : $this->transaction->run($operationId, fn (Connection $connection): array => $this->commit($connection, $replay, $authority, $after, $run));

            $totals = self::tally($totals, $batch);
            $after  = $batch['last'];
        } while ($batch['read'] === $run['limit']);

        $skipped = $totals['skipped'];

        $count = count($skipped) + $totals['unnamed'];

        return new RewrapResult($operationId, $dryRun, $rotate, $run['current'], $totals['rewrapped'], $totals['rotated'], $count, $skipped, $totals['batches']);
    }

    /**
     * Commit one batch: decide its keys after the lock, write each change, and
     * journal it when it changed or skipped a key.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  ?string  $after
     * @param  array{operation: string, boundary: string, current: string, rotate: bool, limit: int, dry: bool}  $run
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay, 1: array{read: int, last: ?string, changes: list<array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}>, skipped: list<string>, unnamed: int}}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function commit(Connection $connection, ?JournalReplay $replay, Authority $authority, ?string $after, array $run): array
    {
        $replay = $replay === null ? JournalReplay::start($this->signer, $this->settings->logId())->verify($connection) : $replay->advance($connection);
        $batch  = $this->plan($connection, $after, $run);

        if (!self::isRecorded($batch)) {
            return [$replay, $batch];
        }

        foreach ($batch['changes'] as $change) {
            self::apply($connection, $change);
        }

        $payload = [
            'run_id'  => $run['operation'],
            'rotate'  => $run['rotate'],
            'keys'    => array_map(static fn (#[\SensitiveParameter] array $change): array => self::entryOf($change), $batch['changes']),
            'skipped' => $batch['skipped'],
        ];

        if ($batch['unnamed'] > 0) {
            $payload['skipped_unnamed'] = $batch['unnamed'];
        }

        return [$this->journal->append($connection, $replay, JournalKind::REWRAP, $run['operation'], $authority, $payload), $batch];
    }

    /**
     * Read and decide the batch's keys; a skipped key is named only by a UUID
     * id, so no byte of an untrusted row reaches the journal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?string  $after
     * @param  array{operation: string, boundary: string, current: string, rotate: bool, limit: int, dry: bool}  $run
     * @return array{read: int, last: ?string, changes: list<array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}>, skipped: list<string>, unnamed: int}
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function plan(Connection $connection, ?string $after, array $run): array
    {
        $rows    = self::candidates($connection, $after, $run);
        $changes = [];
        $skipped = [];
        $unnamed = 0;
        $last    = $after;

        foreach ($rows as $row) {
            $id     = $row['id'] ?? null;
            $last   = is_string($id) ? $id : $last;
            $change = $this->changeOf($row, $run);

            if ($change !== null) {
                $changes[] = $change;
            } elseif (is_string($id) && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1) {
                $skipped[] = $id;
            } else {
                $unnamed++;
            }
        }

        sort($skipped, SORT_STRING);

        return ['read' => count($rows), 'last' => $last, 'changes' => $changes, 'skipped' => $skipped, 'unnamed' => $unnamed];
    }

    /**
     * The change the key takes, or `null` when it is skipped; every candidate
     * is unwrapped, so none is superseded that cannot be opened.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<string, scalar|null>  $row
     * @param  array{operation: string, boundary: string, current: string, rotate: bool, limit: int, dry: bool}  $run
     * @return ?array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}
     *
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function changeOf(#[\SensitiveParameter] array $row, array $run): ?array
    {
        $key = $this->authentic($row);

        if ($key === null || $key->wrappedKey === null || $key->wrapKeyId === null) {
            return null;
        }

        $state   = $run['rotate'] && $key->state === KeyState::LIVE ? KeyState::SUPERSEDED : $key->state;
        $wrapped = $this->rewrapped($key, $run['current'], $run['dry']);

        if ($key->wrapKeyId === $run['current']) {
            return $wrapped === null ? null : ['key' => $key, 'wrapped' => $key->wrappedKey, 'wrap_key_id' => $key->wrapKeyId, 'state' => $state];
        }

        return $wrapped === null ? null : ['key' => $key, 'wrapped' => $wrapped, 'wrap_key_id' => $run['current'], 'state' => $state];
    }

    /**
     * The stored row's key when it verifies under the signing key it names,
     * else `null`.
     *
     * @param  array<string, scalar|null>  $row
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function authentic(#[\SensitiveParameter] array $row): ?SubjectKeyRow
    {
        try {
            $key = SubjectKeyRow::fromRow($row);

            return $this->keySigner->verifies($key) ? $key : null;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // Skipped and named, for verification to report
            return null;
        }
    }

    /**
     * The data key wrapped under the current key, or `null` unless it reopens;
     * the stored wrapped key is the only copy.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  string  $current
     * @param  bool  $dry
     * @return ?string
     *
     * @throws \Throwable
     */
    private function rewrapped(#[\SensitiveParameter] SubjectKeyRow $key, string $current, bool $dry): ?string
    {
        $dataKey = $this->opened((string) $key->wrappedKey, (string) $key->wrapKeyId, $key->wrapContext());

        if ($dataKey === null) {
            return null;
        }

        if ($dry || $key->wrapKeyId === $current) {
            return $key->wrappedKey;
        }

        $context  = SubjectKeyRow::wrapContextOf($key->id, $key->unit, $key->generation, $current);
        $wrapped  = $this->wrapper->wrap($dataKey, $current, $context);
        $reopened = $this->opened($wrapped, $current, $context);

        return $reopened !== null && hash_equals($dataKey, $reopened) ? $wrapped : null;
    }

    /**
     * The data key, or `null` when it does not unwrap; the wrapper's exception
     * is dropped, as it could name the key.
     *
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return ?string
     */
    private function opened(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): ?string
    {
        try {
            return $this->wrapper->unwrap($wrapped, $wrapKeyId, $context);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Up to a batch of the keys the run considers after the id, in id order, on
     * the writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?string  $after
     * @param  array{operation: string, boundary: string, current: string, rotate: bool, limit: int, dry: bool}  $run
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    private static function candidates(Connection $connection, ?string $after, array $run): array
    {
        $query = $connection->table(KeyTables::subjectKeysTable())
            ->useWritePdo()
            ->where('created_at', '<=', $run['boundary'])
            ->whereIn('state', [KeyState::LIVE->value, KeyState::SUPERSEDED->value])
            ->where(static function (Builder $query) use ($run): void {
                $query->where('wrap_key_id', '<>', $run['current']);

                if (!$run['rotate']) {
                    return;
                }

                $query->orWhere('state', KeyState::LIVE->value);
            })
            ->orderBy('id')
            ->limit($run['limit']);

        if ($after !== null) {
            $query->where('id', '>', $after);
        }

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (object $stored): array => (array) $stored, $query->get()->all()));
    }

    /**
     * Write the change with a compare-and-set update, refusing anything but one
     * row; failures are masked so no wrapped key is reported.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}  $change
     * @return void
     *
     * @throws \UnexpectedValueException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function apply(Connection $connection, #[\SensitiveParameter] array $change): void
    {
        $key     = $change['key'];
        $columns = $change['wrap_key_id'] === $key->wrapKeyId ? [] : ['wrapped_key' => $change['wrapped'], 'wrap_key_id' => $change['wrap_key_id']];

        if ($change['state'] !== $key->state) {
            $columns['state'] = $change['state']->value;
        }

        try {
            $updated = $connection->table(KeyTables::subjectKeysTable())
                ->where('id', $key->id)
                ->where('state', $key->state->value)
                ->where('wrapped_key', $key->wrappedKey)
                ->update($columns);
        } catch (QueryException $failure) { // @phpstan-ignore catch.neverThrown
            FailureClassifier::rethrowMasked($failure);
        }

        if ($updated !== 1) {
            throw new \UnexpectedValueException(self::MISMATCH);
        }
    }

    /**
     * What a batch's row lists of a changed key, before and after.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}  $change
     * @return array{key_id: string, before: array{state: string, wrapped_digest: ?string, wrap_key_id: ?string}, after: array{state: string, wrapped_digest: string, wrap_key_id: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function entryOf(#[\SensitiveParameter] array $change): array
    {
        $key = $change['key'];

        return [
            'key_id' => $key->id,
            'before' => ['state' => $key->state->value, 'wrapped_digest' => $key->wrappedDigest(), 'wrap_key_id' => $key->wrapKeyId],
            'after'  => ['state' => $change['state']->value, 'wrapped_digest' => hash('sha256', $change['wrapped']), 'wrap_key_id' => $change['wrap_key_id']],
        ];
    }

    /**
     * The run's totals with the batch's added.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{rewrapped: int, rotated: int, skipped: list<string>, unnamed: int, batches: int}  $totals
     * @param  array{read: int, last: ?string, changes: list<array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}>, skipped: list<string>, unnamed: int}  $batch
     * @return array{rewrapped: int, rotated: int, skipped: list<string>, unnamed: int, batches: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function tally(array $totals, #[\SensitiveParameter] array $batch): array
    {
        foreach ($batch['changes'] as $change) {
            $totals['rewrapped'] += $change['wrap_key_id'] === $change['key']->wrapKeyId ? 0 : 1;
            $totals['rotated']   += $change['state']       === $change['key']->state ? 0 : 1;
        }

        $totals['skipped'] = [...$totals['skipped'], ...$batch['skipped']];
        $totals['unnamed'] += $batch['unnamed'];
        $totals['batches'] += self::isRecorded($batch) ? 1 : 0;

        return $totals;
    }

    /**
     * Whether the batch changed or skipped a key, and so is journalled.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{read: int, last: ?string, changes: list<array{key: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, wrapped: string, wrap_key_id: string, state: \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState}>, skipped: list<string>, unnamed: int}  $batch
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isRecorded(#[\SensitiveParameter] array $batch): bool
    {
        return $batch['changes'] !== [] || $batch['skipped'] !== [] || $batch['unnamed'] > 0;
    }
}
