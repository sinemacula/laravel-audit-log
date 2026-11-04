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
 * Rewraps the owners' keys onto the key wrapper's current wrapping key, and
 * with rotation supersedes every live key, so the next write of each unit opens
 * the unit's next generation: rotation is not rewrap, and both are journalled.
 *
 * A run confirms the installation first, once, and never in a dry run. Its
 * boundary is frozen at its start: only keys created at or before that instant
 * are considered, so a key a concurrent write creates under the current key is
 * never superseded by the same run. Its current wrapping key is read once, at
 * its start. The keys it considers are those live or superseded and wrapped
 * under another key than the current, and with rotation every live key too;
 * erased keys hold no wrapped key and are never touched.
 *
 * The keys are walked in batches of `audit-log.privacy.rewrap_batch`, by id,
 * each batch after the last id of the one before, each in a lifecycle
 * transaction of its own: the lock, the journal verified for the first batch
 * and advanced from the last committed head for each later one, then the
 * batch's keys read after the lock. A key whose row fails its signature, names
 * a signing key the ring does not hold or cannot be read is skipped and never
 * rewrapped; so is one whose wrapped key does not unwrap under its own wrap
 * context. Every other key's data key is wrapped again under the current key,
 * bound to its row, unit, generation and the current key's id, and written with
 * a compare-and-set update on its id, its state and the wrapped key it was read
 * with, rotation setting `superseded` in the same statement; a key already
 * under the current key is unwrapped too, then only superseded. A new wrapped
 * key must unwrap to the same data key before it replaces the stored one, which
 * is the only copy, or the key is skipped and left as it was. A skipped key is
 * named by its id only when that id is a lower-case UUID, and counted either
 * way. An update that changes anything but the one row it read rolls the batch
 * back and fails the run, so a key changed behind the lock is never
 * overwritten. A batch that changed or skipped a key appends one `rewrap` row
 * listing each key's state, wrapped key digest and wrapping key before and
 * after, the keys it skipped and, when there were any, how many it skipped
 * without naming (`skipped_unnamed`), and it commits with its updates or not at
 * all.
 *
 * A run that fails throws, and the batches it committed stand. A dry run takes
 * no lock and writes nothing: it reads the same keys the same way on the
 * maintenance connection, authenticates and unwraps them, and counts what a run
 * would do, wrapping nothing.
 *
 * Rewrapping changes how a data key is stored, never what it opens: whoever
 * holds the maintenance credentials can still change a key's wrapping, and the
 * wrap context and the journal make that detectable, not impossible.
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
     * Rewrap every key created before the run that is not wrapped under the
     * current wrapping key, and with `$rotate` supersede every live key, in
     * batches each journalled; or with `$dryRun` count what a run would do.
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
     * Commit one batch inside the lifecycle transaction the connection holds:
     * the journal verified or advanced, the batch's keys read and decided after
     * the lock, each change written, and the batch's row appended when it
     * changed or skipped a key. The replay the batch leaves and the batch are
     * returned.
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
     * Read the batch's keys after the id on the connection and decide each: the
     * change it takes, or skipped. How many keys were read, the last id read,
     * the changes in id order, the skipped ids, sorted, and how many skipped
     * keys were not named are returned. A skipped key is named only by an id
     * that is a lower-case UUID, since its row is the one that could not be
     * trusted, so no byte it holds reaches a console or the journal; one
     * without such an id is counted alone.
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
     * The change the stored key takes: its data key wrapped under the current
     * key unless it already is, and `superseded` when the run rotates a live
     * key; `null` when the key is skipped, as one whose row does not
     * authenticate or whose wrapped key does not unwrap. Every candidate is
     * unwrapped, one already under the current key included, so no key is
     * superseded or counted that could not be opened. A dry run wraps nothing
     * and keeps the stored wrapped key in its place.
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
     * The key of the stored row when the row verifies under the signing key it
     * names, and `null` when it does not, when the ring does not hold that key,
     * or when the row cannot be read.
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
            // A key that cannot be authenticated is never rewrapped: it is
            // skipped and named, for verification to report
            return null;
        }
    }

    /**
     * The key's data key wrapped under the current key, bound to the key's row,
     * unit and generation and the current key's id, or `null` when its wrapped
     * key does not unwrap under its own wrap context, or when the new wrapped
     * key does not unwrap to the same data key under its own: the stored
     * wrapped key is the only copy, so it is never replaced by one that could
     * not be opened. A key already under the current key, and every key of a
     * dry run, is unwrapped only, and its stored wrapped key given back.
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
        // A key that does not unwrap is left as it is, skipped and named:
        // whatever wrapped it, the run cannot wrap it again
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

        // A wrapper that cannot open what it wrapped leaves the key as it is,
        // skipped and named
        return $reopened !== null && hash_equals($dataKey, $reopened) ? $wrapped : null;
    }

    /**
     * The data key the wrapped key holds under the wrapping key and context, or
     * `null` when it does not unwrap, whatever the wrapper threw, which could
     * name the key.
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
     * Up to a batch of the keys the run considers after the id, or from the
     * first, in id order, on the connection's writer, each as its stored row:
     * created at or before the run's boundary, live or superseded, and wrapped
     * under another key than the current, or with rotation live.
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
     * Write the change with a compare-and-set update on the key's id, state and
     * the wrapped key it was read with, refusing anything but one row changed.
     * A failed statement is thrown masked, so no wrapped key reaches a
     * reporter.
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
     * What a batch's row lists of a key it changed: its id, and its state, the
     * digest of its wrapped key and its wrapping key's id before and after.
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
     * The run's totals with the batch's added: the keys it rewrapped onto
     * another wrapping key, the live keys it superseded, the keys it skipped,
     * and the batch itself when it changed or skipped one.
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
