<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Writes again the activity records the journal says are missing: for every
 * prune run that finished, every hold, every release, every import that
 * finished, every erasure, every reinstatement and every rewrap run within the
 * days looked back, the record of its code is written through
 * `LifecycleRecorder` unless an entry of that code already names the operation,
 * or the record's id, derived from its code and its operation, is already
 * stored or, in outbox mode, queued in the outbox.
 *
 * The journal's rows of those kinds, and the starts of runs and imports, are
 * read by kind and time on the storage connection's writer, a page at a time;
 * each row's signature and payload digest are verified, and a row that does not
 * verify, or an operation whose start row is not among the verified rows, is
 * counted `unverifiable` and never recorded. A start before the window is
 * looked for backwards from it, a page at a time, only when its finish is in
 * the window. The entries of the seven codes within the window are read by
 * event and time, and the operation each names is read from its decoded
 * properties in PHP, never by a JSON path query, so every engine reads them
 * alike. The derived ids are looked for by primary key in the entries and, in
 * outbox mode, in the outbox, a page at a time, so a record still waiting for
 * its delivery counts as recorded; in sync mode no record is ever queued there,
 * and the writer holds no grant on the outbox, so it is never read. An
 * operation is recorded at most once per run, so a second run records nothing,
 * whether or not the outbox drained between them; a prune run that started and
 * has not finished has nothing to record and is counted `unfinished`.
 *
 * A record is written again with the properties its journal rows give, built by
 * `ReconciledOperations`: a prune's tenants affected and the reason a failed
 * prune gave included, since its finish row holds them, and a rewrap run's
 * counts summed over its batches in the window; one the rows do not hold is
 * `null`. A refused erasure or reinstatement wrote no row, so it is never
 * reconciled; a rewrap that failed after committing batches, whose own failure
 * record is missing, is recorded from those batches. Nothing here takes the
 * lifecycle lock, so the reconciler is never scheduled; but a record keeps its
 * derived id however it is written, so two runs at once, or a run alongside an
 * operation still writing its own record, never write it twice: the second
 * write meets the outbox's or the entries' primary key and is counted `failed`,
 * or is the record stored already.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Reconciler
{
    /** @var int How many days are looked back when no other number is given. */
    public const int DEFAULT_SINCE_DAYS = 7;

    /** @var int Most days a reconciliation may look back: ten years. */
    public const int MAX_SINCE_DAYS = 3650;

    /** @var int Rows read by one statement. */
    private const int PAGE = 500;

    /** @var string The phase a prune run's finish row names. */
    private const string FINISH = 'finish';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder  $recorder
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DeliverySettings  $delivery
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every run. */
        private DatabaseManager $database,

        /** The signer each journal row is verified with. */
        private JournalSigner $signer,

        /** The writer of each missing record. */
        private LifecycleRecorder $recorder,

        /** The time the window ends at. */
        private Clock $clock,

        /** The delivery mode, which says whether a record may wait in the outbox. */
        private DeliverySettings $delivery,
    ) {}

    /**
     * Record every operation journalled within the days looked back, from 1 to
     * 3650, that no entry records, and return the tally.
     *
     * @param  int  $sinceDays
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReconcileResult
     *
     * @throws \InvalidArgumentException
     */
    public function reconcile(int $sinceDays = self::DEFAULT_SINCE_DAYS): ReconcileResult
    {
        if ($sinceDays < 1 || $sinceDays > self::MAX_SINCE_DAYS) {
            throw new \InvalidArgumentException(sprintf('A reconciliation looks back from 1 to %d days.', self::MAX_SINCE_DAYS));
        }

        $since      = StoredTime::toStorage(StoredTime::format($this->clock->now()->subDays($sinceDays)));
        $connection = $this->database->connection(StorageConnection::resolvedName());

        [$operations, $unverifiable, $unfinished] = $this->operations($connection, $since);

        $recorded = $this->recordedSince($connection, $since, $operations);
        $counts   = ['recorded' => 0, 'already' => 0, 'failed' => 0];

        foreach ($operations as [$activity, $actor, $evidence, $outcome, $reason]) {
            $key = $activity->value . "\0" . $evidence->operationId;

            if (isset($recorded[$key])) {
                $counts['already']++;

                continue;
            }

            $written = $this->recorder->record($activity, $actor, $evidence, $outcome, $reason);

            $counts[$written ? 'recorded' : 'failed']++;
            $recorded[$key] = true;
        }

        return new ReconcileResult($counts['recorded'], $counts['already'], $unverifiable, $unfinished, $counts['failed']);
    }

    /**
     * The operations journalled since the time, each as the record it needs, in
     * journal order, with the rows and operations that do not verify and the
     * prune runs that have not finished counted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $since
     * @return array{0: list<array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}>, 1: int, 2: int}
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function operations(Connection $connection, string $since): array
    {
        [$rows, $unverifiable] = $this->journalSince($connection, $since);

        $runs       = self::startsAmong($rows, JournalKind::PRUNE_RUN, 'run_id');
        $batches    = self::startsAmong($rows, JournalKind::IMPORT_STARTED, 'batch_id');
        $unfinished = count(array_diff_key($runs, self::finishedAmong($rows, JournalKind::PRUNE_RUN, [])));

        $runs    += $this->startsBefore($connection, $since, JournalKind::PRUNE_RUN, 'run_id', self::finishedAmong($rows, JournalKind::PRUNE_RUN, $runs));
        $batches += $this->startsBefore($connection, $since, JournalKind::IMPORT_STARTED, 'batch_id', self::finishedAmong($rows, JournalKind::IMPORT_FINISHED, $batches));

        $operations = [];

        foreach ($rows as [$row, $payload]) {
            $operation = self::operationOf($row, $payload, $runs, $batches);

            if ($operation === false) {
                continue;
            }

            if ($operation === null) {
                $unverifiable++;

                continue;
            }

            $operations[] = $operation;
        }

        foreach (ReconciledOperations::rewrapped($rows) as $operation) {
            if ($operation === null) {
                $unverifiable++;

                continue;
            }

            $operations[] = $operation;
        }

        return [$operations, $unverifiable, $unfinished];
    }

    /**
     * The record the verified row's operation needs, `null` when the row, or
     * the start row it needs, does not describe its operation, and `false` for
     * a row that records no operation of its own: a start, or a rewrap batch,
     * whose run is recorded from all of its batches together.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @param  array<string, array<array-key, mixed>>  $runs
     * @param  array<string, array<array-key, mixed>>  $batches
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}|false|null
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function operationOf(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload, array $runs, array $batches): array|false|null
    {
        $finish = self::finishIdOf($row, $payload);

        return match (true) {
            $row->kind === JournalKind::HOLD            => ReconciledOperations::held($row, $payload),
            $row->kind === JournalKind::RELEASE         => ReconciledOperations::released($row, $payload),
            $row->kind === JournalKind::ERASURE         => ReconciledOperations::erased($row, $payload),
            $row->kind === JournalKind::REINSTATE       => ReconciledOperations::reinstated($row, $payload),
            $finish    === null                         => false,
            $row->kind === JournalKind::IMPORT_FINISHED => ReconciledOperations::imported($row, $payload, $batches[$finish] ?? null),
            default                                     => ReconciledOperations::pruned($payload, $runs[$finish] ?? null),
        };
    }

    /**
     * The verified rows of the kinds that record or start an operation since
     * the time, each with its payload, in time order, and how many rows did not
     * verify.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $since
     * @return array{0: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}>, 1: int}
     *
     * @throws \InvalidArgumentException
     */
    private function journalSince(Connection $connection, string $since): array
    {
        $kinds = [
            JournalKind::PRUNE_RUN, JournalKind::HOLD, JournalKind::RELEASE, JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED,
            JournalKind::ERASURE, JournalKind::REINSTATE, JournalKind::REWRAP,
        ];
        $query = $connection->table(LifecycleTables::journalTable())
            ->useWritePdo()
            ->whereIn('kind', array_map(static fn (JournalKind $kind): string => $kind->value, $kinds))
            ->where('occurred_at', '>=', $since);

        $rows         = [];
        $unverifiable = 0;

        self::eachRow($query, true, function (#[\SensitiveParameter] array $stored) use (&$rows, &$unverifiable): bool {
            $verified = $this->verified($stored);

            if ($verified === null) {
                $unverifiable++;

                return true;
            }

            $rows[] = $verified;

            return true;
        });

        return [$rows, $unverifiable];
    }

    /**
     * The verified start rows of the kind before the time that name the wanted
     * ids under the payload key, each by its id, read backwards from the time,
     * a page at a time, until each is found; a row that does not verify is
     * passed over.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $since
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  'batch_id'|'run_id'  $key
     * @param  array<string, true>  $wanted
     * @return array<string, array<array-key, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    private function startsBefore(Connection $connection, string $since, JournalKind $kind, string $key, array $wanted): array
    {
        if ($wanted === []) {
            return [];
        }

        $query = $connection->table(LifecycleTables::journalTable())
            ->useWritePdo()
            ->where('kind', $kind->value)
            ->where('occurred_at', '<', $since);

        $found = [];

        self::eachRow($query, false, function (#[\SensitiveParameter] array $stored) use ($kind, $key, &$wanted, &$found): bool {
            $verified = $this->verified($stored);
            $id       = $verified === null ? null : self::startIdOf($verified[0], $verified[1], $kind, $key);

            if ($verified !== null && $id !== null && isset($wanted[$id])) {
                $found[$id] = $verified[1];

                unset($wanted[$id]);
            }

            return $wanted !== [];
        });

        return $found;
    }

    /**
     * Each operation recorded already, by its code and its operation id: those
     * an entry of the four codes since the time names in its decoded
     * properties, and those among the operations given whose record's derived
     * id the entries hold, or the outbox in outbox mode.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $since
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}>  $operations
     * @return array<string, true>
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function recordedSince(Connection $connection, string $since, array $operations): array
    {
        $codes = [
            PackageActivity::PRUNED, PackageActivity::HELD, PackageActivity::RELEASED, PackageActivity::IMPORTED,
            PackageActivity::SUBJECT_ERASED, PackageActivity::KEYS_REINSTATED, PackageActivity::KEYS_REWRAPPED,
        ];
        $query = $connection->table(EntrySettings::table())
            ->useWritePdo()
            ->select(['id', 'event', 'occurred_at', 'properties'])
            ->whereIn('event', array_map(static fn (PackageActivity $code): string => $code->value, $codes))
            ->where('occurred_at', '>=', $since);

        $recorded = [];

        self::eachRow($query, true, static function (#[\SensitiveParameter] array $stored) use (&$recorded): bool {
            $properties  = is_string($stored['properties'] ?? null) ? json_decode($stored['properties'], true) : null;
            $operationId = is_array($properties) ? ($properties[LifecycleEvidence::OPERATION_KEY] ?? null) : null;

            if (is_string($operationId) && is_string($stored['event'] ?? null)) {
                $recorded[$stored['event'] . "\0" . $operationId] = true;
            }

            return true;
        });

        $keys = [];

        foreach ($operations as [$activity, , $evidence]) {
            $keys[LifecycleRecorder::recordIdOf($activity, $evidence->operationId)] = $activity->value . "\0" . $evidence->operationId;
        }

        $present = static fn (Connection $on, string $table): array => array_merge(...array_map(
            static fn (array $chunk): array => $on->table($table)->useWritePdo()->whereIn('id', $chunk)->pluck('id')->all(),
            array_chunk(array_keys($keys), self::PAGE),
        ));

        $ids = $present($connection, EntrySettings::table());

        if ($this->delivery->mode() === DeliveryMode::OUTBOX) {
            $ids = [...$ids, ...$present($this->database->connection(DeliveryTables::resolvedOutboxConnection()), DeliveryTables::outboxTable())];
        }

        foreach (array_intersect_key($keys, array_flip($ids)) as $key) {
            $recorded[$key] = true;
        }

        return $recorded;
    }

    /**
     * The row with its decoded payload, when its signature and its payload's
     * digest verify; `null` for a row that cannot be read, is signed under a
     * key the ring does not hold, or does not verify.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}
     */
    private function verified(#[\SensitiveParameter] array $stored): ?array
    {
        try {
            $row = JournalRow::fromRow($stored, true);

            if (!$row->hasPayloadOfItsDigest() || !$this->signer->verifies($row)) {
                return null;
            }

            return [$row, $row->payloadMap() ?? []];
        } catch (\JsonException|\UnexpectedValueException|UnknownKeyException) {
            // A row that cannot be read or verified is never recorded
            return null;
        }
    }

    /**
     * The payloads of the start rows of the kind among the verified rows, each
     * by the id under the payload key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}>  $rows
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  'batch_id'|'run_id'  $key
     * @return array<string, array<array-key, mixed>>
     */
    private static function startsAmong(#[\SensitiveParameter] array $rows, JournalKind $kind, string $key): array
    {
        $starts = [];

        foreach ($rows as [$row, $payload]) {
            $id = self::startIdOf($row, $payload, $kind, $key);

            if ($id === null) {
                continue;
            }

            $starts[$id] = $payload;
        }

        return $starts;
    }

    /**
     * The ids of the operations the finish rows of the kind among the verified
     * rows finish, but those whose start is among the starts given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}>  $rows
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<string, array<array-key, mixed>>  $starts
     * @return array<string, true>
     */
    private static function finishedAmong(#[\SensitiveParameter] array $rows, JournalKind $kind, array $starts): array
    {
        $finished = [];

        foreach ($rows as [$row, $payload]) {
            $id = $row->kind === $kind ? self::finishIdOf($row, $payload) : null;

            if ($id === null || isset($starts[$id])) {
                continue;
            }

            $finished[$id] = true;
        }

        return $finished;
    }

    /**
     * The id under the payload key of a row that starts an operation of the
     * kind, a prune run's start row or an import's, or `null` for any other
     * row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  'batch_id'|'run_id'  $key
     * @return ?string
     */
    private static function startIdOf(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload, JournalKind $kind, string $key): ?string
    {
        $id = $payload[$key] ?? null;

        return $row->kind === $kind && is_string($id) && ($payload['phase'] ?? null) !== self::FINISH ? $id : null;
    }

    /**
     * The id of the operation a finish row finishes, a prune run's under
     * `run_id` or an import's under `batch_id`, or `null` for any other row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?string
     */
    private static function finishIdOf(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?string
    {
        $id = match (true) {
            $row->kind === JournalKind::IMPORT_FINISHED                                           => $payload['batch_id'] ?? null,
            $row->kind === JournalKind::PRUNE_RUN && ($payload['phase'] ?? null) === self::FINISH => $payload['run_id']   ?? null,
            default                                                                               => null,
        };

        return is_string($id) ? $id : null;
    }

    /**
     * Hand each row of the query to the callback, in time and then id order,
     * oldest or newest first, a page to a statement, each page seeking past the
     * last row of the one before, until the rows run out or the callback
     * answers `false`.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool  $ascending
     * @param  \Closure(array<string, scalar|null>): bool  $each
     * @return void
     */
    private static function eachRow(Builder $query, bool $ascending, #[\SensitiveParameter] \Closure $each): void
    {
        [$direction, $through, $past] = $ascending ? ['asc', '>=', '>'] : ['desc', '<=', '<'];

        $after = null;

        do {
            $page = clone $query;

            if ($after !== null) {
                $page->where('occurred_at', $through, $after[0])
                    ->where(static fn (Builder $seek): Builder => $seek->where('occurred_at', $past, $after[0])->orWhere('id', $past, $after[1]));
            }

            $rows = $page->orderBy('occurred_at', $direction)->orderBy('id', $direction)->limit(self::PAGE)->get()->all();

            foreach ($rows as $row) {
                /** @var array<string, scalar|null> $stored */
                $stored = (array) $row;

                if (!$each($stored)) {
                    return;
                }

                $after = [$stored['occurred_at'] ?? null, $stored['id'] ?? null];
            }
        } while (count($rows) === self::PAGE);
    }
}
