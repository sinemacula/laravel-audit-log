<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Prunes the entries retention no longer keeps, entry by entry, seal by seal,
 * each chunk in a lifecycle transaction of its own behind the lock, and
 * journals the run and every deletion. It never runs on the write path.
 *
 * A run has a run id, which every journal row of the run names. Its policy is
 * resolved once, and each category and tenant pair it meets is decided once,
 * against the UTC midnight of the run's start, so one cut-off holds for each
 * pair for the whole run. Its start is one lifecycle transaction: the lock, the
 * whole journal verified, then, from the verified chain, the cursor to resume
 * after and the boundary, the latest seal, both read after the lock; the
 * policy's row when its version is not yet journalled; and the start row. The
 * cursor is the last finished run's, and only when that run stopped on its time
 * budget before its boundary: after any other run the walk starts again at the
 * first seal, so an entry a released hold or a finished delivery frees is
 * reached by the next run. A run that crashed after its start row left no
 * finish row, and is passed over.
 *
 * The seals from the cursor to the boundary are walked oldest first, so a seal
 * made during the run is left to the next. A seal that fails authentication is
 * skipped and named. The present members of an authenticated seal that are past
 * their pair's cut-off and whose code is not protected are planned into chunks
 * of `audit-log.retention.batch`; the plan decides nothing, since each chunk
 * reads its candidates again under the lock. A chunk whose deletes mismatch is
 * retried once from a fresh read, then its seal is skipped; a chunk keeps only
 * the replay a committed transaction returned. The time budget is read from the
 * clock between seals and between chunks, and a run past it stops, leaving what
 * it did not walk to the next run.
 *
 * A policy that throws, answers out of range or retains a category for less
 * than it is preserved, a configuration that is malformed, a journal that fails
 * verification and any other failure stop the run, are reported by their class
 * alone, and end it `failed`; the chunks it committed stand. A run that
 * committed its start row writes its finish row whatever happened, with its
 * status, counts, cursor and bounded decisions, and every run that is not a dry
 * run then writes `retention.last_run`. A dry run takes no lock and writes
 * nothing: it verifies the journal read-only, reads the cursor and the boundary
 * the same way, and counts the entries per pair and per seal, counting as held
 * those the verified chain's holds keep, exactly as a chunk would.
 *
 * Pruning makes deletion accountable, never impossible: whoever holds the
 * maintenance credentials can still delete entries, and the seals and the
 * journal make that detectable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Pruner
{
    /** @var int The attempts a chunk whose deletes mismatch makes in all: the first and one retry. */
    private const int MISMATCH_ATTEMPTS = 2;

    /** @var string The phase a run's first row names. */
    private const string START = 'start';

    /** @var string The refusal of a run inside a transaction. */
    private const string IN_TRANSACTION = 'A prune runs in transactions of its own on the maintenance connection, and refuses to run inside one.';

    /** @var string What a run that stopped on a failure reports, by the run's id and the failure's class. */
    private const string STOPPED = 'The prune run `%s` stopped with %s; the chunks it committed stand.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings  $retention
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeals  $seals
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk  $chunk
     * @param  \SineMacula\Laravel\AuditLog\Database\IntegrityProgress  $progress
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The container the retention policy and the connections are resolved from on every run. */
        private Container $container,

        /** The frame every transaction of a run takes, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal a run's rows are appended to. */
        private Journal $journal,

        /** The signer the journal is verified with. */
        private JournalSigner $signer,

        /** The settings the journal's log id is read from. */
        private SealSettings $settings,

        /** The retention settings a run's chunk size and time budget are read from. */
        private RetentionSettings $retention,

        /** The seals a run walks, authenticated. */
        private PruneSeals $seals,

        /** The chunk every deletion is made in. */
        private PruneChunk $chunk,

        /** The progress a run leaves when it ends. */
        private IntegrityProgress $progress,

        /** The time a run starts, decides its cut-offs and its budget by, and ends at. */
        private Clock $clock,

        /** The handler a run's failures are reported to. */
        private ExceptionHandler $handler,
    ) {}

    /**
     * Run a prune, or with `$dryRun` plan one, within the time budget given or
     * `audit-log.retention.max_seconds`, and return what it did.
     *
     * @param  bool  $dryRun
     * @param  ?int  $maxSeconds
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function run(bool $dryRun = false, ?int $maxSeconds = null): PruneResult
    {
        $this->refuseInsideATransaction();

        self::checkBudget($maxSeconds);

        $startedAt = $this->clock->now();
        $tally     = new PruneTally(Str::uuid7($startedAt)->toString(), $dryRun);
        $decisions = null;
        $replay    = null;

        try {
            [$policy, $decisions]         = $this->prepare($tally, $maxSeconds, $startedAt);
            [$replay, $cursor, $boundary] = $dryRun ? $this->positionOn($this->maintenance()) : $this->begin($tally, $policy, $decisions);

            $tally->start($decisions->version(), $cursor, $boundary);

            $replay = $this->walk($tally, $decisions, $replay, $cursor, $boundary);
        } catch (\Throwable $exception) {
            $tally->fail($exception instanceof JournalBrokenException ? 'journal_broken' : 'prune_failed');

            $this->report($tally, $exception);
        }

        if (!$dryRun) {
            $this->finish($tally, $decisions, $replay);
        }

        return $tally->result();
    }

    /**
     * Prepare the run: the installation confirmed, unless it is a dry run; the
     * policy resolved and its decisions made against the start's midnight; its
     * version read; and the run limited. A failure of the policy or of the
     * configuration is noted as such before it propagates.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  ?int  $maxSeconds
     * @param  \DateTimeInterface  $startedAt
     * @return array{0: \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy, 1: \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions}
     *
     * @throws \Throwable
     */
    private function prepare(PruneTally $tally, ?int $maxSeconds, \DateTimeInterface $startedAt): array
    {
        if (!$tally->dryRun) {
            $this->transaction->confirm();
        }

        try {
            $policy    = $this->container->make(RetentionPolicy::class);
            $decisions = new RetentionDecisions($policy, $startedAt);

            $tally->underPolicy($decisions->version());
            $tally->limit($this->retention->batch(), $maxSeconds ?? $this->retention->maxSeconds(), $startedAt->getTimestamp());
        } catch (\Throwable $exception) {
            $tally->fail(self::policyFailure($exception));

            throw $exception;
        }

        return [$policy, $decisions];
    }

    /**
     * Start the run in one lifecycle transaction: the journal verified, the
     * cursor and the boundary read from the verified chain after the lock, the
     * policy's row appended when its version is new, and the start row; the
     * replay the commit returned, the cursor and the boundary are returned.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy  $policy
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay, 1: int, 2: int}
     *
     * @throws \Throwable
     */
    private function begin(PruneTally $tally, RetentionPolicy $policy, RetentionDecisions $decisions): array
    {
        $runId   = $tally->runId;
        $version = $decisions->version();

        return $this->transaction->run($runId, function (Connection $connection) use ($runId, $policy, $version, $decisions): array {
            [$replay, $cursor, $boundary] = $this->positionOn($connection);

            if (!$replay->hasPolicyVersion($version)) {
                $settings = $policy instanceof ConfiguredRetentionPolicy ? $policy->settings() : null;
                $payload  = ['version' => $version, 'policy' => $policy::class, 'settings' => $settings];
                $replay   = $this->journal->append($connection, $replay, JournalKind::POLICY, $runId, null, $payload);
            }

            $start = [
                'run_id'            => $runId,
                'phase'             => self::START,
                'policy_version'    => $version,
                'boundary_sequence' => $boundary,
                'cutoff_midnight'   => $decisions->midnight(),
                'resume_from'       => $cursor,
            ];

            return [$this->journal->append($connection, $replay, JournalKind::PRUNE_RUN, $runId, null, $start), $cursor, $boundary];
        });
    }

    /**
     * The whole journal verified on the connection, and from the verified chain
     * the cursor to resume after, then the boundary: the latest seal's
     * sequence, or 0 when there is none. The cursor is the last finished run's
     * when that run stopped on its time budget before its boundary, and 0, the
     * first seal, otherwise.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay, 1: int, 2: int}
     *
     * @throws \Throwable
     */
    private function positionOn(Connection $connection): array
    {
        $replay = JournalReplay::start($this->signer, $this->settings->logId())->verify($connection);
        $cursor = self::resumeCursorOf($replay->lastRunFinish($connection) ?? []);

        $boundary = IntegerSetting::parse($connection->table(IntegrityTables::checkpointsTable())
            ->useWritePdo()
            ->where('sequence', '>=', 1)
            ->orderByDesc('sequence')
            ->value('sequence')) ?? 0;

        return [$replay, min($cursor, $boundary), $boundary];
    }

    /**
     * Walk the seals after the cursor up to the boundary, oldest first, and
     * return the replay the last committed transaction returned: each seal
     * authenticated or skipped, its eligible present members planned, and,
     * unless it is a dry run, pruned chunk by chunk. A run past its budget
     * stops before the next seal or chunk.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  int  $cursor
     * @param  int  $boundary
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     *
     * @throws \Throwable
     */
    private function walk(PruneTally $tally, RetentionDecisions $decisions, JournalReplay $replay, int $cursor, int $boundary): JournalReplay
    {
        $connection = $this->maintenance();

        for ($sequence = $cursor + 1; $sequence <= $boundary; $sequence++) {
            if ($tally->isPastBudget($this->clock->now()->getTimestamp())) {
                $tally->stop();

                return $replay;
            }

            $seal = $this->seals->load($connection, $sequence);

            if ($seal === null) {
                $tally->skipped(self::sealIdAt($connection, $sequence));
                $tally->walked($sequence);

                continue;
            }

            $planned = $this->planOf($tally, $decisions, $seal, $sequence, $replay->holds(), $connection);

            if ($tally->dryRun) {
                $tally->walked($sequence);

                continue;
            }

            [$replay, $walked] = $this->pruneSeal($tally, $decisions, $seal, $planned, $replay);

            if (!$walked) {
                $tally->stop();

                return $replay;
            }

            $tally->walked($sequence);
        }

        return $replay;
    }

    /**
     * The seal's present members that are eligible, by id: past their pair's
     * cut-off and of a code that is not protected. A dry run counts each as
     * planned, or as held when a hold keeps it, and plans nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  int  $sequence
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  \Illuminate\Database\Connection  $connection
     * @return array<string, array<string, scalar|null>>
     *
     * @throws \Throwable
     */
    private function planOf(PruneTally $tally, RetentionDecisions $decisions, PruneSeal $seal, int $sequence, array $holds, Connection $connection): array
    {
        $planned = [];

        foreach ($this->seals->present($connection, $seal) as $row) {
            $decision = self::eligibleDecision($tally, $decisions, $row);

            if ($decision === null) {
                continue;
            }

            if ($tally->dryRun) {
                $tally->planned($sequence, $decision, PruneChunk::isHeld($row, $holds));

                continue;
            }

            $planned[(string) $row['id']] = $row;
        }

        return $planned;
    }

    /**
     * Prune the planned members of the seal in chunks, and return the replay
     * the last committed chunk returned and whether the seal was walked to its
     * end: `false` when the budget stopped the run before a chunk. A chunk
     * whose candidate fails verification, or whose deletes mismatch twice,
     * skips the rest of the seal.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  array<string, array<string, scalar|null>>  $planned
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay, 1: bool}
     *
     * @throws \Throwable
     */
    private function pruneSeal(PruneTally $tally, RetentionDecisions $decisions, PruneSeal $seal, #[\SensitiveParameter] array $planned, JournalReplay $replay): array
    {
        foreach (array_chunk(array_map(strval(...), array_keys($planned)), $tally->batch()) as $ids) {
            if ($tally->isPastBudget($this->clock->now()->getTimestamp())) {
                return [$replay, false];
            }

            $outcome = $this->attempt($tally, $decisions, $seal, $ids, $replay);

            if ($outcome === null || $outcome->sealFailed) {
                $tally->skipped($seal->envelope->id);

                return [$outcome->replay ?? $replay, true];
            }

            $tally->committed($seal->envelope->id, $outcome, $planned);

            $replay = $outcome->replay;
        }

        return [$replay, true];
    }

    /**
     * Run one chunk of the ids in a lifecycle transaction from the replay the
     * last commit returned, and return its outcome once it has committed. A
     * chunk whose deletes mismatched rolled back, and is made once more from a
     * fresh read; `null` when that mismatched too.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  list<string>  $ids
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome
     *
     * @throws \Throwable
     */
    private function attempt(PruneTally $tally, RetentionDecisions $decisions, PruneSeal $seal, array $ids, JournalReplay $replay): ?PruneChunkOutcome
    {
        $runId = $tally->runId;
        $chunk = $this->chunk;
        $clock = $this->clock;
        $work  = static fn (Connection $connection): PruneChunkOutcome => $chunk->run($connection, $replay, $decisions, $seal, $ids, $runId, StoredTime::format($clock->now()));

        for ($attempt = 1; $attempt <= self::MISMATCH_ATTEMPTS; $attempt++) {
            try {
                return $this->transaction->run($runId, $work);
            } catch (PruneMismatchException) {
                // The chunk rolled back whole; it is read afresh once, then its
                // seal is skipped
            }
        }

        return null;
    }

    /**
     * End the run: once it committed its start row, its finish row in one
     * lifecycle transaction, the replay advanced first, or the journal verified
     * afresh when the run lost its replay to a failure; then its progress.
     * Either failing is reported, and a finish row that could not be written
     * fails the run.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return void
     */
    private function finish(PruneTally $tally, ?RetentionDecisions $decisions, ?JournalReplay $replay): void
    {
        if ($tally->hasStarted() && $decisions !== null) {
            try {
                $this->transaction->run($tally->runId, fn (Connection $connection): JournalReplay => $this->journal->append(
                    $connection,
                    $replay?->advance($connection) ?? JournalReplay::start($this->signer, $this->settings->logId())->verify($connection),
                    JournalKind::PRUNE_RUN,
                    $tally->runId,
                    null,
                    $tally->finishPayload($decisions),
                ));
            } catch (\Throwable $exception) {
                $tally->fail('prune_failed');

                $this->report($tally, $exception);
            }
        }

        try {
            $now = $this->clock->now();

            $this->progress->put(IntegrityProgress::RETENTION_LAST_RUN, $tally->progress(StoredTime::format($now)), $now);
        } catch (\Throwable $exception) {
            $this->report($tally, $exception);
        }
    }

    /**
     * Report the failure that stopped the run, or that its end met, by its
     * class alone, so nothing of an entry, a statement or a binding reaches a
     * reporter.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \Throwable  $exception
     * @return void
     */
    private function report(PruneTally $tally, #[\SensitiveParameter] \Throwable $exception): void
    {
        $this->handler->report(new \RuntimeException(sprintf(self::STOPPED, $tally->runId, $exception::class)));
    }

    /**
     * Refuse to run while the maintenance or the storage connection is in a
     * transaction, before anything is read or written.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseInsideATransaction(): void
    {
        $database = $this->container->make(DatabaseManager::class);

        if ($database->connection(StorageConnection::forMaintenance())->transactionLevel() === 0 && $database->connection(StorageConnection::name())->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException(self::IN_TRANSACTION);
    }

    /**
     * The maintenance connection, which every read and transaction of a run
     * takes.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function maintenance(): Connection
    {
        return $this->container->make(DatabaseManager::class)->connection(StorageConnection::forMaintenance());
    }

    /**
     * The decision of the present member's pair when the member is eligible:
     * its time strictly before the pair's cut-off, and its code not protected;
     * `null` otherwise, and for a member whose time or tenant cannot be read. A
     * failure of the policy is noted as such before it propagates.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  array<string, scalar|null>  $row
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision
     *
     * @throws \Throwable
     */
    private static function eligibleDecision(PruneTally $tally, RetentionDecisions $decisions, #[\SensitiveParameter] array $row): ?RetentionDecision
    {
        $read = self::timeAndTenantOf($row);

        if ($read === null) {
            return null;
        }

        try {
            $decision = $decisions->for((string) ($row['category'] ?? ''), $read[1]);
        } catch (\Throwable $exception) {
            $tally->fail(self::policyFailure($exception));

            throw $exception;
        }

        return $decision->admits($read[0]) ? $decision : null;
    }

    /**
     * The present member's time, read from the engine's form, and its tenant,
     * or `null` for a member of a protected code, and for one whose time or
     * tenant cannot be read.
     *
     * @param  array<string, scalar|null>  $row
     * @return ?array{0: string, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference}
     */
    private static function timeAndTenantOf(#[\SensitiveParameter] array $row): ?array
    {
        if (PackageActivity::tryFrom((string) ($row['event'] ?? ''))?->isProtected() === true) {
            return null;
        }

        $type = $row['tenant_type'] ?? null;
        $id   = $row['tenant_id']   ?? null;

        try {
            return [StoredTime::fromStorage((string) ($row['occurred_at'] ?? '')), $type === null || $id === null ? null : Reference::of((string) $type, (string) $id)];
        } catch (\InvalidArgumentException|\UnexpectedValueException) {
            return null;
        }
    }

    /**
     * Refuse a time budget shorter than a second.
     *
     * @param  ?int  $maxSeconds
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkBudget(?int $maxSeconds): void
    {
        if ($maxSeconds === null || $maxSeconds >= 1) {
            return;
        }

        throw new \InvalidArgumentException('A prune\'s time budget must be at least a second.');
    }

    /**
     * The cursor a run resumes after, read from the last finished run's
     * verified payload: its cursor when it stopped on its time budget, before
     * its boundary, without failing; 0, the first seal, otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $finish
     * @return int
     */
    private static function resumeCursorOf(array $finish): int
    {
        $remaining = $finish['remaining'] ?? null;
        $cursor    = $finish['cursor']    ?? null;

        if (!is_int($remaining) || $remaining < 1 || !is_int($cursor) || $cursor < 1) {
            return 0;
        }

        return ($finish['status'] ?? null) === PruneStatus::FAILED->value ? 0 : $cursor;
    }

    /**
     * Why a failure of the policy or of the configuration stops the run: a
     * retention shorter than its preservation, or a malformed setting, is
     * refused configuration, and anything else the policy's failure.
     *
     * @param  \Throwable  $exception
     * @return 'configuration_refused'|'policy_failed'
     */
    private static function policyFailure(#[\SensitiveParameter] \Throwable $exception): string
    {
        return $exception instanceof RetentionConflictException || $exception instanceof \InvalidArgumentException ? 'configuration_refused' : 'policy_failed';
    }

    /**
     * The id of the stored seal at the sequence, or `null` when there is none
     * or it is not text.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $sequence
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function sealIdAt(Connection $connection, int $sequence): ?string
    {
        $id = $connection->table(IntegrityTables::checkpointsTable())->useWritePdo()->where('sequence', $sequence)->value('id');

        return is_string($id) ? $id : null;
    }
}
