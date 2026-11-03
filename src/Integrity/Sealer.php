<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Sleep;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Seals the entries no seal holds yet, batch after batch, each batch one seal
 * written in its own transaction: the recent pass, and the resumable sweep of
 * the whole table.
 *
 * The recent pass starts `integrity.seal.lookback_seconds` before the latest
 * entry time a recent pass has sealed, a high-water mark progress keeps and
 * only a recent pass moves forward, so a sweep's seal of old rows at the head
 * never pulls the window back. Without that mark it starts the lookback before
 * the latest entry of the last seal in the chain, or at the beginning of the
 * table when there is no seal. It reads only entries that are no seal's member,
 * so a row that commits late with an earlier time joins a later seal. The sweep
 * reads the whole table in windows from the cursor progress keeps, saved after
 * every window, so an interrupted sweep resumes where it stopped and never
 * restarts at the beginning until a pass is complete; it finds the rows older
 * than the lookback. Each batch reads on strictly after the last row the one
 * before read, and only a batch that writes a seal counts towards
 * `integrity.seal.max_batches`, so a run always ends.
 *
 * Only entries recorded no later than the run's start, less
 * `integrity.seal.settle_seconds`, are sealed; that bound is fixed when the run
 * starts. Sealing refuses to run inside a transaction on the storage
 * connection, so each seal commits on its own. An attempt lost to a concurrent
 * writer (a duplicate seal or member, a deadlock, a serialisation failure, a
 * lock wait timeout, PostgreSQL's lock timeout or a locked database) is rolled
 * back whole and made again from scratch, after a jittered wait that grows with
 * each attempt, at most `integrity.seal.max_attempts` times; then the run stops
 * with a `SealContentionException`. A lost connection is never retried, because
 * the commit may have happened; the next run sees what it left. Anything else
 * stops the run unchanged.
 *
 * Progress records the last seal after each commit, the recent pass's
 * high-water mark after each of its seals, the sweep's cursor after every
 * window and its completion, and the run itself once it ends without a failure.
 * Progress is operational, never evidence: a mark that is lost or rewritten
 * moves only where the recent pass reads from, and the sweep still seals
 * everything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Sealer
{
    /** @var int The bound of the first retry's wait, in milliseconds, doubled for each later one. */
    public const int JITTER_BASE_MS = 20;

    /** @var int The greatest bound of a retry's wait, in milliseconds. */
    public const int JITTER_MAX_MS = 1000;

    /** @var int The most doublings of the first bound, past which the greatest bound always applies. */
    private const int MAX_DOUBLINGS = 10;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter  $writer
     * @param  \SineMacula\Laravel\AuditLog\Database\IntegrityProgress  $progress
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Database\FailureClassifier  $classifier
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The writer that makes each attempt at one seal. */
        private CheckpointWriter $writer,

        /** The progress the last seal, the sweep's cursor and the run are recorded in. */
        private IntegrityProgress $progress,

        /** The settings the batch, the bounds and the attempts are read from. */
        private SealSettings $settings,

        /** The classifier that tells a failure lost to a concurrent writer from any other. */
        private FailureClassifier $classifier,

        /** The clock that fixes the run's bound and the time progress is written at. */
        private Clock $clock,

        /** The connections the storage connection is resolved from. */
        private DatabaseManager $database,
    ) {}

    /**
     * Seal the recent entries no seal holds: those recorded from the lookback
     * before the last seal's latest entry, or every one when there is no seal.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealContentionException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \Throwable
     */
    public function seal(): SealResult
    {
        $this->refuseInsideATransaction();

        $now       = $this->clock->now();
        $until     = $this->untilOf($now);
        $highWater = $this->recentHighWater();
        $lookback  = $this->settings->lookbackSeconds();
        $start     = $highWater === null ? null : SealCursor::from(StoredTime::format(StoredTime::instant(StoredTime::toStorage($highWater))->subSeconds($lookback)));

        return $this->run($now, $start, $highWater, fn (?SealCursor $after, int $limit): SealBatch => $this->writer->write($after, $until, $limit));
    }

    /**
     * Seal every entry no seal holds, window after window from where the last
     * sweep stopped, or from the beginning after a complete one.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealContentionException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \Throwable
     */
    public function sweep(): SealResult
    {
        $this->refuseInsideATransaction();

        $now   = $this->clock->now();
        $until = $this->untilOf($now);
        $after = SealCursor::fromProgress($this->progress->get(IntegrityProgress::SWEEP_CURSOR));

        return $this->run($now, $after, null, fn (?SealCursor $after, int $limit): SealBatch => $this->writer->writeWindow($after, $until, $limit), true);
    }

    /**
     * Seal batch after batch from the position until a batch reaches the end of
     * what there is to read or the run has written its most seals, and record
     * the run; a recent pass moves its high-water mark forward from the one
     * given as it seals.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealCursor  $after
     * @param  ?string  $highWater
     * @param  \Closure(?\SineMacula\Laravel\AuditLog\Integrity\SealCursor, int): \SineMacula\Laravel\AuditLog\Integrity\SealBatch  $write
     * @param  bool  $sweep
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealContentionException
     * @throws \Throwable
     */
    private function run(CarbonImmutable $now, ?SealCursor $after, ?string $highWater, \Closure $write, bool $sweep = false): SealResult
    {
        $result     = new SealResult;
        $limit      = $this->settings->batch();
        $maxBatches = $this->settings->maxBatches();

        while ($result->seals() < $maxBatches) {

            $batch = $this->attempt(static fn (): SealBatch => $write($after, $limit), $result);

            $this->record($batch, $sweep, $result);

            $highWater = $sweep ? $highWater : $this->recordHighWater($batch, $highWater);

            if ($batch->exhausted) {
                break;
            }

            $after = $batch->last;
        }

        $this->progress->put(IntegrityProgress::SEAL_LAST_RUN, [
            'at'      => StoredTime::format($now),
            'seals'   => $result->seals(),
            'entries' => $result->entries(),
            'sweep'   => $sweep,
        ], $this->clock->now());

        return $result;
    }

    /**
     * Make attempt after attempt at one seal until one succeeds: one lost to a
     * concurrent writer is made again after a jittered wait while attempts
     * remain, and is contention once none do; anything else stops the run
     * unchanged.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Integrity\SealBatch  $write
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealResult  $result
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealBatch
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealContentionException
     * @throws \Throwable
     */
    private function attempt(\Closure $write, SealResult $result): SealBatch
    {
        $attempts = $this->settings->maxAttempts();

        for ($attempt = 1;; $attempt++) {
            try {
                return $write();
            } catch (\Throwable $exception) {
                if (!$this->isLostToAConcurrentWriter($exception)) {
                    throw $exception;
                }

                if ($attempt >= $attempts) {
                    throw SealContentionException::after($attempts);
                }

                $result->retried();

                $this->waitAfter($attempt);
            }
        }
    }

    /**
     * Wait before the next attempt a random time no longer than the bound of
     * the attempt that failed: 20 milliseconds after the first, doubling after
     * each, up to a second.
     *
     * @param  int  $attempt
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function waitAfter(int $attempt): void
    {
        $bound = min(self::JITTER_MAX_MS, self::JITTER_BASE_MS * 2 ** min($attempt - 1, self::MAX_DOUBLINGS));

        Sleep::for(random_int(0, $bound))->milliseconds();
    }

    /**
     * Whether the failure is one a concurrent writer causes, which a fresh
     * attempt may not meet: a duplicate seal or member, a concurrency error, or
     * PostgreSQL's lock timeout. A lost connection never is, since its commit
     * may have happened.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private function isLostToAConcurrentWriter(#[\SensitiveParameter] \Throwable $exception): bool
    {
        if ($this->classifier->isLostConnection($exception)) {
            return false;
        }

        return $exception instanceof UniqueConstraintViolationException
            || $this->classifier->isConcurrencyError($exception)
            || $this->classifier->isLockTimeout($exception);
    }

    /**
     * Record what the batch did: its seal and its skipped candidates in the
     * result, the seal in progress, and for the sweep its cursor, or its
     * completion once it reached the end of the table.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealBatch  $batch
     * @param  bool  $sweep
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function record(SealBatch $batch, bool $sweep, SealResult $result): void
    {
        $result->skipped($batch->skipped);

        if ($batch->seal !== null) {
            $result->added($batch->seal);

            $seal = ['sequence' => $batch->seal->sequence, 'id' => $batch->seal->id, 'sealed_at' => $batch->seal->sealedAt];

            $this->progress->put(IntegrityProgress::SEAL_LAST, $seal, $this->clock->now());
        }

        if (!$sweep) {
            return;
        }

        if (!$batch->exhausted && $batch->last !== null) {
            $this->progress->put(IntegrityProgress::SWEEP_CURSOR, $batch->last->toProgress(), $this->clock->now());

            return;
        }

        $result->completedSweep();

        $this->progress->put(IntegrityProgress::SWEEP_COMPLETED, ['at' => StoredTime::format($this->clock->now())], $this->clock->now());
        $this->progress->forget(IntegrityProgress::SWEEP_CURSOR);
    }

    /**
     * Move the recent pass's high-water mark forward to the latest entry time
     * of the batch's seal, if it is later, and return the mark.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealBatch  $batch
     * @param  ?string  $highWater
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function recordHighWater(SealBatch $batch, ?string $highWater): ?string
    {
        $latest = $batch->seal?->lastRecordedAt;

        if ($latest === null || ($highWater !== null && strcmp($latest, $highWater) <= 0)) {
            return $highWater;
        }

        $this->progress->put(IntegrityProgress::SEAL_RECENT, ['last_recorded_at' => $latest], $this->clock->now());

        return $latest;
    }

    /**
     * The latest entry time a recent pass has sealed, in the package's form:
     * progress's mark, or without one the latest entry of the last seal in the
     * chain, or `null` when there is no seal.
     *
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    private function recentHighWater(): ?string
    {
        $mark = $this->progress->get(IntegrityProgress::SEAL_RECENT)['last_recorded_at'] ?? null;

        if (is_string($mark) && StoredTime::isInstant($mark)) {
            return $mark;
        }

        $latest = $this->database->connection(StorageConnection::name())
            ->table(IntegrityTables::checkpointsTable())
            ->useWritePdo()
            ->where('sequence', '>=', 1)
            ->orderByDesc('sequence')
            ->value('last_recorded_at');

        if ($latest === null) {
            return null;
        }

        if (!is_string($latest)) {
            throw new \UnexpectedValueException('A stored seal\'s `last_recorded_at` is malformed.');
        }

        return StoredTime::fromStorage($latest);
    }

    /**
     * The run's bound in the package's form: the instant less the settle delay.
     * No entry recorded after it is sealed.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function untilOf(CarbonImmutable $now): string
    {
        return StoredTime::format($now->subSeconds($this->settings->settleSeconds()));
    }

    /**
     * Refuse to seal while a transaction is open on the storage connection,
     * before any statement, so each seal commits on its own.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseInsideATransaction(): void
    {
        if ($this->database->connection(StorageConnection::name())->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException('Sealing refuses to run inside a transaction on the storage connection, so each seal commits on its own.');
    }
}
