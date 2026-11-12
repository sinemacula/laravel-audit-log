<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Sleep;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Seals the entries no seal holds yet, one seal per transaction, in a recent
 * pass or a resumable sweep of the whole table.
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
     * @param  \SineMacula\Laravel\AuditLog\Database\InstallationIdentity  $identity
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

        /** The installation's identity, ensured once per run. */
        private InstallationIdentity $identity,
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

        $now = $this->clock->now();

        $this->identity->ensure($now);

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

        $now = $this->clock->now();

        $this->identity->ensure($now);

        $until = $this->untilOf($now);
        $after = SealCursor::fromProgress($this->progress->get(IntegrityProgress::SWEEP_CURSOR));

        return $this->run($now, $after, null, fn (?SealCursor $after, int $limit): SealBatch => $this->writer->writeWindow($after, $until, $limit), true);
    }

    /**
     * Seal batch after batch until one reads to the end or the run has written
     * its most seals, then record the run.
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
     * Make attempts at one seal until one succeeds, retrying one lost to a
     * concurrent writer after a jittered wait while attempts remain.
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
     * Wait a random time up to the failed attempt's bound: 20 milliseconds
     * after the first, doubling after each, up to a second.
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
     * Whether a concurrent writer caused the failure, so a fresh attempt may
     * succeed. A lost connection never is, since its commit may have happened.
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
     * Record the batch's seal and skips in the result and progress, and the
     * sweep's cursor or completion.
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
     * The latest entry time a recent pass has sealed: progress's mark, else the
     * last seal's latest entry, or `null` with no seal.
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
