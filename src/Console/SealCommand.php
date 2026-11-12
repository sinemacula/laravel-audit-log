<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\AnchorResult;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealFailedException;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:seal`: seals the entries no seal holds yet, recent ones or with
 * `--sweep` the whole table from its cursor, then anchors pending seals.
 *
 * Nothing printed, dispatched or reported holds a message, statement, binding
 * or entry value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:seal')]
final class SealCommand extends Command
{
    /** @var string The name of the cache lock a recent pass holds. */
    public const string LOCK = 'audit-log:seal';

    /** @var string The name of the cache lock a sweep holds, apart from the recent pass's. */
    public const string SWEEP_LOCK = 'audit-log:seal:sweep';

    /** @var int The most seconds a run holds the lock, after which it lapses. */
    public const int LOCK_SECONDS = 900;

    /** @var string The command the event and the exception name. */
    private const string COMMAND = 'seal';

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:seal {--sweep : Seal the whole table from the sweep\'s cursor instead of the recent window}';

    /** @var string The console command description. */
    protected $description = 'Seal the audit log\'s unsealed entries and anchor the seals';

    /**
     * Seal and anchor under the run's lock, when the cache can hold one, then
     * print the tally.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Sealer  $sealer
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return int
     */
    public function handle(Sealer $sealer, Container $container, CacheFactory $cache, IntegrityAlarm $alarm): int
    {
        $lock = self::acquire($cache, $this->isSweep() ? self::SWEEP_LOCK : self::LOCK);

        if ($lock === false) {
            $this->line('Another sealer holds the lock.');

            return self::SUCCESS;
        }

        try {
            $sealed   = $this->seals($sealer, $alarm);
            $anchored = $this->anchors($container, $alarm);
        } finally {
            if ($lock !== null) {
                self::release($lock);
            }
        }

        return $sealed && $anchored ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Seal the recent entries, or sweep the table, print what was sealed, and
     * return whether sealing succeeded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Sealer  $sealer
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return bool
     */
    private function seals(Sealer $sealer, IntegrityAlarm $alarm): bool
    {
        try {
            $result = $this->isSweep() ? $sealer->sweep() : $sealer->seal();
        } catch (SealChainException $refusal) {
            $this->error(sprintf('Sealing stopped with %s.', SealChainException::class));
            $alarm->raise(self::event([$refusal->finding->status()->value => 1], [], $refusal->finding, $refusal->sealId));

            return false;
        } catch (\Throwable $exception) {
            $this->stopped('Sealing', get_debug_type($exception), $alarm);

            return false;
        }

        $this->printSealing($result);

        return $this->hasNoSkippedEntries($result, $alarm);
    }

    /**
     * Anchor the pending seals; an unavailable anchor does not fail it, and
     * resolving the anchorer here keeps its settings from stopping sealing.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return bool
     */
    private function anchors(Container $container, IntegrityAlarm $alarm): bool
    {
        try {
            $result = $container->make(Anchorer::class)->anchorPending();
        } catch (\Throwable $exception) {
            $this->stopped('Anchoring', get_debug_type($exception), $alarm);

            return false;
        }

        if (!$result->isConfigured()) {
            return true;
        }

        $this->line(sprintf('Anchored %d seals.', $result->anchoredCount()));

        $this->warnUnavailable($result);
        $this->alarmConflict($result, $alarm);
        $this->alarmRefusal($result, $alarm);

        return !$result->isAlarm();
    }

    /**
     * Print what the run sealed and, for a sweep, whether it reached the end of
     * the table.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealResult  $result
     * @return void
     */
    private function printSealing(SealResult $result): void
    {
        $this->line($result->seals() === 0
            ? 'Nothing to seal.'
            : sprintf('Sealed %d entries in %d seals (sequences %d to %d).', $result->entries(), $result->seals(), $result->firstSequence(), $result->lastSequence()));

        if (!$this->isSweep()) {
            return;
        }

        $this->line($result->isSweepComplete() ? 'The sweep is complete.' : 'The sweep continues from its cursor next run.');
    }

    /**
     * Alarm on entries that cannot be sealed, never naming one; the event
     * counts the condition once, since its maps count segments.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return bool
     */
    private function hasNoSkippedEntries(SealResult $result, IntegrityAlarm $alarm): bool
    {
        $skipped = $result->skippedEntries();

        if ($skipped === 0) {
            return true;
        }

        $this->error(sprintf('Skipped %d entries that cannot be sealed (a malformed id, HMAC or time); they stay unsealed.', $skipped));
        $alarm->raise(self::event([IntegrityStatus::UNVERIFIABLE->value => 1], [], Finding::ENTRY_MALFORMED, null));

        return false;
    }

    /**
     * Warn that the anchor was unavailable, naming the class of its failure and
     * the seal from which seals wait.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @return void
     */
    private function warnUnavailable(AnchorResult $result): void
    {
        $class = $result->unavailableClass();

        if ($class === null) {
            return;
        }

        $from = $result->waitingFrom();

        $this->warn($from === null
            ? sprintf('The anchor is unavailable (%s); no seal is anchored until it is.', $class)
            : sprintf('The anchor is unavailable (%s); seals from %d wait to be anchored.', $class, $from));
    }

    /**
     * Alarm on an anchor that holds another digest for a seal: the log is
     * tampered and its anchoring contradicted.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return void
     */
    private function alarmConflict(AnchorResult $result, IntegrityAlarm $alarm): void
    {
        $conflict = $result->conflict();

        if ($conflict === null) {
            return;
        }

        $this->error(sprintf('The anchor holds another digest for seal %d; the local log or the anchor has been altered.', $conflict['sequence']));

        $integrity = [Finding::ANCHOR_CONFLICT->status()->value => 1];
        $anchoring = [AnchorStatus::CONTRADICTED->value => 1];

        $alarm->raise(self::event($integrity, $anchoring, Finding::ANCHOR_CONFLICT, $conflict['sealId']));
    }

    /**
     * Alarm on a seal refused because it does not verify, under the status of
     * the finding it was refused for.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return void
     */
    private function alarmRefusal(AnchorResult $result, IntegrityAlarm $alarm): void
    {
        $refusal = $result->refusal();

        if ($refusal === null) {
            return;
        }

        $finding = $refusal['finding'];

        $this->error(sprintf('Seal %d does not verify (%s), so it is not anchored; run audit-log:verify.', $refusal['sequence'], $finding->value));
        $alarm->raise(self::event([$finding->status()->value => 1], [], $finding, $refusal['sealId']));
    }

    /**
     * Print that the stage stopped with a failure of the class, and report it
     * by that class alone, dispatching nothing.
     *
     * @param  string  $stage
     * @param  string  $class
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return void
     */
    private function stopped(string $stage, string $class, IntegrityAlarm $alarm): void
    {
        $this->error(sprintf('%s stopped with %s.', $stage, $class));

        $alarm->report(SealFailedException::stoppedBy($class));
    }

    /**
     * Whether the run is a sweep of the whole table.
     *
     * @return bool
     */
    private function isSweep(): bool
    {
        return $this->option('sweep') === true;
    }

    /**
     * Take the named lock: the lock, `false` when another run holds it, or
     * `null` when the default store cannot lock or fails.
     *
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     * @param  string  $name
     * @return false|\Illuminate\Contracts\Cache\Lock|null
     */
    private static function acquire(CacheFactory $cache, string $name): false|Lock|null
    {
        // A cache that fails costs only the lock, which is an optimisation:
        // sealing is safe beside another sealer
        return self::attempt(static function () use ($cache, $name): false|Lock|null {
            $store = $cache->store()->getStore();

            if (!$store instanceof LockProvider) {
                return null;
            }

            $lock = $store->lock($name, self::LOCK_SECONDS);

            return $lock->get() === true ? $lock : false;
        }, null);
    }

    /**
     * Release the lock the run took.
     *
     * @param  \Illuminate\Contracts\Cache\Lock  $lock
     * @return void
     */
    private static function release(Lock $lock): void
    {
        // A lock that is not released lapses after its seconds
        self::attempt(static function () use ($lock): void {
            $lock->release();
        }, null);
    }

    /**
     * Run the step, or return the fallback when it throws, for a step whose
     * failure costs only an optimisation.
     *
     * @template T
     *
     * @param  \Closure(): T  $step
     * @param  T  $otherwise
     * @return T
     */
    private static function attempt(\Closure $step, mixed $otherwise): mixed
    {
        try {
            return $step();
        } catch (\Throwable) {
            // The caller gives the fallback for exactly this failure
            return $otherwise;
        }
    }

    /**
     * The event of a failed seal run, zero-filled across every status, with no
     * head since a seal run does not verify the log.
     *
     * @param  array<string, int>  $integrity
     * @param  array<string, int>  $anchoring
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $firstBadId
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private static function event(array $integrity, array $anchoring, Finding $finding, ?string $firstBadId): IntegrityCheckFailed
    {
        return new IntegrityCheckFailed(
            self::COMMAND,
            self::whole($integrity, IntegrityStatus::cases()),
            self::whole($anchoring, AnchorStatus::cases()),
            $finding->value,
            $firstBadId,
            null,
            null,
            false,
        );
    }

    /**
     * The counts under every status, in order, zero where not counted.
     *
     * @param  array<string, int>  $counts
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus|\SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus>  $statuses
     * @return array<string, int>
     */
    private static function whole(array $counts, array $statuses): array
    {
        $whole = [];

        foreach ($statuses as $status) {
            $whole[$status->value] = $counts[$status->value] ?? 0;
        }

        return $whole;
    }
}
