<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:drain`: delivers the outbox's due rows to the store, at most
 * `--limit` of them (100 unless given, from 1 to 10000), or, with
 * `--until-empty`, batch after batch of that many until no row that was due
 * when the run began is left to claim.
 *
 * It prints how many rows were delivered, completed as pruned because retention
 * had already pruned their record, retried, failed, taken over by another drain
 * and missed because another drain claimed them first, and exits non-zero when
 * any row failed; a pruned row is no failure. A limit it refuses is said before
 * anything is drained. Whatever stops the run, such as a missing table or a
 * transaction left open, is named by its class alone and reported as a
 * payload-free `AuditWriteFailedException`, so a scheduled run whose output is
 * discarded still raises it, and the tally of the rows already worked is
 * printed after it; the command never prints a message, a payload or a binding.
 *
 * The package neither schedules the command nor dispatches a job to run it: the
 * application runs it, from its scheduler or a worker of its own, as often as
 * the outbox needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:drain')]
final class DrainCommand extends Command
{
    /** @var int The rows a run drains, or each batch of a run until empty, unless `--limit` says otherwise. */
    public const int DEFAULT_LIMIT = 100;

    /** @var int The most rows `--limit` may name. */
    public const int MAX_LIMIT = 10000;

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:drain {--limit= : The most rows to drain, from 1 to 10000 (default 100)} {--until-empty : Drain batch after batch until none is left}';

    /** @var string The console command description. */
    protected $description = 'Deliver the audit log outbox\'s due rows to the store';

    /**
     * Drain the outbox, then print the tally.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer  $drainer
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @return int
     */
    public function handle(OutboxDrainer $drainer, ExceptionHandler $handler, WriteGuard $guard): int
    {
        try {
            $limit = IntegerSetting::from('The --limit option', $this->option('limit') ?? self::DEFAULT_LIMIT, 1, self::MAX_LIMIT);
        } catch (\InvalidArgumentException $exception) {
            $this->error($exception->getMessage());

            return self::INVALID;
        }

        $result = new DrainResult;

        try {
            $drainer->drain($limit, $this->option('until-empty') === true, $result);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The drain stopped with %s.', get_debug_type($exception)));
            $this->line(self::tally($result));

            self::report($exception, $handler, $guard);

            return self::FAILURE;
        }

        $this->line(self::tally($result));

        return $result->hasFailures() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Report what stopped the run, payload-free and inside the write guard, so
     * a run nobody reads still raises it. A reporter that fails too is ignored.
     *
     * @param  \Throwable  $exception
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @return void
     */
    private static function report(#[\SensitiveParameter] \Throwable $exception, ExceptionHandler $handler, WriteGuard $guard): void
    {
        $sanitised = new AuditWriteFailedException(WriteDiagnostics::of($exception, null, null, FailedOperation::DRAIN, OutboxDrainer::class));

        try {
            $guard->during(static function () use ($handler, $sanitised): void {
                $handler->report($sanitised);
            });
        } catch (\Throwable) {
            // The class is already printed, and there is nowhere left to say so
        }
    }

    /**
     * The drain's tally, as one line.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return string
     */
    private static function tally(DrainResult $result): string
    {
        return sprintf(
            'Delivered %d, pruned %d, retried %d, failed %d, stale %d, missed %d.',
            $result->delivered(),
            $result->pruned(),
            $result->retried(),
            $result->failed(),
            $result->stale(),
            $result->missed(),
        );
    }
}
