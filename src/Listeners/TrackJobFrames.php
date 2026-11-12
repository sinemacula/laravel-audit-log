<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use Illuminate\Log\Context\Repository;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;

/**
 * Enters an execution frame when a queued job starts and leaves it when the job
 * ends, on success or failure, on a worker or the sync queue.
 *
 * A failed job fires `JobFailed` and `JobExceptionOccurred` in either order;
 * whichever comes first leaves the frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrackJobFrames
{
    /**
     * Handle the `JobProcessing`, `JobProcessed`, `JobFailed` and
     * `JobExceptionOccurred` events.
     *
     * @param  \Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed|\Illuminate\Queue\Events\JobProcessed|\Illuminate\Queue\Events\JobProcessing  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(JobExceptionOccurred|JobFailed|JobProcessed|JobProcessing $event): void
    {
        $container = Container::getInstance();
        $frames    = $container->make(ExecutionFrames::class);

        if (!$event instanceof JobProcessing) {

            $frames->leave($event->job);

            return;
        }

        $onWorker = !$event->job instanceof SyncJob;

        if ($onWorker) {
            $container->make(RequestIdentity::class)->forgetResolved();
        }

        $carried = CarriedContext::actor($container->make(Repository::class));

        $frames->enterJob($event->job, self::nameFrom($event->job->resolveName()), $carried, $onWorker ? self::leftovers($container) : []);
    }

    /**
     * The users the guards hold as a worker job starts, or none when they
     * cannot be read; a record the job makes then fails closed.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return array<string, object>
     */
    private static function leftovers(Container $container): array
    {
        try {
            return $container->make(AmbientActor::class)->held();
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * The payload's job name, or `null` when it is not a string, since a queued
     * payload is untrusted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $name
     * @return ?string
     */
    private static function nameFrom(mixed $name): ?string
    {
        return is_string($name) ? $name : null;
    }
}
