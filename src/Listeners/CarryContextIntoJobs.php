<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Log\Context\Repository;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;

/**
 * Carries the request id, trace id and ambient actor into a queued job as
 * hidden Context on the payload's copy, which is not encrypted in the queue.
 *
 * It runs inside the host's `dispatch()`, so a failure is reported once and the
 * job goes without the actor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CarryContextIntoJobs
{
    /**
     * Handle the `ContextDehydrating` event.
     *
     * @param  \Illuminate\Log\Context\Events\ContextDehydrating  $event
     * @return void
     */
    public function __invoke(ContextDehydrating $event): void
    {
        $container = Container::getInstance();

        try {
            self::carry($event->context, $container);
        } catch (\Throwable $exception) {
            CarriedContext::forgetActor($event->context);

            self::report($container, $exception);
        }
    }

    /**
     * Write what the job carries; inside a job with no ambient actor, the actor
     * it carried goes on to its chained jobs.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  \Illuminate\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function carry(Repository $context, Container $container): void
    {
        $identity = $container->make(RequestIdentity::class);

        $context->addHidden(CarriedContext::REQUEST_ID, $identity->requestId());

        $traceId = $identity->traceId();

        if ($traceId !== null) {
            $context->addHidden(CarriedContext::TRACE_ID, $traceId);
        }

        $actor = $container->make(AmbientActor::class)->current() ?? $container->make(ExecutionFrames::class)->carriedActor();

        if ($actor === null) {

            CarriedContext::forgetActor($context);

            return;
        }

        CarriedContext::carryActor($context, $actor);
    }

    /**
     * Report the failure, unless the report itself made this dispatch.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \Throwable  $exception
     * @return void
     */
    private static function report(Container $container, \Throwable $exception): void
    {
        try {
            $container->make(ReportLatch::class)->once(static function () use ($container, $exception): void {
                $container->make(ExceptionHandler::class)->report($exception);
            });
        } catch (\Throwable) {
            // A broken reporter must not stop the host's dispatch
        }
    }
}
