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
 * Carries the request id, the trace id and the ambient actor into a queued job,
 * as hidden keys on the copy of Context the payload is made from, never on the
 * scoped repository. A request id is generated now if none exists yet, so
 * dispatching before the first record still carries it.
 *
 * With no ambient actor inside a job, the actor that job carried goes on, so
 * its chained jobs keep it. Anything else a sync job left in Context is dropped
 * rather than sent on.
 *
 * This runs inside the host's `dispatch()`, and a malformed setting or an
 * unreferenceable user must not stop a job being queued. Any failure is
 * reported and the job goes without the actor, so no stale one goes out. A
 * handler that dispatches while it reports comes back here, so the failure is
 * reported once and not again from inside its own report.
 *
 * Hidden Context stays out of the logs, but it travels in the queue payload
 * unencrypted.
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
     * Write what the job carries on the repository given.
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
     * Report the failure, unless this is a dispatch the report itself made. A
     * reporter that fails too is ignored: there is nowhere left to say so, and
     * the job must still be queued.
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
            // A broken reporter must not stop the host's dispatch, which this
            // runs inside
        }
    }
}
