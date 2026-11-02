<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Http\Request;
use Illuminate\Log\Context\Repository;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;

/**
 * The request id and trace id of the work in hand, kept in hidden Context so a
 * queued job inherits them.
 *
 * A request id is what Context carries, or else a trusted inbound id, or else a
 * UUID v7 from the clock, and it is generated only when first asked for. A
 * trace id is what Context carries, or else a trusted `traceparent`; it is
 * never generated, so there may be none. A value that is found is stored, so it
 * stays the same for the rest of the work, a carried value that is malformed is
 * ignored, and a malformed request id is replaced.
 *
 * Context alone cannot keep that promise, because `Context::scope()` restores
 * hidden Context when it ends and would drop an id first made inside it, so the
 * ids are remembered here as well. Context still comes first, so a job's
 * hydrated ids win, and a remembered id is written back to Context. A job on a
 * worker forgets what an earlier job left here.
 *
 * An inbound header is trusted only from the HTTP frame anywhere on the stack,
 * with its flag on, from a trusted proxy, under exactly one value, and when it
 * is well formed. Anything else falls through silently: a header is never
 * reported or kept. `isFromTrustedProxy()` checks only the immediate peer, so
 * the trusted edge must overwrite or validate these headers. A malformed
 * setting is a refusal, not a fall-through, and fails closed whichever peer the
 * request came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequestIdentity
{
    /** @var string The W3C Trace Context header. */
    private const string TRACEPARENT_HEADER = 'traceparent';

    /** @var ?string The request id once it is known, whatever becomes of Context. */
    private ?string $requestId = null;

    /** @var ?string The trace id once it is known, whatever becomes of Context. */
    private ?string $traceId = null;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ContextSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The scoped Context the identifiers are kept in. */
        private readonly Repository $context,

        /** The frames, which say whether there is a request to read a header from. */
        private readonly ExecutionFrames $frames,

        /** Whether an inbound header is believed, and under which name. */
        private readonly ContextSettings $settings,

        /** The clock a generated request id takes its time from. */
        private readonly Clock $clock,
    ) {}

    /**
     * The request id: the one Context carries, the one already known, a trusted
     * inbound one, or a new UUID v7, stored in all but the first case.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function requestId(): string
    {
        $carried = InboundIdentifiers::requestId($this->context->getHidden(CarriedContext::REQUEST_ID));

        if ($carried !== null) {
            return $this->requestId = $carried;
        }

        $this->requestId ??= $this->inboundRequestId() ?? Str::uuid7($this->clock->now())->toString();

        $this->context->addHidden(CarriedContext::REQUEST_ID, $this->requestId);

        return $this->requestId;
    }

    /**
     * The trace id: the one Context carries, or the one already known or a
     * trusted inbound one, which is stored; `null` when there is none of them,
     * since none is ever generated.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function traceId(): ?string
    {
        $carried = InboundIdentifiers::traceId($this->context->getHidden(CarriedContext::TRACE_ID));

        if ($carried !== null) {
            return $this->traceId = $carried;
        }

        $this->traceId ??= $this->inboundTraceId();

        if ($this->traceId !== null) {
            $this->context->addHidden(CarriedContext::TRACE_ID, $this->traceId);
        }

        return $this->traceId;
    }

    /**
     * Forget the ids and the package's hidden keys, and nothing else in
     * Context.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->forgetResolved();

        $this->context->forgetHidden([CarriedContext::REQUEST_ID, CarriedContext::TRACE_ID]);

        CarriedContext::forgetActor($this->context);
    }

    /**
     * Forget the ids this object remembers and leave Context as it is, for a
     * job on a worker, whose Context Laravel has just hydrated from its
     * payload.
     *
     * @return void
     */
    public function forgetResolved(): void
    {
        $this->requestId = null;
        $this->traceId   = null;
    }

    /**
     * The request id a trusted edge sent, if any.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function inboundRequestId(): ?string
    {
        $request = $this->frames->inboundRequest();

        if ($request === null || !$this->settings->trustsRequestId()) {
            return null;
        }

        return InboundIdentifiers::requestId(self::soleValue($request, $this->settings->requestIdHeader()));
    }

    /**
     * The trace id of the `traceparent` a trusted edge sent, if any.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function inboundTraceId(): ?string
    {
        $request = $this->frames->inboundRequest();

        if ($request === null || !$this->settings->trustsTraceparent()) {
            return null;
        }

        return InboundIdentifiers::traceparent(self::soleValue($request, self::TRACEPARENT_HEADER));
    }

    /**
     * The one value the header has on a request from a trusted proxy; `null`
     * from any other peer, and with no value or more than one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $header
     * @return ?string
     */
    private static function soleValue(Request $request, string $header): ?string
    {
        if (!$request->isFromTrustedProxy()) {
            return null;
        }

        $values = $request->headers->all($header);

        return count($values) === 1 ? $values[0] : null;
    }
}
