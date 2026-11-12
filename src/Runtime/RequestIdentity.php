<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Http\Request;
use Illuminate\Log\Context\Repository;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;

/**
 * The request id and trace id of the work in hand, kept in hidden Context so a
 * queued job inherits them, and remembered here because `Context::scope()`
 * drops an id first made inside it.
 *
 * An inbound header is trusted only from a trusted proxy, with its flag on and
 * one well-formed value. `isFromTrustedProxy()` checks only the immediate peer,
 * so the trusted edge must overwrite these headers.
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
     * The request id: carried by Context, already known, trusted inbound, or a
     * new UUID v7.
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
     * The trace id: carried by Context, already known or trusted inbound;
     * `null` when none, since none is generated.
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
     * Forget the ids and the package's hidden keys, leaving the rest of
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
     * Forget the remembered ids but not Context, which Laravel has just
     * hydrated for a worker's job.
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
     * The header's single value on a request from a trusted proxy, else `null`.
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
