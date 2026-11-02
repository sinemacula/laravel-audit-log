<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enters the execution frame of an HTTP request and forgets the identity of any
 * earlier one, so a record made anywhere inside it, global middleware included,
 * has the request's origin, its client and its own request id.
 *
 * The package prepends it to the HTTP kernel's global stack. Only the package's
 * hidden keys are forgotten: the rest of Context belongs to the application. It
 * has no `terminate()`, because the frame must outlive the response:
 * `terminating()` callbacks, `defer()` and terminable middleware keep their
 * request, and the frame ends with the scoped instance that holds it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnterHttpFrame
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     * @param  \SineMacula\Laravel\AuditLog\Runtime\RequestIdentity  $identity
     */
    public function __construct(

        /** The frames the request's is entered on. */
        private ExecutionFrames $frames,

        /** The identity an earlier request left behind, which is forgotten. */
        private RequestIdentity $identity,
    ) {}

    /**
     * Enter the request's frame, forget any earlier identity and pass the
     * request on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        $this->frames->enterRequest($request);
        $this->identity->forget();

        return $next($request);
    }
}
