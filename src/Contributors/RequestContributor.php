<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;

/**
 * Fills the request id and trace id, and from an innermost HTTP frame the
 * client's IP address and user agent, the method and the route's name; never a
 * URL, a path or a query string.
 *
 * A client can choose the method through `_method` or an override header, so it
 * is stored only when it is a standard method.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestContributor implements ContextContributor
{
    /** @var list<string> The methods a record may store. */
    private const array METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     * @param  \SineMacula\Laravel\AuditLog\Runtime\RequestIdentity  $identity
     */
    public function __construct(

        /** What the current code is running in. */
        private ExecutionFrames $frames,

        /** The request id and trace id of the work in hand. */
        private RequestIdentity $identity,
    ) {}

    /**
     * Fill the identifiers and, from an innermost HTTP frame, the client, the
     * method and the route's name.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        $contribution->fillRequest($this->identity->requestId(), $this->identity->traceId());

        $request = $this->frames->request();

        if ($request === null) {
            return;
        }

        $contribution->fillClient(self::ipOf($request), $request->userAgent());
        $contribution->fillContext(self::routeOf($request));
    }

    /**
     * The request's IP address, kept only when it is a valid one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?string
     */
    private static function ipOf(Request $request): ?string
    {
        $ip = $request->ip();

        return filter_var($ip, FILTER_VALIDATE_IP) === false ? null : $ip;
    }

    /**
     * The request's method, when it is a standard one, and the route's name,
     * when its route has one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, string>
     */
    private static function routeOf(Request $request): array
    {
        $route  = $request->route();
        $name   = $route instanceof Route ? $route->getName() : null;
        $method = self::methodOf($request);

        return [...($method === null ? [] : ['method' => $method]), ...($name === null ? [] : ['route' => $name])];
    }

    /**
     * The request's method, or `null` for an override that is malformed, which
     * Symfony refuses with an exception, or that is no standard method.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?string
     */
    private static function methodOf(Request $request): ?string
    {
        try {
            $method = $request->getMethod();
        } catch (SuspiciousOperationException) { // @phpstan-ignore catch.neverThrown
            return null;
        }

        return in_array($method, self::METHODS, true) ? $method : null;
    }
}
