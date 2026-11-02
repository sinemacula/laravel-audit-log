<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Records\Enums\Origin;

/**
 * The view of a pending record a contributor gets: it may fill the gaps in the
 * record and read what it needs to decide how, and it cannot record the record,
 * choose its timing, or read its properties or note.
 *
 * It holds nothing and validates nothing of its own, since every method
 * delegates to the builder. A filler fills only a field that is neither given
 * nor filled yet, so an explicit value is never replaced, `by(null)` included,
 * and the first contributor to fill a field wins; a filler given `null` changes
 * nothing and leaves the field open for the next. A malformed value is refused
 * whether or not it would have been used.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Contribution
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     *
     * @internal
     */
    public function __construct(

        /** The builder being contributed to; only the recorder makes a view of one. */
        private PendingRecord $pending,
    ) {}

    /**
     * Fill the actor, unless one was given or filled already, `by(null)`
     * included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return void
     *
     * @throws \LogicException
     */
    public function fillActor(?Reference $actor): void
    {
        $this->pending->fillActor($actor);
    }

    /**
     * Fill the principal, unless one was given or filled already,
     * `asPrincipal(null)` included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @return void
     *
     * @throws \LogicException
     */
    public function fillPrincipal(?Reference $principal): void
    {
        $this->pending->fillPrincipal($principal);
    }

    /**
     * Fill the tenant, unless one was given or filled already,
     * `forTenant(null)` included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return void
     *
     * @throws \LogicException
     */
    public function fillTenant(?Reference $tenant): void
    {
        $this->pending->fillTenant($tenant);
    }

    /**
     * Fill the name of the authentication guard the activity ran under: 1 to 64
     * characters.
     *
     * @param  ?string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillGuard(?string $guard): void
    {
        $this->pending->fillGuard($guard);
    }

    /**
     * Fill the session reference: an application-owned, non-secret reference to
     * the session, never Laravel's session id, which is the secret its cookie
     * carries. 1 to 191 characters.
     *
     * @param  ?string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillSession(?string $sessionId): void
    {
        $this->pending->fillSession($sessionId);
    }

    /**
     * Fill the request id, 1 to 64 characters, and the W3C trace id of a
     * trusted `traceparent`, 32 lower-case hexadecimal digits not all zero,
     * each on its own.
     *
     * @param  ?string  $requestId
     * @param  ?string  $traceId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillRequest(?string $requestId, ?string $traceId = null): void
    {
        $this->pending->fillRequest($requestId, $traceId);
    }

    /**
     * Fill the client's IP address, 1 to 255 characters, and its user agent,
     * cleaned and cut to 512 bytes, each on its own.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillClient(?string $ip, ?string $userAgent): void
    {
        $this->pending->fillClient($ip, $userAgent);
    }

    /**
     * Fill where the activity ran: an HTTP request, a console command or a
     * queued job.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Origin  $origin
     * @return void
     *
     * @throws \LogicException
     */
    public function fillOrigin(Origin $origin): void
    {
        $this->pending->fillOrigin($origin);
    }

    /**
     * Fill the context, a map of names to values such as the route name, the
     * method, the command or the job; only the keys the context does not hold
     * yet are added, so the first contributor to name a key wins. Never give a
     * URL or a query string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $context
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillContext(array $context): void
    {
        $this->pending->fillContext($context);
    }

    /**
     * The event code naming what happened.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function code(): string
    {
        $code = $this->pending->snapshot()->code;

        if ($code === null) {
            throw new \LogicException('A pending record needs an event code before it is recorded; set one with `event()`.');
        }

        return $code->value;
    }

    /**
     * What the activity was done to, if anything.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \LogicException
     */
    public function subject(): ?Reference
    {
        return $this->pending->snapshot()->subject;
    }

    /**
     * Who did it, given or filled so far; `null` for no actor yet and for
     * explicitly no one, which `isActorSettled()` tells apart.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \LogicException
     */
    public function actor(): ?Reference
    {
        return $this->pending->snapshot()->actor;
    }

    /**
     * Whether a non-null actor is present.
     *
     * @return bool
     *
     * @throws \LogicException
     */
    public function hasActor(): bool
    {
        return $this->actor() !== null;
    }

    /**
     * Whether the actor is given or filled, so no filler can change it,
     * `by(null)` included.
     *
     * @return bool
     *
     * @throws \LogicException
     */
    public function isActorSettled(): bool
    {
        return $this->pending->isActorSettled();
    }
}
