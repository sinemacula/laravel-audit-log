<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Records\Enums\Origin;

/**
 * A contributor's view of a pending record: it fills the gaps and reads what it
 * needs, but cannot record, choose a timing, or read properties or note.
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

        /** The builder being contributed to. */
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
     * Fill the authentication guard's name.
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
     * Fill an application-owned session reference, never Laravel's session id,
     * which is the secret its cookie carries.
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
     * Fill the credential's identifier, never the secret.
     *
     * @param  ?string  $credentialId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillCredential(#[\SensitiveParameter] ?string $credentialId): void
    {
        $this->pending->fillCredential($credentialId);
    }

    /**
     * Fill the request id and the W3C trace id of a trusted `traceparent`, each
     * on its own.
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
     * Fill the client's IP address, as it comes, and its user agent, each on
     * its own; an invalid address is stored as `null`.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillClient(#[\SensitiveParameter] ?string $ip, #[\SensitiveParameter] ?string $userAgent): void
    {
        $this->pending->fillClient($ip, $userAgent);
    }

    /**
     * Fill where the activity ran.
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
     * Add the context keys not held yet, so the first contributor to name a key
     * wins; never give a URL or a query string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $context
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function fillContext(#[\SensitiveParameter] array $context): void
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
     * Who did it so far; `null` for no actor yet and for explicitly no one,
     * which `isActorSettled()` tells apart.
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
