<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * The gaps a contributor fills in the pending record, never over an explicit
 * value; a trait only to keep `PendingRecord` within the method-count limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait FillsAmbientContext
{
    /** @var int Longest guard name, in characters: the `guard` column. */
    private const int GUARD_MAX_CHARACTERS = 64;

    /** @var int Longest session reference, in characters: the `session_id` column. */
    private const int SESSION_MAX_CHARACTERS = 191;

    /** @var int Longest request id, in characters: the `request_id` column. */
    private const int REQUEST_MAX_CHARACTERS = 64;

    /** @var int Longest user agent kept, in bytes: the `user_agent` column. */
    private const int USER_AGENT_MAX_BYTES = 512;

    /** @var string Pattern of a W3C trace id: 32 lower-case hexadecimal digits. */
    private const string TRACE_PATTERN = '/\A[0-9a-f]{32}\z/';

    /** @var string The invalid W3C trace id: every digit zero. */
    private const string ZERO_TRACE = '00000000000000000000000000000000';

    /** @var array<string, true> The fields given explicitly or filled. */
    private array $given = [];

    /** @var ?string The authentication guard the activity ran under, if known. */
    private ?string $guard = null;

    /** @var ?string An application-owned, non-secret reference to the session, if known. */
    private ?string $sessionId = null;

    /** @var ?string The request's id, if known. */
    private ?string $requestId = null;

    /** @var ?string The W3C trace id of a trusted `traceparent`, if known. */
    private ?string $traceId = null;

    /** @var ?string The client's IP address as given, before it is minimised. */
    private ?string $ip = null;

    /** @var ?string The client's user agent, cleaned and capped, if known. */
    private ?string $userAgent = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Enums\Origin Where the activity ran, once filled. */
    private ?Origin $origin = null;

    // phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint

    /** @var array<array-key, mixed> The context, normalised, as a map. */
    private array $context = [];

    // phpcs:enable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint

    /** @var list<list<int|string>> Paths of the context keys that collided once cleaned, first 32 across every call. */
    private array $contextCollisions = [];

    /** @var int How many context keys collided once cleaned, across every call. */
    private int $contextCollisionCount = 0;

    /**
     * Fill the actor, unless one was given or filled already, `by(null)`
     * included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return void
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function fillActor(?Reference $actor): void
    {
        $this->assertUsable();

        if (!$this->claims('actor', $actor !== null)) {
            return;
        }

        $this->actor = $actor;
    }

    /**
     * Fill the principal, unless one was given or filled already,
     * `asPrincipal(null)` included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @return void
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function fillPrincipal(?Reference $principal): void
    {
        $this->assertUsable();

        if (!$this->claims('principal', $principal !== null)) {
            return;
        }

        $this->principal = $principal;
    }

    /**
     * Fill the tenant, unless one was given or filled already,
     * `forTenant(null)` included.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return void
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function fillTenant(?Reference $tenant): void
    {
        $this->assertUsable();

        if (!$this->claims('tenant', $tenant !== null)) {
            return;
        }

        $this->tenant = $tenant;
    }

    /**
     * Fill the authentication guard's name; validated, never cleaned or cut.
     *
     * @param  ?string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function fillGuard(?string $guard): void
    {
        $this->assertUsable();

        if ($guard === null) {
            return;
        }

        self::checkIdentifier($guard, self::GUARD_MAX_CHARACTERS, 'A guard name');

        if (!$this->claims('guard', true)) {
            return;
        }

        $this->guard = $guard;
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
     *
     * @internal
     */
    public function fillSession(?string $sessionId): void
    {
        $this->assertUsable();

        if ($sessionId === null) {
            return;
        }

        self::checkIdentifier($sessionId, self::SESSION_MAX_CHARACTERS, 'A session reference');

        if (!$this->claims('session', true)) {
            return;
        }

        $this->sessionId = $sessionId;
    }

    /**
     * Fill the request id and the W3C trace id of a trusted `traceparent`, each
     * on its own; validated, never cleaned or cut.
     *
     * @param  ?string  $requestId
     * @param  ?string  $traceId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function fillRequest(?string $requestId, ?string $traceId = null): void
    {
        $this->assertUsable();

        if ($requestId !== null) {
            self::checkIdentifier($requestId, self::REQUEST_MAX_CHARACTERS, 'A request id');
        }

        if ($traceId !== null) {
            self::checkTraceId($traceId);
        }

        if ($this->claims('request', $requestId !== null)) {
            $this->requestId = $requestId;
        }

        if (!$this->claims('trace', $traceId !== null)) {
            return;
        }

        $this->traceId = $traceId;
    }

    /**
     * Fill the client's IP address, taken as it comes for minimising to judge,
     * and its cleaned user agent, each on its own.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function fillClient(#[\SensitiveParameter] ?string $ip, #[\SensitiveParameter] ?string $userAgent): void
    {
        $this->assertUsable();

        $userAgent = self::userAgent($userAgent);

        if ($this->claims('ip', $ip !== null)) {
            $this->ip = $ip;
        }

        if (!$this->claims('user_agent', $userAgent !== null)) {
            return;
        }

        $this->userAgent = $userAgent;
    }

    /**
     * Fill where the activity ran.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Origin  $origin
     * @return void
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function fillOrigin(Origin $origin): void
    {
        $this->assertUsable();

        if (!$this->claims('origin', true)) {
            return;
        }

        $this->origin = $origin;
    }

    /**
     * Add the normalised context keys not held yet, so the first contributor to
     * name a key wins; never a URL or query string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $context
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function fillContext(#[\SensitiveParameter] array $context): void
    {
        $this->assertUsable();

        $normalised = ValueNormaliser::normalise($context);
        $values     = self::mapOf($normalised, 'Context is a map of names to values, not a list.');

        $this->context += $values;
        $this->contextCollisions = array_slice(array_merge($this->contextCollisions, $normalised->collisions), 0, Normalised::MAX_COLLISIONS);
        $this->contextCollisionCount += $normalised->collisionCount;
    }

    /**
     * Whether the actor is given or filled, so no filler can change it,
     * `by(null)` included.
     *
     * @return bool
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function isActorSettled(): bool
    {
        $this->assertUsable();

        return $this->isGiven('actor');
    }

    /**
     * Mark the field given, so no contributor fills it.
     *
     * @param  'actor'|'guard'|'ip'|'origin'|'principal'|'request'|'session'|'tenant'|'trace'|'user_agent'  $field
     * @return void
     */
    private function give(string $field): void
    {
        $this->given[$field] = true;
    }

    /**
     * Claim an unclaimed field for a contributor's value, saying whether to
     * keep it.
     *
     * @param  'actor'|'guard'|'ip'|'origin'|'principal'|'request'|'session'|'tenant'|'trace'|'user_agent'  $field
     * @param  bool  $present
     * @return bool
     */
    private function claims(string $field, bool $present): bool
    {
        if (!$present || $this->isGiven($field)) {
            return false;
        }

        $this->give($field);

        return true;
    }

    /**
     * Whether the field was given, explicitly or by a contributor.
     *
     * @param  'actor'|'guard'|'ip'|'origin'|'principal'|'request'|'session'|'tenant'|'trace'|'user_agent'  $field
     * @return bool
     */
    private function isGiven(string $field): bool
    {
        return $this->given[$field] ?? false;
    }

    /**
     * Refuse an identifier that is empty, too long or not clean text; one that
     * cleaning would change is not that identifier, so it is never cleaned.
     *
     * @param  string  $value
     * @param  int  $maxCharacters
     * @param  string  $name
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkIdentifier(#[\SensitiveParameter] string $value, int $maxCharacters, string $name): void
    {
        if ($value === '' || mb_strlen($value, 'UTF-8') > $maxCharacters || !TextSanitizer::isClean($value)) {
            throw new \InvalidArgumentException(sprintf('%s must be from 1 to %d characters, with no control characters.', $name, $maxCharacters));
        }
    }

    /**
     * The user agent cleaned and cut to 512 bytes; `null` when empty once
     * cleaned.
     *
     * @param  ?string  $userAgent
     * @return ?string
     */
    private static function userAgent(#[\SensitiveParameter] ?string $userAgent): ?string
    {
        $userAgent = $userAgent === null ? '' : TextSanitizer::clean($userAgent, self::USER_AGENT_MAX_BYTES);

        return $userAgent === '' ? null : $userAgent;
    }

    /**
     * Refuse a trace id that is not 32 lower-case hex digits, or is all zero,
     * which W3C Trace Context makes invalid.
     *
     * @param  string  $traceId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkTraceId(string $traceId): void
    {
        if (preg_match(self::TRACE_PATTERN, $traceId) !== 1 || $traceId === self::ZERO_TRACE) {
            throw new \InvalidArgumentException('A trace id must be 32 lower-case hexadecimal digits, not all zero.');
        }
    }

    /**
     * The normalised value as a map, refusing a non-empty list with the message
     * given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Support\Normalised  $normalised
     * @param  string  $message
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function mapOf(#[\SensitiveParameter] Normalised $normalised, string $message): array
    {
        $value = $normalised->value;

        if (!is_array($value) || ($value !== [] && array_is_list($value))) {
            throw new \InvalidArgumentException($message);
        }

        return $value;
    }
}
