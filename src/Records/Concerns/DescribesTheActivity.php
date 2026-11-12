<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\CorrelationId;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * The pending record's description of the activity; a trait only to keep
 * `PendingRecord` within the method-count limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DescribesTheActivity
{
    /** @var int Longest credential or correlation id, in characters: their columns. */
    private const int ID_MAX_CHARACTERS = 191;

    /** @var string Prefix of the property keys that belong to the package's own metadata. */
    private const string RESERVED_KEY = '_audit';

    /** @var ?\SineMacula\Laravel\AuditLog\Records\EventCode The code naming what happened, once given. */
    private ?EventCode $code = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference What the activity was done to, if anything. */
    private ?Reference $subject = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference Who did it, given or filled. */
    private ?Reference $actor = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference The principal the actor acted as, given or filled. */
    private ?Reference $principal = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference The tenant the activity happened in, given or filled. */
    private ?Reference $tenant = null;

    /** @var ?string Identifier of the credential the activity used, if any; never a secret. */
    private ?string $credentialId = null;

    /** @var ?string Namespaced id tying the record to other activity, such as `app:ticket-123`. */
    private ?string $correlationId = null;

    // phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint

    /** @var array<array-key, mixed> The properties, normalised, as a map. */
    private array $properties = [];

    // phpcs:enable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint

    /** @var ?string The note, cleaned and capped, if one was given. */
    private ?string $note = null;

    /** @var \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null Whose key the note is encrypted under; `null` for a plaintext note. */
    private KeyOwner|Reference|null $noteOwner = null;

    /** @var ?string The identifier a sign-in was attempted with, raw until it is hashed at capture. */
    private ?string $identifier = null;

    /** @var list<list<int|string>> Paths of the property keys that collided once cleaned, first 32 across every call. */
    private array $collisions = [];

    /** @var int How many property keys collided once cleaned, across every call. */
    private int $collisionCount = 0;

    /**
     * Name what happened with an event code or string-backed enum case; a code
     * beginning `audit_log.` is refused.
     *
     * @param  \BackedEnum|string  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function event(\BackedEnum|string $code): self
    {
        $this->assertUsable();

        $this->code = EventCode::of($code);

        return $this;
    }

    /**
     * Name what the activity was done to.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function on(Model|Reference $subject): self
    {
        $this->assertUsable();

        $this->subject = self::reference($subject);

        return $this;
    }

    /**
     * Name who did it; `null` says explicitly no one, which a contributor never
     * fills.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $actor
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function by(Model|Reference|null $actor): self
    {
        $this->assertUsable();

        $this->actor = self::reference($actor);
        $this->give('actor');

        return $this;
    }

    /**
     * Name the principal the actor acted as, such as a team or an account;
     * `null` says explicitly none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $principal
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function asPrincipal(Model|Reference|null $principal): self
    {
        $this->assertUsable();

        $this->principal = self::reference($principal);
        $this->give('principal');

        return $this;
    }

    /**
     * Name the tenant the activity happened in; `null` says explicitly none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $tenant
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function forTenant(Model|Reference|null $tenant): self
    {
        $this->assertUsable();

        $this->tenant = self::reference($tenant);
        $this->give('tenant');

        return $this;
    }

    /**
     * Name the guard the activity ran under, 1 to 64 characters; `null` says
     * explicitly none.
     *
     * @param  ?string  $guard
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function viaGuard(?string $guard): self
    {
        $this->assertUsable();

        if ($guard !== null) {
            self::checkIdentifier($guard, self::GUARD_MAX_CHARACTERS, 'A guard name');
        }

        $this->guard = $guard;
        $this->give('guard');

        return $this;
    }

    /**
     * Name the session by an application-owned, non-secret reference of 1 to
     * 191 characters, never Laravel's session id; `null` says explicitly none.
     *
     * @param  ?string  $sessionId
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function inSession(?string $sessionId): self
    {
        $this->assertUsable();

        if ($sessionId !== null) {
            self::checkIdentifier($sessionId, self::SESSION_MAX_CHARACTERS, 'A session reference');
        }

        $this->sessionId = $sessionId;
        $this->give('session');

        return $this;
    }

    /**
     * Name the client's IP address and user agent together, so no contributor
     * fills either; `null` says that part is explicitly unknown.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return self
     *
     * @throws \LogicException
     */
    public function fromClient(#[\SensitiveParameter] ?string $ip, #[\SensitiveParameter] ?string $userAgent): self
    {
        $this->assertUsable();

        $this->ip        = $ip;
        $this->userAgent = self::userAgent($userAgent);
        $this->give('ip');
        $this->give('user_agent');

        return $this;
    }

    /**
     * Name the credential the activity used by its identifier, never the
     * secret; validated, never cleaned or cut.
     *
     * @param  string  $credentialId
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function usingCredential(#[\SensitiveParameter] string $credentialId): self
    {
        $this->assertUsable();

        self::checkIdentifier($credentialId, self::ID_MAX_CHARACTERS, 'A credential id');

        $this->credentialId = $credentialId;

        return $this;
    }

    /**
     * Tie the record to other activity with a namespaced id such as
     * `app:ticket-123`; validated, never cleaned or cut.
     *
     * @param  string  $correlationId
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function correlatedWith(string $correlationId): self
    {
        $this->assertUsable();

        if (!CorrelationId::isValid($correlationId)) {
            throw new \InvalidArgumentException('A correlation id must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.');
        }

        $this->correlationId = $correlationId;

        return $this;
    }

    /**
     * Merge normalised properties into those already given; a key beginning
     * `_audit`, at any depth, is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function withProperties(#[\SensitiveParameter] array $properties): self
    {
        $this->assertUsable();

        $normalised = ValueNormaliser::normalise($properties);
        $values     = self::mapOf($normalised, 'Properties are a map of names to values, not a list.');

        self::checkKeys($values);

        $this->properties = array_replace($this->properties, $values);
        $this->collisions = array_slice(array_merge($this->collisions, $normalised->collisions), 0, Normalised::MAX_COLLISIONS);
        $this->collisionCount += $normalised->collisionCount;

        return $this;
    }

    /**
     * Add a note, cleaned and cut to 1,024 bytes; with an owner it is encrypted
     * and erasable, without one stored as given.
     *
     * @param  string  $text
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null  $owner
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function withNote(#[\SensitiveParameter] string $text, KeyOwner|Model|Reference|null $owner = null): self
    {
        $this->assertUsable();

        $note      = self::note($text);
        $noteOwner = $owner instanceof Model ? Reference::to($owner) : $owner;

        $this->note      = $note;
        $this->noteOwner = $noteOwner;

        return $this;
    }

    /**
     * Name the identifier a sign-in was attempted with, kept unvalidated as
     * untrusted input and hashed at capture apart from the properties.
     *
     * @param  string  $identifier
     * @return self
     *
     * @throws \LogicException
     */
    public function withIdentifier(#[\SensitiveParameter] string $identifier): self
    {
        $this->assertUsable();

        $this->identifier = $identifier;

        return $this;
    }

    /**
     * The reference a model or a reference gives, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $value
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function reference(Model|Reference|null $value): ?Reference
    {
        return $value instanceof Model ? Reference::to($value) : $value;
    }

    /**
     * Refuse properties holding a reserved key at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkKeys(#[\SensitiveParameter] array $values): void
    {
        if (self::holdsReservedKey($values)) {
            throw new \InvalidArgumentException(sprintf('Keys beginning `%s` are reserved for the package\'s own metadata.', self::RESERVED_KEY));
        }
    }

    /**
     * The note's text cleaned and cut to its cap, refusing one empty once
     * cleaned.
     *
     * @param  string  $text
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function note(#[\SensitiveParameter] string $text): string
    {
        $note = TextSanitizer::clean($text, self::NOTE_MAX_BYTES);

        if ($note === '') {
            throw new \InvalidArgumentException('A note must have text.');
        }

        return $note;
    }

    /**
     * Whether any key of the map, at any depth, begins with the reserved
     * prefix.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private static function holdsReservedKey(#[\SensitiveParameter] array $values): bool
    {
        foreach ($values as $key => $value) {
            if (str_starts_with((string) $key, self::RESERVED_KEY) || (is_array($value) && self::holdsReservedKey($value))) {
                return true;
            }
        }

        return false;
    }
}
