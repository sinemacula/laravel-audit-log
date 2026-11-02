<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * The pending record's description of the activity: its event code, the
 * references it names (subject, actor, principal and tenant), the credential
 * and correlation ids, the properties, the note, and the identifier a sign-in
 * was attempted with.
 *
 * Setting a field again replaces it, the last call winning, except that
 * properties merge at the top level, later keys replacing earlier ones. A model
 * is referred to through `Reference::to()`, so an unsaved one is refused, and a
 * value is normalised when it is given, so the builder's properties hold only
 * strings, integers, booleans, `null`, lists and maps, and every other field a
 * validated value. `by(null)`, `asPrincipal(null)` and `forTenant(null)` say
 * that there is explicitly none, which a contributor never fills.
 *
 * The methods sit in a trait only so the builder stays within the number of
 * methods one class may declare; they are `PendingRecord`'s public surface.
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

    /** @var string Pattern of a correlation id: a lower-case namespace, a colon, then a value that starts with a non-space. */
    private const string CORRELATION_PATTERN = '/\A[a-z][a-z0-9_-]{0,31}:\S.*\z/u';

    /** @var string Prefix of the property keys that belong to the package's own metadata. */
    private const string RESERVED_KEY = '_audit';

    /** @var ?\SineMacula\Laravel\AuditLog\Records\EventCode The code naming what happened, once given. */
    private ?EventCode $code = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference What the activity was done to, if anything. */
    private ?Reference $subject = null;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Reference Who did it, given or filled; `null` also when explicitly no one. */
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

    /** @var list<list<int|string>> Concrete paths of the property keys that collided once cleaned, segment by segment, first 32 across every call. */
    private array $collisions = [];

    /** @var int How many property keys collided once cleaned, across every call. */
    private int $collisionCount = 0;

    /**
     * Name what happened with an event code, given as a string or as a
     * string-backed enum case; a code beginning `audit_log.` is refused. The
     * last code given wins.
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
     * Name what the activity was done to: a model, by its reference, or a
     * reference. The last subject given wins.
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
     * Name who did it: a model, by its reference, or a reference; `null` says
     * that explicitly no one did, which a contributor never fills, unlike an
     * actor that is never given. The last actor given wins, and it replaces one
     * a contributor filled.
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
     * `null` says that there is explicitly none, which a contributor never
     * fills. The last principal given wins.
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
     * Name the tenant the activity happened in; `null` says that there is
     * explicitly none, which a contributor never fills. The last tenant given
     * wins.
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
     * Name the credential the activity used, by its id: an API key's or a
     * token's identifier, never the secret itself. The id is validated, never
     * cleaned or cut. The last id given wins.
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
     * Tie the record to other activity with a namespaced id, written
     * `<namespace>:<value>` (`app:ticket-123`): a lower-case namespace of up to
     * 32 characters, then a value that starts with a non-space. The id is
     * validated, never cleaned or cut. The last id given wins.
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

        self::checkCorrelationId($correlationId);

        $this->correlationId = $correlationId;

        return $this;
    }

    /**
     * Describe the activity with properties, a map of names to values,
     * normalised now: a model becomes its reference, an enum its value, a date
     * ISO-8601 UTC, and so on. The map merges into the properties already
     * given, a later key replacing an earlier one. A key beginning `_audit`, at
     * any depth, belongs to the package's own metadata and is refused, and then
     * nothing is merged.
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
     * Add a note in words, cleaned and cut to 1,024 bytes on a character
     * boundary. With an owner (a model, by its reference, a reference, or the
     * record's actor or subject) the note is erasable and is never stored in
     * plaintext; without one it is stored as given and cannot be erased. No
     * note is claimed to be free of secrets. The last note given wins, its text
     * and owner together.
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
     * Name the identifier a sign-in was attempted with, such as the email
     * address a form posted. It is kept as given and validated not at all,
     * because it is untrusted input and not a programming error. It is hashed
     * at capture to `properties._audit.identifier_hash` under
     * `redaction.identifiers`. It is not in the properties, so
     * `withProperties()` cannot spoof it and an `unlisted = DROP` definition
     * cannot lose it. The last identifier given wins.
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
     * Refuse a correlation id that is not namespaced, is longer than its
     * column, or is not already clean text.
     *
     * @param  string  $correlationId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkCorrelationId(string $correlationId): void
    {
        $fits = mb_strlen($correlationId, 'UTF-8') <= self::ID_MAX_CHARACTERS && TextSanitizer::isClean($correlationId);

        if ($fits && preg_match(self::CORRELATION_PATTERN, $correlationId) === 1) {
            return;
        }

        throw new \InvalidArgumentException('A correlation id must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.');
    }

    /**
     * Refuse properties holding a key, at any depth, that begins with the
     * prefix of the package's own metadata.
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
     * The note's text cleaned and cut to its cap, refusing text that is empty
     * once cleaned.
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
     * Whether any key of the normalised map, at any depth, begins with the
     * prefix of the package's own metadata.
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
