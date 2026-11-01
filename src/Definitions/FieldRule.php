<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;

/**
 * One field rule of an event definition: the path it names and how the value
 * there is handled, with, for an encrypted field, the owner whose key it is
 * stored under.
 *
 * An encrypted field always names its owner, the record's actor or subject or
 * the path of a property holding a reference, and only an encrypted field names
 * one. When the owner is absent from a record or has no key, the field is
 * dropped, never stored in plaintext; applying a rule to a payload is the
 * redaction pipeline's work, not this class's.
 *
 * Definitions build their rules through `EventDefinition::rule()` and its
 * shorthands.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FieldRule
{
    /** @var non-empty-list<string> The path's segments. */
    public array $segments;

    /**
     * Constructor.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string|null  $owner
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function __construct(

        /** The path, as written. */
        public string $path,

        /** How the field is handled. */
        public FieldHandling $handling,

        /** An encrypted field's owner: an owner kind or the path of a property holding a reference. */
        public KeyOwner|string|null $owner = null,
    ) {
        $this->segments = FieldPath::parse($path);

        self::checkOwner($path, $handling, $owner);
    }

    /**
     * Whether the other rule has the same path, handling and owner.
     *
     * @param  self  $other
     * @return bool
     */
    public function equals(self $other): bool
    {
        return $this->path     === $other->path
            && $this->handling === $other->handling
            && $this->owner    === $other->owner;
    }

    /**
     * Refuse an encrypted field without an owner, an owner on any other field,
     * and an owner's path that is malformed, holds `*` or is the field's own.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string|null  $owner
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkOwner(string $path, FieldHandling $handling, KeyOwner|string|null $owner): void
    {
        if ($handling !== FieldHandling::ENCRYPT) {
            if ($owner !== null) {
                throw new \InvalidArgumentException('Only an encrypted field names an owner.');
            }

            return;
        }

        if ($owner === null || $owner === '') {
            throw new \InvalidArgumentException('An encrypted field must name its owner: `KeyOwner::ACTOR`, `KeyOwner::SUBJECT` or the path of a property holding a reference.');
        }

        if ($owner instanceof KeyOwner) {
            return;
        }

        self::checkOwnerPath($path, $owner);
    }

    /**
     * Refuse an owner's path that is malformed, holds `*` or is the field's
     * own.
     *
     * @param  string  $path
     * @param  string  $owner
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkOwnerPath(string $path, string $owner): void
    {
        if (FieldPath::hasWildcard(FieldPath::parse($owner))) {
            throw new \InvalidArgumentException('An owner\'s path must name one property, without `*`.');
        }

        if ($owner === $path) {
            throw new \InvalidArgumentException('An encrypted field cannot be its own owner.');
        }
    }
}
