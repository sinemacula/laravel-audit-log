<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * A pending record's state at one moment, as the recorder reads it and the
 * captured record is built from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSnapshot
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $credentialId
     * @param  ?string  $correlationId
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @param  ?array<array-key, mixed>  $properties
     * @param  ?string  $note
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null  $noteOwner
     * @param  ?string  $guard
     * @param  ?string  $sessionId
     * @param  ?string  $requestId
     * @param  ?string  $traceId
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Enums\Origin  $origin
     * @param  ?array<array-key, mixed>  $context
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @param  bool  $failClosed
     * @param  list<list<int|string>>  $collisions
     * @param  int  $collisionCount
     * @param  ?string  $identifier
     * @param  list<list<int|string>>  $contextCollisions
     * @param  int  $contextCollisionCount
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @param  ?string  $id
     */
    public function __construct(

        /** The code naming what happened, once given. */
        public ?EventCode $code,

        /** What the activity was done to, if anything. */
        public ?Reference $subject,

        /** Who did it; `null` when no one is known or explicitly no one. */
        public ?Reference $actor,

        /** The principal the actor acted as, if any. */
        public ?Reference $principal,

        /** The tenant the activity happened in, if any. */
        public ?Reference $tenant,

        /** Identifier of the credential the activity used, if any; never a secret. */
        #[\SensitiveParameter]
        public ?string $credentialId,

        /** Namespaced id tying the record to other activity, if any. */
        public ?string $correlationId,

        /** How the activity ended. */
        public Outcome $outcome,

        /** Why it failed or was denied, as a machine-readable code, if given. */
        public ?string $reason,

        /** The properties, normalised, as a map; `null` when there are none. */
        #[\SensitiveParameter]
        public ?array $properties,

        /** The note, cleaned and capped, if one was given. */
        #[\SensitiveParameter]
        public ?string $note,

        /** Whose key the note is encrypted under; `null` for a plaintext note. */
        public KeyOwner|Reference|null $noteOwner,

        /** The authentication guard the activity ran under, if known. */
        public ?string $guard,

        /** An application-owned, non-secret reference to the session, if known. */
        public ?string $sessionId,

        /** The request's id, if known. */
        public ?string $requestId,

        /** The W3C trace id of a trusted `traceparent`, if known. */
        public ?string $traceId,

        /** The client's IP address as it was filled, valid or not, if known. */
        #[\SensitiveParameter]
        public ?string $ip,

        /** The client's user agent, cleaned and capped, if known. */
        public ?string $userAgent,

        /** Where the activity ran, once filled. */
        public ?Origin $origin,

        /** The context, normalised, as a map; `null` when there is none. */
        #[\SensitiveParameter]
        public ?array $context,

        /** When the record is written; `null` when the recorder applies its default. */
        public ?Timing $timing,

        /** The connection the timing is pinned to, if any. */
        public ?string $connection,

        /** Whether a failed write throws. */
        public bool $failClosed,

        /** Paths of the property keys that collided once cleaned, first 32; raw until masked. */
        #[\SensitiveParameter]
        public array $collisions,

        /** How many property keys collided once cleaned. */
        public int $collisionCount,

        /** The identifier a sign-in was attempted with, raw until it is hashed at capture, if given. */
        #[\SensitiveParameter]
        public ?string $identifier,

        /** Paths of the context keys that collided once cleaned, first 32; raw until masked. */
        #[\SensitiveParameter]
        public array $contextCollisions,

        /** How many context keys collided once cleaned. */
        public int $contextCollisionCount,

        /** What a bulk operation affected, before it is sealed; `null` for any other record. */
        public ?Manifest $manifest = null,

        /** The id the package gave its own record; `null` for a fresh one. */
        public ?string $id = null,
    ) {}
}
