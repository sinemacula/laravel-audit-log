<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The actor a guard holds, as a `Contracts\HeldActorReader` gives it, with the
 * principal, tenant and session reference that go with it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HeldActor
{
    /** @var int Longest session reference, in characters: the `session_id` column. */
    private const int SESSION_MAX_CHARACTERS = 191;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $session
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Who the guard holds. */
        public Reference $actor,

        /** The principal the actor acts as, if any. */
        public ?Reference $principal = null,

        /** The tenant the actor acts in, if any. */
        public ?Reference $tenant = null,

        /** An application-owned, non-secret session reference, never Laravel's session id. */
        public ?string $session = null,
    ) {
        if ($session !== null && ($session === '' || mb_strlen($session, 'UTF-8') > self::SESSION_MAX_CHARACTERS || !TextSanitizer::isClean($session))) {
            throw new \InvalidArgumentException(sprintf('A session reference must be from 1 to %d characters, with no control characters.', self::SESSION_MAX_CHARACTERS));
        }
    }
}
