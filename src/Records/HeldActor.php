<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The actor a guard holds, as a `Contracts\HeldActorReader` gives it, with the
 * principal, tenant, session reference and credential that go with it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HeldActor
{
    /** @var int Longest session reference or credential id, in characters: the `session_id` and `credential_id` columns. */
    private const int MAX_CHARACTERS = 191;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $session
     * @param  ?string  $credentialId
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

        /** The id of the credential the actor authenticated with, never the secret. */
        #[\SensitiveParameter] public ?string $credentialId = null,
    ) {
        self::check($session, 'A session reference');
        self::check($credentialId, 'A credential id');
    }

    /**
     * Refuse a value a record could not store.
     *
     * @param  ?string  $value
     * @param  string  $name
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function check(#[\SensitiveParameter] ?string $value, string $name): void
    {
        if ($value !== null && ($value === '' || mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS || !TextSanitizer::isClean($value))) {
            throw new \InvalidArgumentException(sprintf('%s must be from 1 to %d characters, with no control characters.', $name, self::MAX_CHARACTERS));
        }
    }
}
