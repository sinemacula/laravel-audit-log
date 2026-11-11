<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Who started a piece of work, as references and the guard that gave them:
 * never a model, and never turned back into one, so it says who started the
 * work rather than who is authenticated now, and it stays valid after the actor
 * is deleted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActorSnapshot
{
    /** @var int Longest guard name, in characters: the `guard` column. */
    private const int GUARD_MAX_CHARACTERS = 64;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\HeldActor  $held
     * @param  string  $guard
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The actor, with the principal, tenant and session that go with it. */
        public HeldActor $held,

        /** The name of the guard that gave the actor, from 1 to 64 clean characters. */
        public string $guard,
    ) {
        if ($guard === '' || mb_strlen($guard, 'UTF-8') > self::GUARD_MAX_CHARACTERS || !TextSanitizer::isClean($guard)) {
            throw new \InvalidArgumentException(sprintf('A guard name must be from 1 to %d characters, with no control characters.', self::GUARD_MAX_CHARACTERS));
        }
    }
}
