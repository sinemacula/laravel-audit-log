<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Illuminate\Contracts\Auth\Guard;
use SineMacula\Laravel\AuditLog\Records\HeldActor;

/**
 * Held actor reader contract: reads who a guard without `GuardHelpers` already
 * holds, for the ambient actor. It reads only what the guard has bound: never
 * `user()`, never authenticating or reading a request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HeldActorReader
{
    /**
     * The actor the guard holds, or `null` to leave the guard to the
     * `GuardHelpers` reading; an `\InvalidArgumentException` means no ambient
     * actor.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Guard  $instance
     * @return ?\SineMacula\Laravel\AuditLog\Records\HeldActor
     *
     * @throws \InvalidArgumentException
     */
    public function read(string $guard, Guard $instance): ?HeldActor;
}
