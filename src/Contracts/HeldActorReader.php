<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Illuminate\Contracts\Auth\Guard;
use SineMacula\Laravel\AuditLog\Records\HeldActor;

/**
 * Held actor reader contract: reads who a guard that does not use Laravel's
 * `GuardHelpers` already holds, so its user can be the ambient actor.
 *
 * It is asked only for the first guard in the walk whose `hasUser()` is true,
 * and only when an integration binds it. It must read only what the guard has
 * bound: never `user()`, never authenticate, never read a request. `null`
 * leaves the guard to the `GuardHelpers` reading, and an
 * `\InvalidArgumentException` means no ambient actor. A guard it reads must not
 * keep its user from one queued job to the next on a worker, since only a
 * `GuardHelpers` guard's leftover user is recognised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HeldActorReader
{
    /**
     * The actor the guard holds, or `null` when this reader does not read it.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Guard  $instance
     * @return ?\SineMacula\Laravel\AuditLog\Records\HeldActor
     *
     * @throws \InvalidArgumentException
     */
    public function read(string $guard, Guard $instance): ?HeldActor;
}
