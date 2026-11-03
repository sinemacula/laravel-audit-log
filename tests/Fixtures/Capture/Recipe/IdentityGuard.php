<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Recipe;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The guard of another package, as the extending guide's recipe has it: a
 * session guard configured as `identity`, whose sign-in fires Laravel's own
 * `Login`, as any session guard's does, and then the package's own
 * `UserSignedIn`, naming the attempt it completed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityGuard extends SessionGuard
{
    /** @var string The name the guard is configured under. */
    public const string NAME = 'identity';

    /**
     * Sign the user in to complete the attempt: Laravel's `Login`, then the
     * package's own event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $user
     * @param  string  $attemptId
     * @return void
     */
    public function signIn(Authenticatable&Model $user, string $attemptId): void
    {
        $this->login($user);

        $this->events?->dispatch(new UserSignedIn($user, $attemptId));
    }
}
