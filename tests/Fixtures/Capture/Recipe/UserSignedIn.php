<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Recipe;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The event another package dispatches when its guard signs a user in, which
 * the extending guide's recipe names `Acme\Identity\Events\UserSignedIn`: the
 * user who signed in and the id of the attempt the sign-in completed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserSignedIn
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $user
     * @param  string  $attemptId
     */
    public function __construct(

        /** The user who signed in. */
        public Authenticatable&Model $user,

        /** The id of the sign-in attempt the sign-in completed. */
        public string $attemptId,
    ) {}
}
