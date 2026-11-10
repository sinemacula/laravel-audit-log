<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User;

/**
 * An Eloquent authenticatable user with an incrementing integer key, which a
 * guard can hold; tests set its key with `forceFill()` and never save it, and
 * no table exists for it, so a query for one fails the test. It can be
 * verified, as a `Verified` event's user must be.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubAuthUser extends User implements MustVerifyEmail
{
    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];
}
