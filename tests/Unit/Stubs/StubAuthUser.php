<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User;

/**
 * An authenticatable, verifiable user with an incrementing key that a guard can
 * hold; it has no table, so a query for one fails the test.
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
