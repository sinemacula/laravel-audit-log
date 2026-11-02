<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;

/**
 * A guard using Laravel's `GuardHelpers`, holding what it is given, whose
 * `user()` fails the test: a read that goes through it, directly or through
 * `check()`, `guest()` or `id()`, is not a read of what the guard holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubHelperGuard implements Guard
{
    use GuardHelpers;

    /**
     * Constructor.
     *
     * @param  ?object  $held
     */
    public function __construct(?object $held = null)
    {
        // A test gives the guard what no `Authenticatable` type would allow
        // @phpstan-ignore assign.propertyType
        $this->user = $held;
    }

    /**
     * Fail the test if the guard is asked to load its user.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function user(): never
    {
        throw new \LogicException('The guard\'s `user()` was called.');
    }

    /**
     * Fail the test if the guard is asked to validate credentials.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function validate(array $credentials = []): never
    {
        throw new \LogicException('The guard\'s `validate()` was called.');
    }
}
