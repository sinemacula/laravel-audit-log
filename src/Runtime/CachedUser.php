<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;

/**
 * Reads the user a guard already holds, without ever calling its `user()`,
 * which loads a user through the provider and dispatches `Authenticated`.
 *
 * `hasUser()` says only whether a guard holds a user, and Laravel exposes no
 * way to read that user without `user()`, so it is read from the guard's own
 * scope. That is sound only for a guard using Laravel's `GuardHelpers`, which
 * declares the property, so the guard is recognised by that trait, never by its
 * class or package; any other guard gives nothing, and an application fills the
 * actor with a contributor or `by()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CachedUser
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The user the guard holds; `null` when it holds none or does not use
     * `GuardHelpers`.
     *
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @return ?object
     */
    public static function of(Guard $guard): ?object
    {
        if (!isset(class_uses_recursive($guard)[GuardHelpers::class]) || !$guard->hasUser()) {
            return null;
        }

        // The trait declares the property the contract does not
        // @phpstan-ignore property.notFound
        $read = \Closure::bind(static fn (Guard $bound): mixed => $bound->user, null, $guard::class);
        $user = $read($guard);

        return is_object($user) ? $user : null;
    }
}
