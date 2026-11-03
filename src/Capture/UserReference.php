<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The reference of the user an event carries, read from the user alone: a model
 * by its reference, any other authenticatable user by its class and its
 * identifier, and anything else as no one.
 *
 * A user that cannot be referred to, such as a model with no key or an
 * identifier a reference refuses, is no one rather than a failure, so the
 * activity is still recorded with no actor. No guard is ever asked: the user is
 * the one the event names, never the one a guard holds now.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UserReference
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The reference of the user, or `null` when it is no user or cannot be
     * referred to: a model through its reference, and any other authenticatable
     * user by its class and its identifier when that is a string or an integer
     * the reference accepts.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $user
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    public static function of(#[\SensitiveParameter] mixed $user): ?Reference
    {
        try {
            return match (true) {
                $user instanceof Model           => Reference::to($user),
                $user instanceof Authenticatable => self::byIdentifier($user),
                default                          => null,
            };
        } catch (\InvalidArgumentException) {
            // A user the reference refuses is no one, never a failure
            return null;
        }
    }

    /**
     * The reference of an authenticatable user by its class and identifier, or
     * `null` when the identifier is neither a string nor an integer.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function byIdentifier(#[\SensitiveParameter] Authenticatable $user): ?Reference
    {
        $id = $user->getAuthIdentifier();

        return is_int($id) || is_string($id) ? Reference::of($user::class, $id) : null;
    }
}
