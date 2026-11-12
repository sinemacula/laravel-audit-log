<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The reference of the user an event names, read from the user alone and never
 * from a guard; one that cannot be referred to is no one, never a failure.
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
     * The user's reference, or `null` when it is no user or cannot be referred
     * to.
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
            return null;
        }
    }

    /**
     * An authenticatable user's reference by class and identifier, or `null`
     * when the identifier is not a string or an integer.
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
