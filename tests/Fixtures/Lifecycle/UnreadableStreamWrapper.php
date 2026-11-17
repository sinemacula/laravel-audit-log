<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

/**
 * A stream wrapper whose every path opens but can never be read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S100")
 */
final class UnreadableStreamWrapper
{
    /** @var string The scheme the wrapper is registered under. */
    public const string SCHEME = 'unreadable';

    /** @var ?resource The context PHP gives every wrapper. */
    public mixed $context = null;

    /**
     * Register the wrapper under its scheme.
     *
     * @return void
     */
    public static function register(): void
    {
        stream_wrapper_register(self::SCHEME, self::class);
    }

    /**
     * Unregister the wrapper, if it is registered.
     *
     * @return void
     */
    public static function unregister(): void
    {
        if (!in_array(self::SCHEME, stream_get_wrappers(), true)) {
            return;
        }

        stream_wrapper_unregister(self::SCHEME);
    }

    // PHP calls a stream wrapper's methods by these names, so they cannot be
    // camel case or read as predicates
    // phpcs:disable PSR1.Methods.CamelCapsMethodName.NotCamelCaps, Squiz.NamingConventions.ValidFunctionName.ScopeNotCamelCaps, SineMacula.NamingConventions.BooleanMethodName.NotPredicate

    /**
     * Open any path.
     *
     * @param  string  $path
     * @param  string  $mode
     * @param  int  $options
     * @param  ?string  $opened
     * @return bool
     */
    public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
    {
        return true;
    }

    /**
     * Fail every read.
     *
     * @param  int  $count
     * @return false
     */
    public function stream_read(int $count): false
    {
        return false;
    }

    /**
     * Never reach the end.
     *
     * @return bool
     */
    public function stream_eof(): bool
    {
        return false;
    }

    // phpcs:enable PSR1.Methods.CamelCapsMethodName.NotCamelCaps, Squiz.NamingConventions.ValidFunctionName.ScopeNotCamelCaps, SineMacula.NamingConventions.BooleanMethodName.NotPredicate
}
