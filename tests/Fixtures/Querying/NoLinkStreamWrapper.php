<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying;

/**
 * A stream wrapper over the local filesystem that, like a FAT volume or an
 * object-store mount, cannot hold a hard link; it wraps only what an export's
 * target checks use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S100")
 */
final class NoLinkStreamWrapper
{
    /** @var string The scheme the wrapper is registered under. */
    public const string SCHEME = 'nolink';

    /** @var ?resource The context PHP gives every wrapper. */
    public mixed $context = null;

    /** @var ?resource The local file a stream opened. */
    private mixed $handle = null;

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

    /**
     * The wrapped path of a local one.
     *
     * @param  string  $path
     * @return string
     */
    public static function wrap(string $path): string
    {
        return self::SCHEME . '://' . $path;
    }

    // PHP calls a stream wrapper's methods by these names, so they cannot be
    // camel case or read as predicates
    // phpcs:disable PSR1.Methods.CamelCapsMethodName.NotCamelCaps, Squiz.NamingConventions.ValidFunctionName.ScopeNotCamelCaps, SineMacula.NamingConventions.BooleanMethodName.NotPredicate

    /**
     * Open the local file in the mode.
     *
     * @param  string  $path
     * @param  string  $mode
     * @param  int  $options
     * @param  ?string  $opened
     * @return bool
     */
    public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
    {
        $handle = @fopen(self::local($path), $mode);

        if ($handle === false) {
            return false;
        }

        $this->handle = $handle;

        return true;
    }

    /**
     * Write the data to the local file.
     *
     * @param  string  $data
     * @return int
     */
    public function stream_write(string $data): int
    {
        return is_resource($this->handle) ? (int) fwrite($this->handle, $data) : 0;
    }

    /**
     * Flush the local file.
     *
     * @return bool
     */
    public function stream_flush(): bool
    {
        return is_resource($this->handle) && fflush($this->handle);
    }

    /**
     * Close the local file.
     *
     * @return void
     */
    public function stream_close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        $this->handle = null;
    }

    /**
     * The local path's status, a link's own when PHP asks for it, or `false`
     * when nothing is there.
     *
     * @param  string  $path
     * @param  int  $flags
     * @return array<int|string, int>|false
     */
    public function url_stat(string $path, int $flags): array|false
    {
        $local = self::local($path);

        if (!file_exists($local) && !is_link($local)) {
            return false;
        }

        return ($flags & STREAM_URL_STAT_LINK) !== 0 ? lstat($local) : stat($local);
    }

    /**
     * Remove the local file.
     *
     * @param  string  $path
     * @return bool
     */
    public function unlink(string $path): bool
    {
        return @unlink(self::local($path));
    }

    // phpcs:enable PSR1.Methods.CamelCapsMethodName.NotCamelCaps, Squiz.NamingConventions.ValidFunctionName.ScopeNotCamelCaps, SineMacula.NamingConventions.BooleanMethodName.NotPredicate

    /**
     * The local path a wrapped one names.
     *
     * @param  string  $path
     * @return string
     */
    private static function local(string $path): string
    {
        return substr($path, strlen(self::SCHEME . '://'));
    }
}
