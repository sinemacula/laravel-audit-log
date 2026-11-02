<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Config;

/**
 * Reads a secret or an application key the one way every settings class reads
 * one: its own bytes, or the strict decoding of what follows a `base64:`
 * prefix, of at least 32 bytes. Anything else is `null`, and the reader refuses
 * it with a message of its own that names the setting and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecretSetting
{
    /** @var int Fewest bytes a secret may hold once decoded. */
    public const int MIN_BYTES = 32;

    /** @var string Prefix of a secret or an application key given as base64. */
    private const string BASE64_PREFIX = 'base64:';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The bytes of a secret or an application key: the strict decoding of what
     * follows a `base64:` prefix, or the string itself, or `null` when the
     * value is not a string, does not decode, or is shorter than 32 bytes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function decode(#[\SensitiveParameter] mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $bytes = str_starts_with($value, self::BASE64_PREFIX)
            ? base64_decode(substr($value, strlen(self::BASE64_PREFIX)), true)
            : $value;

        return is_string($bytes) && strlen($bytes) >= self::MIN_BYTES ? $bytes : null;
    }
}
