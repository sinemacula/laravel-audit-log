<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The plaintext a field is sealed as: the canonical JSON of its value, for
 * every type, so the string `"true"` and the boolean `true` are sealed apart
 * and read back as what they were.
 *
 * The limit is measured on the encoding, never on the value: at most 1024
 * bytes. A string over it is cut to the longest prefix, on a character
 * boundary, whose encoding fits, so an escaped character costs what it costs
 * once encoded. Any other value over it is `null`, and the caller drops it
 * without asking an encrypter. A value with no canonical encoding, such as a
 * float or a string that is not UTF-8, is refused as the encoder refuses it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TypedPlaintext
{
    /** @var int Longest plaintext, in bytes, after encoding. */
    public const int MAX_BYTES = 1024;

    /** @var int Most bytes the encoding of one byte of a string can take: a control character escaped as `\u00XX`. */
    private const int MAX_ESCAPED_BYTES = 6;

    /** @var int Bytes of the quotes around an encoded string. */
    private const int QUOTE_BYTES = 2;

    /** @var int Greatest depth of a decoded plaintext. */
    private const int MAX_DEPTH = 64;

    /** @var string Why a plaintext is refused; it names nothing of the text. */
    private const string MALFORMED = 'A typed plaintext must be the JSON of a value that is not a float.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The canonical encoding of the value, within the limit: a string cut to
     * the longest prefix whose encoding fits, and `null` for any other value
     * whose encoding does not.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    public static function encode(#[\SensitiveParameter] mixed $value): ?string
    {
        $encoded = CanonicalEncoder::encode($value);

        if (strlen($encoded) <= self::MAX_BYTES) {
            return $encoded;
        }

        return is_string($value) ? self::cut($value) : null;
    }

    /**
     * The value a plaintext encodes: a map as an associative array, a list as a
     * list, and a scalar or `null` as itself. Text that is not JSON, nests
     * deeper than 64 levels, or encodes a float is refused, naming nothing of
     * the text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $plaintext
     * @return array<array-key, mixed>|bool|int|string|null
     *
     * @throws \UnexpectedValueException
     */
    public static function decode(#[\SensitiveParameter] string $plaintext): array|bool|int|string|null
    {
        try {
            $decoded = json_decode($plaintext, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \UnexpectedValueException(self::MALFORMED);
        }

        return match (true) {
            is_array($decoded), is_bool($decoded), is_int($decoded), is_string($decoded), $decoded === null => $decoded,
            default                                                                                         => throw new \UnexpectedValueException(self::MALFORMED),
        };
    }

    /**
     * The encoding of the longest prefix of the string whose encoding fits.
     * Each byte cut takes at least one byte and at most six off the encoding,
     * so cutting a sixth of the excess, rounded up, never cuts below the
     * longest prefix that fits, and every pass cuts at least one byte.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function cut(#[\SensitiveParameter] string $value): string
    {
        $prefix  = TextSanitizer::cut($value, self::MAX_BYTES - self::QUOTE_BYTES);
        $encoded = CanonicalEncoder::encode($prefix);

        while (strlen($encoded) > self::MAX_BYTES) {
            $excess  = strlen($encoded) - self::MAX_BYTES;
            $prefix  = mb_strcut($prefix, 0, strlen($prefix) - intdiv($excess + self::MAX_ESCAPED_BYTES - 1, self::MAX_ESCAPED_BYTES), 'UTF-8');
            $encoded = CanonicalEncoder::encode($prefix);
        }

        return $encoded;
    }
}
