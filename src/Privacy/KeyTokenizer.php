<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

/**
 * Splits a key into the lower-case tokens key matching compares. Format
 * characters are removed first, so a byte order mark, a zero-width character or
 * a soft hyphen hides nothing and `pass\u{200B}word` gives `password`. The key
 * then splits at every run of characters that are not letters, marks or digits,
 * at each boundary between a letter and a digit in either direction, and at
 * each camel-case boundary, an acronym staying together: `NEW_PASSWORD` gives
 * `new`, `password`, `user[password]` gives `user`, `password`, `APIKey` gives
 * `api`, `key`, and `HTTP2Token` gives `http`, `2`, `token`.
 *
 * A token is never matched as a substring of anything, so words joined with no
 * boundary stay one token. A key that is not valid UTF-8 has no tokens, and the
 * work is linear in the key's length. So is the memory, at many times that
 * length, which is why the redactor never gives it a key past
 * `KeyCeiling::MAX_BYTES`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyTokenizer
{
    /** @var string The format characters a key is read without: the byte order mark, the zero-width characters and the soft hyphen among them. */
    private const string FORMAT_CHARACTERS = '/\p{Cf}+/u';

    /** @var string Where a key turns to its next word with nothing between them: from a letter to a digit, from a digit to a letter, after a lower-case letter before a capital, or within an acronym before its last capital. */
    private const string WORD_BOUNDARY = '/(?<=[\p{L}\p{M}])(?=\p{N})|(?<=\p{N})(?=\p{L})|(?<=\p{Ll})(?=\p{Lu})|(?<=\p{Lu})(?=\p{Lu}\p{Ll})/u';

    /** @var string The characters that separate tokens: anything but a letter, a mark or a digit. */
    private const string SEPARATORS = '/[^\p{L}\p{M}\p{N}]+/u';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key's tokens, in order and lower-cased, or none when the key is
     * empty, holds only separators, or is not valid UTF-8.
     *
     * @param  string  $key
     * @return list<string>
     */
    public static function tokens(#[\SensitiveParameter] string $key): array
    {
        $spaced = preg_replace([self::FORMAT_CHARACTERS, self::WORD_BOUNDARY], ['', ' '], $key);
        $parts  = $spaced === null ? false : preg_split(self::SEPARATORS, $spaced, -1, PREG_SPLIT_NO_EMPTY);

        return $parts === false ? [] : array_map(static fn (string $part): string => mb_strtolower($part, 'UTF-8'), $parts);
    }
}
