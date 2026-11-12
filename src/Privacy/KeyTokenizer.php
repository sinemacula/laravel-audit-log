<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

/**
 * Splits a key into the lower-case tokens key matching compares; memory runs to
 * many times the key's length, so no key past `KeyCeiling::MAX_BYTES` reaches
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyTokenizer
{
    /** @var string Format characters a key is read without, so a zero-width character or soft hyphen hides nothing. */
    private const string FORMAT_CHARACTERS = '/\p{Cf}+/u';

    /** @var string Where a key turns to its next word with nothing between them, an acronym staying together. */
    private const string WORD_BOUNDARY = '/(?<=[\p{L}\p{M}])(?=\p{N})|(?<=\p{N})(?=\p{L})|(?<=\p{Ll})(?=\p{Lu})|(?<=\p{Lu})(?=\p{Lu}\p{Ll})/u';

    /** @var string The characters that separate tokens: anything but a letter, a mark or a digit. */
    private const string SEPARATORS = '/[^\p{L}\p{M}\p{N}]+/u';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key's tokens, in order and lower-cased, or none when it is empty,
     * only separators or invalid UTF-8.
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
