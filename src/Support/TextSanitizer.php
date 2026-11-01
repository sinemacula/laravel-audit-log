<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

/**
 * How every string is made safe to store at capture: invalid UTF-8 is repaired
 * byte by byte to U+FFFD, the whitespace controls (tab, line feed, vertical
 * tab, form feed, carriage return) each become one space, every other control
 * character and the bidirectional embeddings, overrides and isolates are
 * removed, and a cap cuts with `mb_strcut()`, so no character is ever split.
 *
 * Everything else is kept as given: combining marks, zero-width characters, the
 * byte order mark, the directional marks, emoji and their joined sequences.
 * There is no Unicode normalisation, and nothing depends on a runtime setting
 * such as `mb_substitute_character()`, so every runtime and every engine stores
 * the same text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TextSanitizer
{
    /** @var string Each byte that does not begin a well-formed UTF-8 sequence, matched byte by byte with every well-formed sequence skipped. */
    private const string MALFORMED_BYTE = '/(?:[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]'
        . '|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})(*SKIP)(*FAIL)|./s';

    /** @var string What a malformed byte becomes: U+FFFD, the replacement character. */
    private const string REPLACEMENT = "\u{FFFD}";

    /** @var array<string, string> The whitespace controls, U+0009 to U+000D, each of which becomes one space. */
    private const array WHITESPACE_CONTROLS = ["\t" => ' ', "\n" => ' ', "\v" => ' ', "\f" => ' ', "\r" => ' '];

    /** @var string Every other control character, and the bidirectional embeddings, overrides and isolates, all of which are removed. */
    private const string STRIPPED = '/[\p{Cc}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The text made safe to store: repaired, its whitespace controls made
     * spaces, its other controls and bidirectional controls removed, and, with
     * a cap, cut to at most that many bytes.
     *
     * @param  string  $text
     * @param  ?int  $maxBytes
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function clean(string $text, ?int $maxBytes = null): string
    {
        if (!mb_check_encoding($text, 'UTF-8')) {
            $text = preg_replace(self::MALFORMED_BYTE, self::REPLACEMENT, $text) ?? '';
        }

        $text = strtr($text, self::WHITESPACE_CONTROLS);
        $text = preg_replace(self::STRIPPED, '', $text) ?? '';

        return $maxBytes === null ? $text : self::cut($text, $maxBytes);
    }

    /**
     * The text cut to at most the cap in bytes without splitting a character;
     * text within the cap is returned whole.
     *
     * @param  string  $text
     * @param  int  $maxBytes
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function cut(string $text, int $maxBytes): string
    {
        if ($maxBytes < 1) {
            throw new \InvalidArgumentException('A cap must be at least one byte.');
        }

        return mb_strcut($text, 0, $maxBytes, 'UTF-8');
    }

    /**
     * Whether the text is already clean: cleaning it would change nothing.
     * Identifiers are checked with this and refused, never cleaned, when it
     * does not hold.
     *
     * @param  string  $text
     * @return bool
     */
    public static function isClean(string $text): bool
    {
        return self::clean($text) === $text;
    }
}
