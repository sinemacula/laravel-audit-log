<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The grammar and precedence of the paths an event definition's field rules
 * name: dot-separated map keys, at most eight of them, where `*` alone matches
 * exactly one key or list index.
 *
 * A path is clean text, with no empty segment, and no segment beginning
 * `_audit`, which belongs to the package's own metadata. A key containing `.`
 * or `*` cannot be written as a literal, so it is reachable only through `*`. A
 * literal matches a key or list index whose decimal string equals it, so
 * `items.0` names the list index `0` as well as the map key `0`, which PHP
 * cannot tell apart. The most specific path wins: more segments, then, at equal
 * length, compared left to right, a literal beats `*`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FieldPath
{
    /** @var int Deepest path, in segments: the normaliser keeps eight levels. */
    public const int MAX_SEGMENTS = 8;

    /** @var string The segment that matches exactly one key or list index. */
    public const string WILDCARD = '*';

    /** @var string What separates a path's segments. */
    private const string SEPARATOR = '.';

    /** @var string Prefix of the keys that belong to the package's own metadata. */
    private const string RESERVED = '_audit';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The segments of a path as written, refused unless it is clean text of one
     * to eight non-empty segments, none beginning `_audit`, where `*` appears
     * only as a whole segment.
     *
     * @param  string  $path
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public static function parse(string $path): array
    {
        if (!TextSanitizer::isClean($path)) {
            throw new \InvalidArgumentException('A field path must be valid UTF-8 with no control characters.');
        }

        $segments = explode(self::SEPARATOR, $path);

        foreach ($segments as $segment) {
            if (!self::isSegment($segment)) {
                throw new \InvalidArgumentException('A field path must be dot-separated keys, each non-empty, with `*` alone matching one key or list index.');
            }
        }

        if (count($segments) > self::MAX_SEGMENTS) {
            throw new \InvalidArgumentException(sprintf('A field path must have at most %d segments.', self::MAX_SEGMENTS));
        }

        foreach ($segments as $segment) {
            if (str_starts_with($segment, self::RESERVED)) {
                throw new \InvalidArgumentException(sprintf('A field path\'s segments may not begin `%s`, which is reserved for the package\'s own metadata.', self::RESERVED));
            }
        }

        return $segments;
    }

    /**
     * Whether any of the segments is `*`.
     *
     * @param  list<string>  $segments
     * @return bool
     */
    public static function hasWildcard(array $segments): bool
    {
        return in_array(self::WILDCARD, $segments, true);
    }

    /**
     * Whether the pattern matches the concrete path: both have the same length
     * and, position by position, the pattern's segment is `*` or a literal
     * equal to the decimal string of the key or list index. The comparison is
     * of strings, never of numbers, so `00` matches the key `00` but not the
     * list index `0`.
     *
     * @param  list<string>  $pattern
     * @param  list<int|string>  $path
     * @return bool
     */
    public static function matches(array $pattern, array $path): bool
    {
        if (count($pattern) !== count($path)) {
            return false;
        }

        foreach ($path as $position => $key) {
            if ($pattern[$position] !== self::WILDCARD && $pattern[$position] !== (string) $key) {
                return false;
            }
        }

        return true;
    }

    /**
     * Which of two paths is more specific: positive when the first is, negative
     * when the second is, and `0` when they are equally specific. More segments
     * is more specific; at equal length, the first position where one has a
     * literal and the other `*` decides, the literal winning.
     *
     * @param  list<string>  $a
     * @param  list<string>  $b
     * @return int
     */
    public static function compare(array $a, array $b): int
    {
        if (count($a) !== count($b)) {
            return count($a) <=> count($b);
        }

        foreach ($a as $position => $segment) {
            $order = ($b[$position] === self::WILDCARD) <=> ($segment === self::WILDCARD);

            if ($order !== 0) {
                return $order;
            }
        }

        return 0;
    }

    /**
     * Whether a concrete path the first pattern matches may lie beneath one the
     * ancestor matches: the ancestor has fewer segments and, position by
     * position, the two are equal or either is `*`. A path of equal or greater
     * length is never beneath.
     *
     * @param  list<string>  $path
     * @param  list<string>  $ancestor
     * @return bool
     */
    public static function mayBeBeneath(array $path, array $ancestor): bool
    {
        if (count($ancestor) >= count($path)) {
            return false;
        }

        foreach ($ancestor as $position => $segment) {
            if (!self::mayOverlap($segment, $path[$position])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a written segment is non-empty and holds `*` only as the whole
     * segment.
     *
     * @param  string  $segment
     * @return bool
     */
    private static function isSegment(string $segment): bool
    {
        return $segment === self::WILDCARD || ($segment !== '' && !str_contains($segment, self::WILDCARD));
    }

    /**
     * Whether two segments may match the same key: they are equal, or either is
     * `*`.
     *
     * @param  string  $a
     * @param  string  $b
     * @return bool
     */
    private static function mayOverlap(string $a, string $b): bool
    {
        return $a === $b || $a === self::WILDCARD || $b === self::WILDCARD;
    }
}
