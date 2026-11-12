<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The bitmap of the members a prune deleted: bit `i % 8` of byte `intdiv(i, 8)`
 * for the `i`-th member by entry id bytewise, stored as unpadded base64url with
 * exactly one accepted form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PruneBitmap
{
    /** @var string Every character a stored bitmap may hold. */
    private const string ALPHABET = '/\A[A-Za-z0-9_-]*\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The stored form of the bitmap of the positions given over the number of
     * members: at least one position, each once, each from 0 to one less than
     * the members.
     *
     * @param  list<int>  $positions
     * @param  int  $memberCount
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function encode(array $positions, int $memberCount): string
    {
        self::checkMembers($memberCount);

        if ($positions === []) {
            throw new \InvalidArgumentException('A prune bitmap must set at least one member.');
        }

        $bytes = str_repeat("\0", self::lengthOf($memberCount));

        foreach ($positions as $position) {
            if ($position < 0 || $position >= $memberCount) {
                throw new \InvalidArgumentException(sprintf('A prune bitmap\'s positions must be from 0 to %d.', $memberCount - 1));
            }

            if (self::isSet($bytes, $position)) {
                throw new \InvalidArgumentException('A prune bitmap must set each position once.');
            }

            $index         = intdiv($position, 8);
            $bytes[$index] = chr(ord($bytes[$index]) | (1 << ($position % 8)));
        }

        return self::text($bytes);
    }

    /**
     * The bytes of the stored bitmap over the number of members, refused unless
     * it is the one canonical text of exactly that many members' bytes with
     * every padding bit zero.
     *
     * @param  string  $encoded
     * @param  int  $memberCount
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function decode(string $encoded, int $memberCount): string
    {
        self::checkMembers($memberCount);

        if (str_contains($encoded, '=')) {
            throw new \InvalidArgumentException('A prune bitmap must not be padded.');
        }

        if (preg_match(self::ALPHABET, $encoded) !== 1) {
            throw new \InvalidArgumentException('A prune bitmap must be base64url: letters, digits, hyphens and underscores.');
        }

        // With the alphabet checked, strict decoding fails only on a bad length
        $bytes = base64_decode(strtr($encoded, '-_', '+/'), true);

        if ($bytes === false) {
            throw new \InvalidArgumentException('A prune bitmap must have a length base64 can encode.');
        }

        if (self::text($bytes) !== $encoded) {
            throw new \InvalidArgumentException('A prune bitmap must be the canonical encoding of its bytes.');
        }

        if (strlen($bytes) !== self::lengthOf($memberCount)) {
            throw new \InvalidArgumentException(sprintf('A prune bitmap of %d members must be %d bytes.', $memberCount, self::lengthOf($memberCount)));
        }

        $used = $memberCount % 8;

        if ($used !== 0 && (ord($bytes[-1]) >> $used) !== 0) {
            throw new \InvalidArgumentException('A prune bitmap must not set a bit past its last member.');
        }

        return $bytes;
    }

    /**
     * The positions the bytes set within the number of members, ascending.
     *
     * @param  string  $bytes
     * @param  int  $memberCount
     * @return list<int>
     */
    public static function positions(string $bytes, int $memberCount): array
    {
        $positions = [];

        for ($position = 0; $position < $memberCount; $position++) {
            if (!self::isSet($bytes, $position)) {
                continue;
            }

            $positions[] = $position;
        }

        return $positions;
    }

    /**
     * How many bits the bytes set, padding bits included.
     *
     * @param  string  $bytes
     * @return int
     */
    public static function count(string $bytes): int
    {
        $count = 0;

        foreach (count_chars($bytes, 1) as $byte => $times) {
            $count += $times * substr_count(decbin($byte), '1');
        }

        return $count;
    }

    /**
     * Whether the bytes set the position: `false` for a position they do not
     * reach.
     *
     * @param  string  $bytes
     * @param  int  $position
     * @return bool
     */
    public static function isSet(string $bytes, int $position): bool
    {
        if ($position < 0 || intdiv($position, 8) >= strlen($bytes)) {
            return false;
        }

        return (ord($bytes[intdiv($position, 8)]) >> ($position % 8) & 1) === 1;
    }

    /**
     * How many bytes the bitmap of the number of members holds.
     *
     * @param  int  $memberCount
     * @return int
     */
    private static function lengthOf(int $memberCount): int
    {
        return intdiv($memberCount + 7, 8);
    }

    /**
     * The strict base64url text of the bytes, with no padding.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function text(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Refuse a bitmap of no member.
     *
     * @param  int  $memberCount
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkMembers(int $memberCount): void
    {
        if ($memberCount < 1) {
            throw new \InvalidArgumentException('A prune bitmap must be over at least one member.');
        }
    }
}
