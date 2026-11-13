<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Random\RandomException;

/**
 * Lower-case UUID v7s of a given time, kept apart from Laravel's process-wide
 * generator, which a given time would move for the host's own ids.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UuidV7
{
    /** @var string The last id `next()` made, as its 16 bytes; empty before the first. */
    private string $last = '';

    /**
     * The next id of the given time; ids of one microsecond count up from the
     * first, so ids of one instant sort in the order they were made.
     *
     * @param  \DateTimeInterface  $time
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function next(\DateTimeInterface $time): string
    {
        $bytes = self::bytesOf($time);

        if (strncmp($bytes, $this->last, 8) === 0) {
            $bytes = substr($this->last, 0, 8) . pack('J', unpack('J', substr($this->last, 8))[1] + 1);
        }

        $this->last = $bytes;

        return self::formatted($bytes);
    }

    /**
     * A UUID v7 of the given time, its sub-millisecond microseconds in the bits
     * after the version so ids sort by time to the microsecond.
     *
     * @param  \DateTimeInterface  $time
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function at(\DateTimeInterface $time): string
    {
        return self::formatted(self::bytesOf($time));
    }

    /**
     * The 16 bytes of a fresh UUID v7 of the given time.
     *
     * @param  \DateTimeInterface  $time
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function bytesOf(\DateTimeInterface $time): string
    {
        try {
            $random = random_int(0, 0x3FFFFFFFFFFFFFFF);
        } catch (RandomException) {
            throw new \UnexpectedValueException('A UUID could not be drawn.');
        }

        $microseconds = (int) $time->format('Uu');

        return substr(pack('J', intdiv($microseconds, 1000)), 2) . pack('n', 0x7000 | $microseconds % 1000) . pack('J', PHP_INT_MIN | $random);
    }

    /**
     * The bytes as a lower-case UUID string.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function formatted(string $bytes): string
    {
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
