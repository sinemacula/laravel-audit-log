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
    /** @var string The last id `next()` made; empty before the first. */
    private string $last = '';

    /**
     * The next id of the given time, after every id this instance made of the
     * same microsecond, so ids of one instant sort in the order they were made.
     *
     * @param  \DateTimeInterface  $time
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function next(\DateTimeInterface $time): string
    {
        $id = self::at($time);

        if (strncmp($id, $this->last, 19) === 0 && strcmp($id, $this->last) <= 0) {
            $tail = bin2hex(pack('J', unpack('J', (string) hex2bin(str_replace('-', '', substr($this->last, 19))))[1] + 1));
            $id   = substr($this->last, 0, 19) . substr($tail, 0, 4) . '-' . substr($tail, 4);
        }

        return $this->last = $id;
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
        try {
            $tail = random_bytes(8);
        } catch (RandomException) {
            throw new \UnexpectedValueException('A UUID could not be drawn.');
        }

        $tail[0] = chr(0x80 | (ord($tail[0]) & 0x3F));

        $bytes = substr(pack('J', (int) $time->format('Uv')), 2) . pack('n', 0x7000 | ((int) $time->format('u') % 1000)) . $tail;

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
