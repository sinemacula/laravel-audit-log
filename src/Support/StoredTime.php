<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Carbon\CarbonImmutable;

/**
 * The one conversion between the package's form of an instant, ISO-8601 in UTC
 * with six fractional digits and `Z`, and the form the database stores, `Y-m-d
 * H:i:s.u` in UTC.
 *
 * Every parse is in UTC with every field reset first, so the default time zone
 * never applies, and a value is accepted only when formatting the parsed
 * instant gives it back, so a date that does not exist, such as `2026-02-30`,
 * or an hour of `24` is refused rather than rolled over. A stored time may
 * carry fewer than six fractional digits, or none, because PostgreSQL drops
 * trailing fractional zeros; it reads back right-padded to six.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StoredTime
{
    /** @var string The package's form of an instant: ISO-8601 UTC with microseconds. */
    private const string INSTANT_FORMAT = 'Y-m-d\TH:i:s.u\Z';

    /** @var string The form the database stores an instant in, in UTC. */
    private const string STORAGE_FORMAT = 'Y-m-d H:i:s.u';

    /** @var string A stored time as an engine returns it: up to six fractional digits, or none. */
    private const string STORED_PATTERN = '/\A(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?\z/';

    /** @var string Why an instant is refused. */
    private const string INSTANT_MESSAGE = 'A time must be ISO-8601 UTC with microseconds, such as 2026-11-01T12:00:00.123456Z.';

    /** @var string Why a stored time is refused. */
    private const string STORED_MESSAGE = 'A stored time must be `Y-m-d H:i:s` with up to six fractional digits.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the value is an instant in the package's form: ISO-8601 in UTC,
     * with six fractional digits and `Z`, on a date and at a time that exist.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isInstant(string $value): bool
    {
        return self::parse(self::INSTANT_FORMAT, $value) !== null;
    }

    /**
     * The instant in the package's form, converted to UTC whatever its own time
     * zone.
     *
     * @param  \DateTimeInterface  $instant
     * @return string
     */
    public static function format(\DateTimeInterface $instant): string
    {
        return \DateTimeImmutable::createFromInterface($instant)
            ->setTimezone(new \DateTimeZone('UTC'))
            ->format(self::INSTANT_FORMAT);
    }

    /**
     * The instant, given in the package's form, as the database stores it.
     *
     * @param  string  $instant
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function toStorage(string $instant): string
    {
        $parsed = self::parse(self::INSTANT_FORMAT, $instant) ?? throw new \InvalidArgumentException(self::INSTANT_MESSAGE);

        return $parsed->format(self::STORAGE_FORMAT);
    }

    /**
     * The stored time in the package's form, its fractional digits right-padded
     * to six.
     *
     * @param  string  $stored
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function fromStorage(string $stored): string
    {
        return self::read($stored)->format(self::INSTANT_FORMAT);
    }

    /**
     * The stored time as an instant in UTC, its microseconds kept.
     *
     * @param  string  $stored
     * @return \Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    public static function instant(string $stored): CarbonImmutable
    {
        return CarbonImmutable::instance(self::read($stored));
    }

    /**
     * The stored time parsed in UTC, refused unless it has the stored form and
     * names a date and a time that exist. A value without the stored form is
     * parsed as empty, which never parses.
     *
     * @param  string  $stored
     * @return \DateTimeImmutable
     *
     * @throws \UnexpectedValueException
     */
    private static function read(string $stored): \DateTimeImmutable
    {
        $padded = preg_match(self::STORED_PATTERN, $stored, $matches) === 1
            ? $matches[1] . '.' . str_pad($matches[2] ?? '', 6, '0')
            : '';

        return self::parse(self::STORAGE_FORMAT, $padded) ?? throw new \UnexpectedValueException(self::STORED_MESSAGE);
    }

    /**
     * The value parsed in UTC under the format, with every field reset first,
     * or `null` unless formatting the result gives the value back.
     *
     * @param  string  $format
     * @param  string  $value
     * @return ?\DateTimeImmutable
     */
    private static function parse(string $format, string $value): ?\DateTimeImmutable
    {
        $parsed = \DateTimeImmutable::createFromFormat('!' . $format, $value, new \DateTimeZone('UTC'));

        return $parsed !== false && $parsed->format($format) === $value ? $parsed : null;
    }
}
