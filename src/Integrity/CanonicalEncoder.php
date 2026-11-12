<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The canonical encoding of integrity version 1. A map, or an object of exactly
 * `stdClass`, is written by hand with its keys sorted bytewise so it never
 * becomes a list; a float, any other object, a resource and invalid UTF-8 are
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CanonicalEncoder
{
    /** @var int The flags of every string; fixed for version 1. */
    public const int JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The canonical encoding of the value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function encode(mixed $value): string
    {
        if (is_array($value)) {
            return array_is_list($value) ? self::list($value) : self::map($value);
        }

        if (is_object($value) && $value::class === \stdClass::class) {
            return self::map(get_object_vars($value));
        }

        return self::scalar($value);
    }

    /**
     * The list's members encoded in their order, in brackets.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<mixed>  $members
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function list(array $members): string
    {
        return '[' . implode(',', array_map(self::encode(...), $members)) . ']';
    }

    /**
     * The map's members in braces, each key cast to a string and encoded as a
     * string, then its value, in the bytewise order of the keys.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $members
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function map(array $members): string
    {
        $keys = array_keys($members);

        usort($keys, static fn (int|string $left, int|string $right): int => strcmp((string) $left, (string) $right));

        $encoded = array_map(static fn (int|string $key): string => self::string((string) $key) . ':' . self::encode($members[$key]), $keys);

        return '{' . implode(',', $encoded) . '}';
    }

    /**
     * The string as `json_encode()` writes it with the fixed flags.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function string(string $value): string
    {
        try {
            return json_encode($value, self::JSON_FLAGS);
        } catch (\JsonException $exception) {
            throw new \UnexpectedValueException('A string that is not valid UTF-8 cannot be encoded canonically.', 0, $exception);
        }
    }

    /**
     * The scalar as JSON writes it; a float or a value of any other type is
     * refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function scalar(mixed $value): string
    {
        return match (true) {
            $value === null   => 'null',
            is_bool($value)   => $value ? 'true' : 'false',
            is_int($value)    => (string) $value,
            is_string($value) => self::string($value),
            is_float($value)  => throw new \UnexpectedValueException('A float cannot be encoded canonically; the package stores decimals as strings.'),
            default           => throw new \UnexpectedValueException(sprintf('A value of type %s cannot be encoded canonically.', get_debug_type($value))),
        };
    }
}
