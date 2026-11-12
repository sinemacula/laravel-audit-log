<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

/**
 * A machine-readable code, as a reason, a purpose or a channel is kept, given
 * as a string or a string-backed enum case. It is validated, never cleaned or
 * cut, and a refusal never names its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MachineCode
{
    /** @var string Pattern of a machine-readable code of 1 to 64 characters. */
    private const string PATTERN = '/\A[a-z0-9][a-z0-9_.:-]{0,63}\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The code a string or an enum case gives: the string itself, or the case's
     * value when the enum is backed by strings. The name says what the code is,
     * and opens the message of a refusal.
     *
     * @param  \BackedEnum|string  $value
     * @param  'A channel'|'A purpose'|'A reason'  $name
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function of(\BackedEnum|string $value, string $name): string
    {
        if ($value instanceof \BackedEnum) {
            if (!is_string($value->value)) {
                throw new \InvalidArgumentException(sprintf('%s enum must be backed by strings.', $name));
            }

            $value = $value->value;
        }

        if (preg_match(self::PATTERN, $value) !== 1) {
            $message = '%s must be a machine-readable code of 1 to 64 characters:'
                . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

            throw new \InvalidArgumentException(sprintf($message, $name));
        }

        return $value;
    }
}
