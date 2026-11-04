<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;

/**
 * The code naming what happened, as a record stores it: lower-case dotted
 * segments such as `invoice.approved`, each a letter followed by letters,
 * digits or underscores, in at least two segments and at most 191 bytes.
 *
 * A code is given as a string or as a string-backed enum case, whose value is
 * the code; it is never derived from a class name. A code is validated, never
 * cleaned or cut: the length is checked first, then the grammar.
 *
 * There are three ways in, and only one of them writes. `of()` takes a caller's
 * code to record, which may not begin with the `audit_log.` prefix, reserved
 * for the package's own codes. `package()` mints one of those codes from the
 * package's own activity, for its read path alone. `forReading()` takes a code
 * to look for, under any prefix, so a filter, a description, a test's assertion
 * or a lookup can name a package code without a way to record one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventCode
{
    /** @var int Longest code, in bytes: the `event` column. */
    public const int MAX_BYTES = 191;

    /** @var string Prefix of the package's own codes. */
    public const string RESERVED_PREFIX = 'audit_log.';

    /** @var string Pattern of a code: lower-case dotted segments, each a letter, then letters, digits or underscores, in at least two segments. */
    private const string PATTERN = '/\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\z/';

    /**
     * Constructor.
     *
     * @param  string  $value
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The code, as stored. */
        public string $value,
    ) {
        if (strlen($value) > self::MAX_BYTES) {
            throw new \InvalidArgumentException(sprintf('An event code must be at most %d bytes.', self::MAX_BYTES));
        }

        if (preg_match(self::PATTERN, $value) !== 1) {
            $message = 'An event code must be lower-case dotted segments, such as `invoice.approved`:'
                . ' each a letter, then letters, digits or underscores, in at least two segments.';

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * A caller's code, given as a string or as a string-backed enum case: it
     * may not begin with the prefix reserved for the package's own codes.
     *
     * @param  \BackedEnum|string  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(\BackedEnum|string $code): self
    {
        $code = new self(self::valueOf($code));

        if (str_starts_with($code->value, self::RESERVED_PREFIX)) {
            throw new \InvalidArgumentException(sprintf('The `%s` prefix is reserved for the package\'s own event codes.', self::RESERVED_PREFIX));
        }

        return $code;
    }

    /**
     * The code of one of the package's own activities, under the reserved
     * prefix: the activity's value, held to the length and the grammar, and
     * refused unless it begins with the prefix.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return self
     *
     * @throws \LogicException
     *
     * @internal
     */
    public static function package(PackageActivity $activity): self
    {
        $code = new self($activity->value);

        if (!str_starts_with($code->value, self::RESERVED_PREFIX)) {
            throw new \LogicException(sprintf('The package\'s own event codes begin with the `%s` prefix.', self::RESERVED_PREFIX));
        }

        return $code;
    }

    /**
     * A code to look for, given as a string or as a string-backed enum case:
     * held to the length and the grammar, under any prefix, the reserved one
     * included. Nothing is ever recorded under a code made this way.
     *
     * @param  \BackedEnum|string  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forReading(\BackedEnum|string $code): self
    {
        return new self(self::valueOf($code));
    }

    /**
     * The code a string or an enum case gives: the string itself, or the case's
     * value when the enum is backed by strings.
     *
     * @param  \BackedEnum|string  $code
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function valueOf(\BackedEnum|string $code): string
    {
        if (is_string($code)) {
            return $code;
        }

        if (!is_string($code->value)) {
            throw new \InvalidArgumentException('An event code enum must be backed by strings.');
        }

        return $code->value;
    }
}
