<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\MachineCode;

/**
 * Reads the options the lifecycle commands share: the authority, the owner, a
 * `type:id` reference, an instant and a hold basis.
 *
 * A refusal names the option and never the value, so a command can print it as
 * it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LifecycleOptions
{
    /** @var string Pattern of a date: `Y-m-d`. */
    private const string DATE_PATTERN = '/\A\d{4}-\d{2}-\d{2}\z/';

    /** @var string Pattern of an ISO-8601 instant: a date and a time to the second, an optional fraction, and `Z` or an offset. */
    private const string INSTANT_PATTERN = '/\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})\z/';

    /** @var string Why an option that names no reference is refused, by the option. */
    private const string NOT_A_REFERENCE = 'The --%s option must name a reference as `type:id`, each part 1 to 191 characters with no control characters.';

    /** @var string Why arguments that name no owner are refused. */
    private const string NOT_AN_OWNER = 'The owner must be named by its type and id, each 1 to 191 characters with no control characters.';

    /** @var string Why an external reference that is not one is refused, by its longest length. */
    private const string NOT_A_TICKET = 'The --reference option must be 1 to %d characters, with no control characters.';

    /** @var string Why an option that names no basis is refused, by the option and the bases. */
    private const string NOT_A_BASIS = 'The --%s option must be %s.';

    /** @var string Why an option that names no instant is refused, by the option. */
    private const string NOT_AN_INSTANT = 'The --%s option must be an ISO-8601 time with `Z` or an offset, or a `Y-m-d` date.';

    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * The authority the `--by-type`, `--by-id`, `--reason` and `--reference`
     * options assert.
     *
     * @param  \Illuminate\Console\Command  $command
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     *
     * @throws \InvalidArgumentException
     */
    public static function authority(Command $command): Authority
    {
        $type   = self::required($command, 'by-type');
        $id     = self::required($command, 'by-id');
        $reason = self::required($command, 'reason');

        try {
            $operator = Reference::of($type, $id);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException('The --by-type and --by-id options must each be 1 to 191 characters, with no control characters.');
        }

        try {
            MachineCode::of($reason, 'A reason');
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException('The --reason option must be 1 to 64 lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.');
        }

        $reference = $command->option('reference');

        try {
            return new Authority($operator, $reason, is_string($reference) ? $reference : null);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException(sprintf(self::NOT_A_TICKET, Authority::MAX_EXTERNAL_REFERENCE_CHARACTERS));
        }
    }

    /**
     * The owner the command's `type` and `id` arguments name together, each
     * given, 1 to 191 characters with no control characters.
     *
     * @param  \Illuminate\Console\Command  $command
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function owner(Command $command): Reference
    {
        $type = $command->argument('type');
        $id   = $command->argument('id');

        try {
            return is_string($type) && is_string($id) ? Reference::of($type, $id) : throw new \InvalidArgumentException(self::NOT_AN_OWNER);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException(self::NOT_AN_OWNER);
        }
    }

    /**
     * The reference the option's value names as `type:id`, split on its first
     * colon, both parts given.
     *
     * @param  string  $option
     * @param  string  $value
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function reference(string $option, #[\SensitiveParameter] string $value): Reference
    {
        $parts = explode(':', $value, 2);

        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException(sprintf(self::NOT_A_REFERENCE, $option));
        }

        try {
            return Reference::of($parts[0], $parts[1]);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException(sprintf(self::NOT_A_REFERENCE, $option));
        }
    }

    /**
     * The instant the option names, in UTC: an ISO-8601 time with `Z` or an
     * offset, or a `Y-m-d` date at midnight; an impossible date is refused.
     *
     * @param  string  $option
     * @param  string  $value
     * @return \DateTimeImmutable
     *
     * @throws \InvalidArgumentException
     */
    public static function instant(string $option, string $value): \DateTimeImmutable
    {
        $utc = new \DateTimeZone('UTC');

        if (preg_match(self::DATE_PATTERN, $value) === 1) {
            $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, $utc);

            return $parsed !== false && $parsed->format('Y-m-d') === $value ? $parsed : throw new \InvalidArgumentException(sprintf(self::NOT_AN_INSTANT, $option));
        }

        if (preg_match(self::INSTANT_PATTERN, $value, $matches) !== 1) {
            throw new \InvalidArgumentException(sprintf(self::NOT_AN_INSTANT, $option));
        }

        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s' . ($matches[2] === '' ? '' : '.u') . 'P', $value, $utc);

        if ($parsed === false || $parsed->format('Y-m-d\TH:i:s') !== $matches[1]) {
            throw new \InvalidArgumentException(sprintf(self::NOT_AN_INSTANT, $option));
        }

        return $parsed->setTimezone($utc);
    }

    /**
     * The basis the option's value names: one of `HoldBasis`'s values.
     *
     * @param  string  $option
     * @param  ?string  $value
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis
     *
     * @throws \InvalidArgumentException
     */
    public static function basis(string $option, ?string $value): HoldBasis
    {
        $basis = $value === null ? null : HoldBasis::tryFrom($value);

        if ($basis !== null) {
            return $basis;
        }

        $values = array_map(static fn (HoldBasis $case): string => $case->value, HoldBasis::cases());
        $last   = array_pop($values);

        throw new \InvalidArgumentException(sprintf(self::NOT_A_BASIS, $option, implode(', ', $values) . ' or ' . $last));
    }

    /**
     * The option's value, refused when it is not given or is empty.
     *
     * @param  \Illuminate\Console\Command  $command
     * @param  'by-id'|'by-type'|'reason'  $option
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function required(Command $command, string $option): string
    {
        $value = $command->option($option);

        if (is_string($value) && $value !== '') {
            return $value;
        }

        throw new \InvalidArgumentException(sprintf('The --%s option is required.', $option));
    }
}
