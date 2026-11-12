<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The first eight arguments of a Gate check as a denial keeps them: a model's
 * reference, an existing class name, or a marker, so no argument's value
 * reaches the record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GateArguments
{
    /** @var int Most arguments kept; the count says how many there were. */
    public const int MAX_ARGUMENTS = 8;

    /** @var string What stands for an argument that is neither a model nor a class name. */
    public const string MARKER = '[ARGUMENT]';

    /** @var int Longest class name kept, in characters: a reference's type. */
    private const int CLASS_MAX_CHARACTERS = 191;

    /** @var string Pattern of a class name without a leading backslash. */
    private const string CLASS_PATTERN = '/\A[A-Za-z_][A-Za-z0-9_]*(?:\\\[A-Za-z_][A-Za-z0-9_]*)*\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The first eight arguments, in order, as kept.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $arguments
     * @return list<array{type: string, id: string}|string>
     */
    public static function of(#[\SensitiveParameter] array $arguments): array
    {
        $kept = [];

        foreach (array_slice(array_values($arguments), 0, self::MAX_ARGUMENTS) as $argument) {
            $kept[] = self::argument($argument);
        }

        return $kept;
    }

    /**
     * How many arguments there were, every one counted, kept or not.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $arguments
     * @return int
     */
    public static function count(#[\SensitiveParameter] array $arguments): int
    {
        return count($arguments);
    }

    /**
     * The argument as kept: a model's reference, a class name, or the marker.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $argument
     * @return array{type: string, id: string}|string
     */
    private static function argument(#[\SensitiveParameter] mixed $argument): array|string
    {
        if ($argument instanceof Model) {
            try {
                return Reference::to($argument)->toArray();
            } catch (\InvalidArgumentException) {
                return self::MARKER;
            }
        }

        return is_string($argument) ? self::className($argument) : self::MARKER;
    }

    /**
     * The string as an existing class name without its leading backslash, or
     * the marker.
     *
     * @param  string  $argument
     * @return string
     */
    private static function className(#[\SensitiveParameter] string $argument): string
    {
        $class = str_starts_with($argument, '\\') ? substr($argument, 1) : $argument;

        if (strlen($class) > self::CLASS_MAX_CHARACTERS || preg_match(self::CLASS_PATTERN, $class) !== 1 || !class_exists($class)) {
            return self::MARKER;
        }

        return $class;
    }
}
