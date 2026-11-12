<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldPath;

/**
 * The path a removed branch is reported under: only what a definition or the
 * package declares, and `*` elsewhere, so a dynamic key never reaches a
 * diagnostic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PathMasker
{
    /** @var list<string> The context keys the package itself fills, the only ones written literally. */
    public const array CONTEXT_NAMES = ['route', 'method', 'command', 'job', 'channel'];

    /** @var string What every context path begins with. */
    private const string CONTEXT_PREFIX = 'context.';

    /** @var string What separates a masked path's segments. */
    private const string SEPARATOR = '.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The masked path of a property: at each position the segment of the rule
     * deciding the field, or the first rule beneath it, and `*` otherwise.
     *
     * @param  list<int|string>  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return string
     */
    public static function property(#[\SensitiveParameter] array $path, EventDefinition $definition): string
    {
        $segments = ($definition->ruleFor($path) ?? $definition->ruleBeneath($path))->segments ?? [];

        $masked = array_map(
            static fn (int $position): string => $segments[$position] ?? FieldPath::WILDCARD,
            array_keys($path),
        );

        return implode(self::SEPARATOR, $masked);
    }

    /**
     * The masked path of a context value: `context.`, then the first segment
     * only when the package fills it, and `*` for the rest.
     *
     * @param  list<int|string>  $path
     * @return string
     */
    public static function context(#[\SensitiveParameter] array $path): string
    {
        $masked = array_fill(0, count($path), FieldPath::WILDCARD);
        $first  = $path[0] ?? '';

        if (in_array($first, self::CONTEXT_NAMES, true)) {
            $masked[0] = $first;
        }

        return self::CONTEXT_PREFIX . implode(self::SEPARATOR, $masked);
    }
}
