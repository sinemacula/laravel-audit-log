<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldPath;

/**
 * The path a removed branch is reported under: only what a definition already
 * declares, and `*` for everything else, so a dynamic key, which could be an
 * email address, never reaches a diagnostic.
 *
 * A property's segment is written only from the rule that decides that same
 * field, or failing that the first rule beneath it, never because the word
 * occurs in some other rule. A context has no rules, so only the first segment
 * can be written, and only when it is one of the fixed names the package itself
 * fills. A concrete key is never written: a literal appears because a rule or
 * the package wrote it, and a segment holds no dot, since a rule's path splits
 * on it.
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
     * The masked path of a property at the concrete path: at each position, the
     * segment of the rule deciding the field, or failing that of the first rule
     * beneath it, when it has one there, and `*` otherwise. A wildcard in the
     * rule stays `*`, whatever key it matched.
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
     * The masked path of a context value at the concrete path: `context.`, then
     * the first segment when it is one of the fixed names the package fills and
     * `*` when it is not, then `*` for every later segment.
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
