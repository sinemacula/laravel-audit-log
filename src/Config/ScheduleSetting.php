<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Config;

use Cron\CronExpression;
use Illuminate\Contracts\Config\Repository;

/**
 * Reads a schedule setting the one way every settings class reads one: its
 * default when it is not set, `null` when it is `null` or empty, so nothing is
 * scheduled, and otherwise a cron expression. Anything else fails closed with
 * an `InvalidArgumentException` naming the key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScheduleSetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The schedule under the key, or the default when it is not set, as a cron
     * expression, or `null` for none.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  ?string  $default
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function read(Repository $config, string $key, ?string $default): ?string
    {
        $expression = $config->get($key, $default);

        if ($expression === null || $expression === '') {
            return null;
        }

        if (!is_string($expression) || !CronExpression::isValidExpression($expression)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be a cron expression, or null or empty to schedule nothing.', $key));
        }

        return $expression;
    }
}
