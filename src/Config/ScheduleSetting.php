<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Config;

use Cron\CronExpression;
use Illuminate\Contracts\Config\Repository;

/**
 * Reads a schedule setting: its default when unset, `null` when `null` or
 * empty, and otherwise a cron expression; anything else fails closed naming the
 * key, never the value.
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
