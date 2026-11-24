<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads `audit-log.require_explicit_keys`, which refuses every key the package
 * would otherwise derive from `app.key`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExplicitKeys
{
    /** @var string The setting's full key. */
    private const string SETTING = 'audit-log.require_explicit_keys';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether every key must be set explicitly; off by default.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function required(Repository $config): bool
    {
        $required = $config->get(self::SETTING, false);

        if (!is_bool($required)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be true or false.', self::SETTING));
        }

        return $required;
    }

    /**
     * Why a key left to derive from `app.key` is refused while the setting is
     * on.
     *
     * @param  string  $setting
     * @return string
     */
    public static function missing(string $setting): string
    {
        return sprintf('`%s` must be set while `%s` is on.', $setting, self::SETTING);
    }
}
