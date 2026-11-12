<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * The capture checks of `audit-log:check`: every capture setting reads, and
 * every guard the except list names is configured in `auth.guards`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CaptureChecks
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * A reader for each capture setting, then the artifacts table's name; each
     * throws when its setting is malformed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    public static function readers(ConfigRepository $config): array
    {
        $capture = new CaptureSettings($config);

        return [
            $capture->exceptGuards(...),
            $capture->identifierKey(...),
            $capture->isGateEnabled(...),
            $capture->onlyAbilities(...),
            $capture->exceptAbilities(...),
            $capture->reasonCodes(...),
            $capture->bulkMaxMembers(...),
            $capture->bulkMaxBytes(...),
            EntrySettings::artifactsTable(...),
        ];
    }

    /**
     * The problem of each excepted guard not configured in `auth.guards`; none
     * for the wildcard or a malformed list, which its reader reports.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     */
    public static function guardProblems(ConfigRepository $config): array
    {
        try {
            $guards = (new CaptureSettings($config))->exceptGuards();
        } catch (\InvalidArgumentException) {
            return [];
        }

        if ($guards === [CaptureSettings::ALL_GUARDS]) {
            return [];
        }

        $problems = [];

        foreach ($guards as $guard) {

            if (is_array($config->get("auth.guards.{$guard}"))) {
                continue;
            }

            $problems[] = sprintf('The guard [%s] that `audit-log.capture.laravel.except_guards` names is not configured in `auth.guards`.', $guard);
        }

        return $problems;
    }
}
