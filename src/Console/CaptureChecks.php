<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * The capture checks of `audit-log:check`: a reader for each capture setting,
 * then for the artifacts table's name, so one run reports every malformed
 * setting, and the problem of each guard
 * `audit-log.capture.laravel.except_guards` names that `auth.guards` does not
 * configure. No event comes under such a name, so it is most likely a mistake
 * that leaves the guard it meant recorded.
 *
 * A guard is looked up by the same dotted path `AuthManager` resolves it by. A
 * malformed list, and the wildcard, name no guard to look up: the first is the
 * problem its reader reports, and the second excludes every guard. The checks
 * read configuration only, and print no setting's value beyond a guard's name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CaptureChecks
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A reader for each capture setting, in the order the settings are listed,
     * then for the artifacts table's name; each throws when its setting is
     * malformed.
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
     * The problem of each guard the except list names that is not configured in
     * `auth.guards`, in the list's order; none for the wildcard, and none when
     * the list is malformed, the problem its reader reports.
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
