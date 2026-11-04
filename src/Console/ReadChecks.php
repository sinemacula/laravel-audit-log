<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\AuditLog\Querying\ReadSettings;

/**
 * The read checks of `audit-log:check`: a reader for each read and export
 * setting, so one run reports every malformed setting. The checks read
 * configuration only, and print no setting's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadChecks
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A reader for each read and export setting, in the order the settings are
     * listed; each throws when its setting is malformed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    public static function readers(ConfigRepository $config): array
    {
        $settings = new ReadSettings($config);

        return [
            $settings->maxPerPage(...),
            $settings->exportChunk(...),
        ];
    }
}
