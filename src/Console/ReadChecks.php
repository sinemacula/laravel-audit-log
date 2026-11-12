<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\AuditLog\Querying\ReadSettings;

/**
 * The read checks of `audit-log:check`: a reader for each read and export
 * setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadChecks
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * A reader for each read and export setting; each throws when malformed.
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
