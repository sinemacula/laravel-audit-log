<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores\Enums;

/**
 * What a failed audit write does to the recording code, under
 * `audit-log.failure.mode`; a record that must not be lost is always strict.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureMode: string
{
    // Spill and report the failure, then let the recording code go on
    case REPORT = 'report';

    // Spill the failure, then throw it to the recording code
    case THROW = 'throw';
}
