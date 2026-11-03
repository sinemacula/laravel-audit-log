<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores\Enums;

/**
 * What a failed audit write does to the code that recorded it, under
 * `audit-log.failure.mode`: report the failure and let the code go on, or throw
 * a sanitised exception it must handle. A record that must not be lost asks for
 * the strict path itself, whatever the mode.
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
