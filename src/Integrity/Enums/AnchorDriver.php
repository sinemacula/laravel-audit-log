<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * Which anchor the package keeps seals in, as
 * `audit-log.integrity.anchor.driver` names it: none, or a write-once namespace
 * on a filesystem disk.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AnchorDriver: string
{
    // No anchor: seals are kept only in the local log
    case NONE = 'null';

    // A write-once namespace on a configured filesystem disk
    case DISK = 'disk';
}
