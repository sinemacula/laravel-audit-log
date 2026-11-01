<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * A string-backed enum of event codes, as an application defines its activity:
 * one ordinary code and one under the package's reserved prefix.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubActivity: string
{
    // An ordinary code an application may record
    case APPROVED = 'invoice.approved';

    // A code under the prefix reserved for the package's own codes
    case RESERVED = 'audit_log.pruned';
}
