<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * Who asserts what a record says; set by the package or the importer, never by
 * a caller.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Provenance: string
{
    // Asserted by this application, not proof that the claim is true
    case CAPTURED = 'captured';

    // Asserted by another source
    case IMPORTED = 'imported';
}
