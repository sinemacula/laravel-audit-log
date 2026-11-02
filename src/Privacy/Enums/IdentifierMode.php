<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy\Enums;

/**
 * What a record keeps of the identifier a sign-in was attempted with, under
 * `audit-log.redaction.identifiers`: a keyed hash, or nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IdentifierMode: string
{
    // A keyed, fingerprinted hash of the normalised identifier
    case HASH = 'hash';

    // No identifier at all
    case DROP = 'drop';
}
