<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions\Enums;

/**
 * Whose key an encrypted field is stored under, so erasing that key leaves the
 * field unreadable; a property path holding a reference is given as a string
 * instead.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyOwner: string
{
    // The record's actor owns the key
    case ACTOR = 'actor';

    // The record's subject owns the key
    case SUBJECT = 'subject';
}
