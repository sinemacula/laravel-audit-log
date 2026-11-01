<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions\Enums;

/**
 * Whose key an encrypted field is stored under: the record's actor or its
 * subject, so erasing that party's key leaves the field unreadable.
 *
 * The third form of owner, a property path holding a reference, is a string on
 * the field rule rather than a case of this enum.
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
