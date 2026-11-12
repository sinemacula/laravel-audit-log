<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

/**
 * How an export's journal record was acknowledged before publishing; accepted
 * is durable in the outbox but not delivered until a drain runs.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Acknowledgement: string
{
    // The store holds the journal entry
    case STORED = 'stored';

    // A committed outbox row holds it, and a drain will deliver it
    case ACCEPTED = 'accepted';
}
