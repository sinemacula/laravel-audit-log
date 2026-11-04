<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

/**
 * How the record that journals an export was acknowledged before the export was
 * published: stored by the audit store, or accepted as a committed outbox row
 * that a drain will deliver. Accepted is not delivered: the row is durable, and
 * the store holds it only once a drain has run.
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
