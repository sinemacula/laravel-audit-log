<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy\Enums;

/**
 * How a record keeps the client's IP address, under `audit-log.redaction.ip`:
 * in full, truncated, as a keyed hash, not at all, or encrypted under the
 * actor's key. An address that is not valid is stored in no mode.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IpMode: string
{
    // The whole address, in its canonical form
    case FULL = 'full';

    // The address's network: a /24 for IPv4, a /48 for IPv6
    case TRUNCATE = 'truncate';

    // A keyed, fingerprinted hash of the address
    case HASH = 'hash';

    // No address at all
    case DROP = 'drop';

    // An envelope under the actor's key, or nothing with no actor or no key
    case ENCRYPT = 'encrypt';
}
