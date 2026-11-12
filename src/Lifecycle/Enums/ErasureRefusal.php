<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Why an erasure was refused, writing nothing; the refusal's
 * `audit_log.subject_erased` record carries it as its reason.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ErasureRefusal: string
{
    // A key of the owner is blocked and a partial erasure was not asked for
    case BLOCKED = 'blocked';

    // The outbox holds older records and the erasure did not accept them
    case PENDING_DELIVERY = 'pending_delivery';

    // The bound field encrypter is not one that keeps the package's key store
    case UNSUPPORTED_ENCRYPTER = 'unsupported_encrypter';

    // A key of the owner fails its signature or names a signing key the ring
    // does not hold
    case KEY_UNVERIFIABLE = 'key_unverifiable';

    // The owner holds more keys than one erasure destroys
    case TOO_MANY_KEYS = 'too_many_keys';
}
