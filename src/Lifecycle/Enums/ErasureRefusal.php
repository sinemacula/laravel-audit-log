<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Why an erasure was refused, writing nothing: a key of the owner is blocked by
 * a hold, by preservation or by an entry that does not authenticate; the outbox
 * holds records older than the erasure; the bound field encrypter keeps its
 * keys where the package cannot see them; a key of the owner does not
 * authenticate; or the owner holds more keys than one erasure destroys. The
 * refusal's `audit_log.subject_erased` record carries it as its reason.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ErasureRefusal: string
{
    // A key of the owner is blocked, and the erasure was not asked to go ahead
    // in part
    case BLOCKED = 'blocked';

    // The outbox holds records created before the erasure started, and the
    // erasure was not asked to accept them
    case PENDING_DELIVERY = 'pending_delivery';

    // The bound field encrypter is not one that keeps the package's key store
    case UNSUPPORTED_ENCRYPTER = 'unsupported_encrypter';

    // A key of the owner fails its signature or names a signing key the ring
    // does not hold
    case KEY_UNVERIFIABLE = 'key_unverifiable';

    // The owner holds more keys than one erasure destroys
    case TOO_MANY_KEYS = 'too_many_keys';
}
