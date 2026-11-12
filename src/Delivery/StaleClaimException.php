<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * Thrown inside a destination's shared transaction when the drain loses the
 * outbox row, so the insert and its receipt roll back together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StaleClaimException extends \RuntimeException
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct('The drain no longer owns the outbox row, so the delivery inside its transaction was rolled back.');
    }
}
