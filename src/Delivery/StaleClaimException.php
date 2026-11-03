<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * Thrown inside the transaction a database destination shares with its receipt
 * when the drain finds it no longer owns the outbox row, so the insert and the
 * receipt roll back together and the new owner repeats the delivery.
 *
 * Its message is fixed and it has no previous exception. It never leaves the
 * delivery coordinator, which reads it as a lost claim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StaleClaimException extends \RuntimeException
{
    /** @var string The fixed message. */
    private const string MESSAGE = 'The drain no longer owns the outbox row, so the delivery inside its transaction was rolled back.';

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
