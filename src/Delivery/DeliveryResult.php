<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * How the delivery of one claimed row's record ended, with what the last
 * destination to fail failed with when one did: an incomplete delivery always
 * says, and no other holds a failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveryResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome  $outcome
     * @param  ?\SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     */
    private function __construct(

        /** How the delivery ended. */
        public DeliveryOutcome $outcome,

        /** What it failed with, for `failure()` to give. */
        private ?WriteDiagnostics $diagnostics = null,
    ) {}

    /**
     * Every destination has the record.
     *
     * @return self
     */
    public static function complete(): self
    {
        return new self(DeliveryOutcome::COMPLETE);
    }

    /**
     * The claim no longer owns the row.
     *
     * @return self
     */
    public static function stale(): self
    {
        return new self(DeliveryOutcome::STALE);
    }

    /**
     * A destination does not have the record, for the reason given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $failure
     * @return self
     */
    public static function incomplete(#[\SensitiveParameter] WriteDiagnostics $failure): self
    {
        return new self(DeliveryOutcome::INCOMPLETE, $failure);
    }

    /**
     * What an incomplete delivery failed with; asking any other is a mistake.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics
     *
     * @throws \LogicException
     */
    public function failure(): WriteDiagnostics
    {
        return $this->diagnostics ?? throw new \LogicException('Only an incomplete delivery has a failure.');
    }
}
