<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Support\MachineCode;

/**
 * The pending record's outcome and optional reason; a trait only to keep
 * `PendingRecord` within the method-count limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SetsTheOutcome
{
    /** @var \SineMacula\Laravel\AuditLog\Records\Enums\Outcome How the activity ended. */
    private Outcome $outcome = Outcome::SUCCESS;

    /** @var ?string Why it failed or was denied, as a machine-readable code, if given. */
    private ?string $reason = null;

    /**
     * Say that the activity happened as asked, clearing any earlier reason.
     *
     * @return self
     *
     * @throws \LogicException
     */
    public function succeeded(): self
    {
        $this->assertUsable();

        $this->outcome = Outcome::SUCCESS;
        $this->reason  = null;

        return $this;
    }

    /**
     * Say that the activity was attempted and did not complete.
     *
     * @param  \BackedEnum|string|null  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function failed(\BackedEnum|string|null $reason = null): self
    {
        return $this->end(Outcome::FAILURE, $reason);
    }

    /**
     * Say that a policy refused the activity before it was attempted.
     *
     * @param  \BackedEnum|string|null  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function denied(\BackedEnum|string|null $reason = null): self
    {
        return $this->end(Outcome::DENIED, $reason);
    }

    /**
     * Set the outcome and its reason together.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  \BackedEnum|string|null  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function end(Outcome $outcome, \BackedEnum|string|null $reason): self
    {
        $this->assertUsable();

        $this->reason  = self::reason($reason);
        $this->outcome = $outcome;

        return $this;
    }

    /**
     * The reason as a machine-readable code, or `null` when none is given.
     *
     * @param  \BackedEnum|string|null  $reason
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function reason(\BackedEnum|string|null $reason): ?string
    {
        return $reason === null ? null : MachineCode::of($reason, 'A reason');
    }
}
