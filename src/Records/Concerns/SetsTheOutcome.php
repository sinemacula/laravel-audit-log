<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Support\MachineCode;

/**
 * The pending record's outcome: it succeeded, which is the default, it failed,
 * or a policy denied it, each failure or denial with an optional reason.
 *
 * A reason is a machine-readable code, never words: 1 to 64 lower-case letters,
 * digits, `_`, `.`, `:` or `-`, starting with a letter or a digit, given as a
 * string or as a string-backed enum case. It is validated, never cleaned or
 * cut. The last outcome given wins, its reason with it.
 *
 * The methods sit in a trait only so the builder stays within the number of
 * methods one class may declare; they are `PendingRecord`'s public surface.
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
     * Say that the activity happened as asked, clearing any reason given with
     * an earlier outcome.
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
     * Say that the activity was attempted and did not complete, with an
     * optional machine-readable reason.
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
     * Say that a policy refused the activity before it was attempted, with an
     * optional machine-readable reason.
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
