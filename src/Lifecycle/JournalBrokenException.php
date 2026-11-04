<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Thrown when a lifecycle operation finds the journal it must decide from fails
 * verification: a gap, a signature that fails, a key the ring does not hold, a
 * row that cannot be read, a transition the chain does not allow, a latest seal
 * whose commitment the chain contradicts, or a head that is not the one the
 * operation verified. The operation fails closed: its transaction is rolled
 * back and nothing destructive runs until the journal is investigated.
 *
 * It carries the finding and the id of the row it was found at, when there is
 * one, and names no other value of the row; the package never gives it another
 * exception.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JournalBrokenException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $rowId
     */
    private function __construct(

        /** What the journal fails verification with. */
        public readonly Finding $finding,

        /** The id of the row, or of the seal, it was found at, or `null` when there is none. */
        public readonly ?string $rowId,
    ) {
        parent::__construct(sprintf('The lifecycle journal fails verification (`%s`); nothing destructive runs until it is investigated.', $finding->value));
    }

    /**
     * The journal fails verification with the finding, at the row given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $rowId
     * @return self
     */
    public static function at(Finding $finding, ?string $rowId): self
    {
        return new self($finding, $rowId);
    }
}
