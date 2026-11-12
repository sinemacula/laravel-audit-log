<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Thrown when the journal a lifecycle operation decides from fails
 * verification; the operation fails closed and rolls back.
 *
 * It names the finding and the row id, never another value of the row.
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

        /** Why the journal fails verification. */
        public readonly Finding $finding,

        /** The row or seal id it was found at, or `null` when there is none. */
        public readonly ?string $rowId,
    ) {
        parent::__construct(sprintf('The lifecycle journal fails verification (`%s`); nothing destructive runs until it is investigated.', $finding->value));
    }

    /**
     * The journal fails verification with the finding at the row given.
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
