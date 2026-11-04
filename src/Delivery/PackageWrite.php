<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * What the package's own read path asks of a record it writes, beyond the
 * guarantees of a fail-closed, immediate record: a check of the record once it
 * is built and before it is delivered, which throws to refuse it, so nothing is
 * delivered that does not keep its evidence exactly; and a hand-over of the
 * finalised record once the store or the outbox has acknowledged it, so the
 * read discloses nothing until then, and holds the very envelope that was
 * written.
 *
 * Only a record under the reserved `audit_log.` prefix is written with one, and
 * such a record is written with nothing else. Both closures capture what the
 * read disclosed, so neither ever shows in a stack frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PackageWrite
{
    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\AuditRecord): void  $accept
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\FinalisedRecord): void  $acknowledged
     */
    public function __construct(

        /** Checks the built record before it is delivered, and throws to refuse it. */
        #[\SensitiveParameter]
        public \Closure $accept,

        /** Given the finalised record once its store or the outbox has acknowledged it. */
        #[\SensitiveParameter]
        public \Closure $acknowledged,
    ) {}

    /**
     * Check the built record before it is delivered; what the check throws
     * propagates as it is, and refuses the record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     */
    public function check(#[\SensitiveParameter] AuditRecord $record): void
    {
        ($this->accept)($record);
    }

    /**
     * Hand over the finalised record, which its store or the outbox has
     * acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @return void
     */
    public function acknowledge(#[\SensitiveParameter] FinalisedRecord $finalised): void
    {
        ($this->acknowledged)($finalised);
    }
}
