<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * What the package's own read path and lifecycle ask of a record they write: a
 * check that throws to refuse it before delivery, and a hand-over of the
 * finalised record once acknowledged, so a read discloses nothing until then.
 *
 * Both closures hold what the activity disclosed, so neither shows in a stack
 * frame.
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

        /** Checks the built record before delivery, throwing to refuse it. */
        #[\SensitiveParameter]
        public \Closure $accept,

        /** Given the finalised record once the store or outbox acknowledges it. */
        #[\SensitiveParameter]
        public \Closure $acknowledged,
    ) {}

    /**
     * Check the built record before delivery; what the check throws refuses it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     */
    public function check(#[\SensitiveParameter] AuditRecord $record): void
    {
        ($this->accept)($record);
    }

    /**
     * Hand over the finalised record once acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @return void
     */
    public function acknowledge(#[\SensitiveParameter] FinalisedRecord $finalised): void
    {
        ($this->acknowledged)($finalised);
    }
}
