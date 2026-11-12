<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Stamps a captured record's recorded time and signs it, once, before delivery;
 * a retry or replay reuses the result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordFinaliser
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     */
    public function __construct(

        /** The clock that says when a record is recorded. */
        private Clock $clock,

        /** The signer that signs each finalised record. */
        private RecordSigner $signer,
    ) {}

    /**
     * The record signed and recorded now, never before it occurred if the clock
     * lags; the fixed time form orders as strings.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function finalise(AuditRecord $record): FinalisedRecord
    {
        $now = StoredTime::format($this->clock->now());

        return $this->signer->sign($record, max($now, $record->occurredAt));
    }
}
