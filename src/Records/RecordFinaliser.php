<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Finalises a captured record: stamps when it was recorded from the clock and
 * signs it, once.
 *
 * It runs once per record, after the record is captured and before it is
 * delivered; a retry or a replay reuses the finalised record it returned, byte
 * for byte, and never finalises the record again. The store never calls it. A
 * record is never recorded before its activity occurred: when the clock is
 * behind the time the record was captured with (a host whose clock lags the
 * capturing one), the record is stamped with the time it occurred instead.
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
     * The record finalised now: recorded at the clock's instant, or at the time
     * it occurred when that is later, and signed under the ring's signing key.
     * Both times are in the package's fixed form, so comparing them as strings
     * orders them as instants.
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
