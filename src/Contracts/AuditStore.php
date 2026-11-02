<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Audit store contract: where finalised records are kept.
 *
 * A store takes the finalised record, never a model, and keeps it as it is: the
 * record was finalised once, and a retry hands the store the same record again.
 * The package binds `Stores\DatabaseAuditStore`, which writes the entries
 * table; an application rebinds the contract to keep records elsewhere. An
 * implementation must keep no state between calls, must store a record at most
 * once (the same id with the same captured content is a success, and with
 * different content a `RecordConflictException`), and must let every other
 * failure propagate, since what a failure means is the caller's to decide.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditStore
{
    /**
     * Store the finalised record, or succeed without writing when the store
     * already holds it with the same captured content.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    public function store(FinalisedRecord $record): void;
}
