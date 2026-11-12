<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Audit store contract: where finalised records are kept.
 *
 * An implementation keeps no state, stores a record at most once (the same id
 * and content succeed, different content is a `RecordConflictException`), and
 * lets every other failure propagate.
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
