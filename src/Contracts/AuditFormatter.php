<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Audit formatter contract: how a finalised record is projected as one line of
 * text for a log, a file or a security tool.
 *
 * The package ships `Export\NdjsonFormatter`, the canonical JSON envelope,
 * `Export\OcsfFormatter`, a pinned version of the Open Cybersecurity Schema
 * Framework, and `Export\CefFormatter`, the Common Event Format. A projection
 * is never the integrity artefact: only the stored row, with its HMAC, is
 * evidence. An implementation must be deterministic, so the same record gives
 * the same bytes, must return exactly one physical line, with no carriage
 * return or line feed in it and none after it, must escape whatever a record
 * holds so that no value can forge a field of its own, and must keep no state
 * between calls. It should mark its own record parameter
 * `#[\SensitiveParameter]`, since an attribute on this contract does not reach
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditFormatter
{
    /**
     * The record projected as one line, without a line ending.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \Throwable
     */
    public function format(#[\SensitiveParameter] FinalisedRecord $record): string;
}
