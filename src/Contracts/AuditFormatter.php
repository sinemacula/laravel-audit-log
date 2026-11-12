<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Audit formatter contract: a finalised record projected as one line of text
 * for a log, a file or a security tool, never the integrity artefact.
 *
 * An implementation is deterministic, returns one line with no line break in or
 * after it, escapes values so none can forge a field, keeps no state, and
 * should mark its record parameter `#[\SensitiveParameter]`, which this
 * contract cannot pass on.
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
