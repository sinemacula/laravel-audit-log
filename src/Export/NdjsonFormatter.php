<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export;

use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Projects a finalised record as one line of newline-delimited JSON: its
 * envelope in the canonical encoding it is signed over, with line breaks
 * escaped, so the same record always gives the same bytes. It is a projection:
 * only the stored row is evidence.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NdjsonFormatter implements AuditFormatter
{
    /**
     * The record's envelope in the canonical encoding, as one line.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function format(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        return CanonicalEncoder::encode($record->toArray());
    }
}
