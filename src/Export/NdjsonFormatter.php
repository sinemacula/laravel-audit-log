<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export;

use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Projects a finalised record as one line of newline-delimited JSON: its
 * envelope, every column under its stored key, in the canonical encoding the
 * record is signed over.
 *
 * Keys are sorted bytewise and nothing is pretty-printed, so the same record
 * always gives the same bytes. A carriage return, a line feed and the Unicode
 * line and paragraph separators in a value are escaped inside their JSON
 * string, so the line is one physical line whatever the record holds; other
 * Unicode is kept as it is. A map whose keys are numbers stays a map. The line
 * carries the record's HMAC, but it is a projection: only the stored row is
 * evidence.
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
