<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * OCSF mapper contract: how the records of one event code are classified in the
 * Open Cybersecurity Schema Framework, for the code's definition to name with
 * `EventDefinition::ocsf()`.
 *
 * A mapper applies only to records of its definition's version; a record of any
 * other version, and every code with no mapper, is projected as a Base Event,
 * so a classification is never invented. The formatter makes a mapper from the
 * container for each record, so a mapper may take what it needs in its
 * constructor, and an implementation must keep no state between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface OcsfMapper
{
    /**
     * The record's attributes in its OCSF class: the integers `class_uid`,
     * `category_uid` and `activity_id`, with the class in that category, and
     * the class's own attributes, its required ones included.
     *
     * The formatter adds the rest, and refuses a mapper that returns any of
     * `metadata`, `time`, `severity_id`, `type_uid` and `type_name`, which it
     * sets itself. A value may be a string, an integer, a boolean, `null`, or a
     * list or map of those, never a float, because the projection is canonical
     * JSON.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     */
    public function map(#[\SensitiveParameter] FinalisedRecord $record): array;
}
