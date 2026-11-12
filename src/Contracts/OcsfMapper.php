<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * OCSF mapper contract: classifies the records of one event code in OCSF, named
 * by `EventDefinition::ocsf()`.
 *
 * It applies only to its definition's version, is made from the container for
 * each record, and keeps no state.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface OcsfMapper
{
    /**
     * The record's attributes in its OCSF class: integer `class_uid`,
     * `category_uid` and `activity_id`, and the class's own attributes,
     * required ones included.
     *
     * The formatter's own `metadata`, `time`, `severity_id`, `type_uid` and
     * `type_name` are refused, and no value may be a float, since the
     * projection is canonical JSON.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     */
    public function map(#[\SensitiveParameter] FinalisedRecord $record): array;
}
