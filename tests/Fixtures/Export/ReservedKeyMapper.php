<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * A mapper that classifies a record correctly but also returns an attribute the
 * formatter sets itself, `metadata` unless it is made with another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReservedKeyMapper implements OcsfMapper
{
    /**
     * Constructor.
     *
     * @param  string  $reserved
     */
    public function __construct(

        /** The reserved attribute the mapper returns. */
        private string $reserved = 'metadata',
    ) {}

    /**
     * A classification as Base Event, with the reserved attribute.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     */
    #[\Override]
    public function map(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        return ['class_uid' => 0, 'category_uid' => 0, 'activity_id' => 0, $this->reserved => 'forged'];
    }
}
