<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * A mapper whose classification is wrong: by default API Activity's class in
 * the IAM category, or whatever classification it is made with, such as one
 * missing an attribute or giving one as a string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MisclassifyingMapper implements OcsfMapper
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string>  $classification
     */
    public function __construct(

        /** The classification the mapper returns. */
        private array $classification = ['class_uid' => 6003, 'category_uid' => 3, 'activity_id' => 3],
    ) {}

    /**
     * The wrong classification, and nothing else.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     */
    #[\Override]
    public function map(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        return $this->classification;
    }
}
