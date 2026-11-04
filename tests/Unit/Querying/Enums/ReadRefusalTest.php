<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;

/**
 * Unit tests for the read refusal enum: its cases and the values a refused
 * read's exception names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadRefusal::class)]
final class ReadRefusalTest extends TestCase
{
    /**
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails.
     *
     * @return void
     */
    public function testTheValues(): void
    {
        self::assertSame([
            'REENTRANT'          => 'reentrant',
            'IN_TRANSACTION'     => 'in_transaction',
            'NOT_DURABLE'        => 'not_durable',
            'KEEPS_NO_ARTIFACTS' => 'keeps_no_artifacts',
            'UNRECORDED'         => 'unrecorded',
            'EVIDENCE_ALTERED'   => 'evidence_altered',
            'FAILED'             => 'failed',
            'PUBLISH_FAILED'     => 'publish_failed',
        ], array_column(ReadRefusal::cases(), 'value', 'name'));
    }
}
