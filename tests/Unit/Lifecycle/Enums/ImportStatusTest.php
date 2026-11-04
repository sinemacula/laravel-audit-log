<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;

/**
 * Unit tests for the import batch status enum: its cases and their stored
 * values, and the one status that is not final.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportStatus::class)]
final class ImportStatusTest extends TestCase
{
    /**
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'RUNNING'     => 'running',
            'COMPLETE'    => 'complete',
            'PARTIAL'     => 'partial',
            'FAILED'      => 'failed',
            'INTERRUPTED' => 'interrupted',
        ], array_column(ImportStatus::cases(), 'value', 'name'));
    }

    /**
     * Every status but `running` is final, so a batch that has finished, in
     * whichever way, never moves again.
     *
     * @return void
     */
    public function testEveryStatusButRunningIsFinal(): void
    {
        self::assertSame([
            'running'     => false,
            'complete'    => true,
            'partial'     => true,
            'failed'      => true,
            'interrupted' => true,
        ], array_combine(
            array_column(ImportStatus::cases(), 'value'),
            array_map(static fn (ImportStatus $status): bool => $status->isFinal(), ImportStatus::cases()),
        ));
    }

    /**
     * Each stored value reads back as its case, and a value the batches table
     * never holds reads as none.
     *
     * @return void
     */
    public function testTheStoredValuesReadBack(): void
    {
        foreach (ImportStatus::cases() as $status) {
            self::assertSame($status, ImportStatus::from($status->value));
        }

        self::assertNull(ImportStatus::tryFrom('Running'));
        self::assertNull(ImportStatus::tryFrom('done'));
    }
}
