<?php

declare(strict_types = 1);

namespace Tests\Unit\Export\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;

/**
 * Unit tests for the export format enum: its cases, the values an export's
 * manifest and record store, and the one format whose lines are evidence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportFormat::class)]
final class ExportFormatTest extends TestCase
{
    /**
     * The cases, in order, with the values a manifest and a record store, so a
     * renamed, reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'NDJSON' => 'ndjson',
            'OCSF'   => 'ocsf',
            'CEF'    => 'cef',
        ], array_column(ExportFormat::cases(), 'value', 'name'));
    }

    /**
     * NDJSON alone is evidence, its lines the signed envelopes; OCSF and CEF
     * are projections.
     *
     * @return void
     */
    public function testOnlyNdjsonIsEvidence(): void
    {
        $evidence = array_map(static fn (ExportFormat $format): bool => $format->isEvidence(), ExportFormat::cases());

        self::assertSame([true, false, false], $evidence);
    }
}
