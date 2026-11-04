<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;

/**
 * Unit tests for the result of a published export: it keeps each field as
 * given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportResult::class)]
final class ExportResultTest extends TestCase
{
    /**
     * The journal entry's id, the paths, the format, the line count, the file's
     * digest and the acknowledgement are kept as given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $digest = hash('sha256', "line\n");

        $result = new ExportResult(
            '01932b4e-a000-7000-8000-000000000001',
            '/exports/trail.ndjson',
            '/exports/trail.ndjson.manifest.json',
            ExportFormat::OCSF,
            1,
            $digest,
            Acknowledgement::ACCEPTED,
        );

        self::assertSame('01932b4e-a000-7000-8000-000000000001', $result->entryId);
        self::assertSame('/exports/trail.ndjson', $result->path);
        self::assertSame('/exports/trail.ndjson.manifest.json', $result->manifestPath);
        self::assertSame(ExportFormat::OCSF, $result->format);
        self::assertSame(1, $result->lines);
        self::assertSame($digest, $result->fileSha256);
        self::assertSame(Acknowledgement::ACCEPTED, $result->acknowledgement);
    }
}
