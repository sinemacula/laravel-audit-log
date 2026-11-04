<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;

/**
 * Unit tests for the import format enum: its cases and the versioned names an
 * import line and a batch row hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportFormat::class)]
final class ImportFormatTest extends TestCase
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
            'IMPORT_V1' => 'audit-log-import/v1',
            'EXPORT_V1' => 'audit-log-export/v1',
        ], array_column(ImportFormat::cases(), 'value', 'name'));
    }

    /**
     * Every format's name is versioned and fits the batches table's
     * `input_format` column of 32 characters.
     *
     * @return void
     */
    public function testEveryFormatIsVersionedAndFitsItsColumn(): void
    {
        foreach (ImportFormat::cases() as $format) {
            self::assertMatchesRegularExpression('/\Aaudit-log-[a-z]+\/v[1-9][0-9]*\z/', $format->value);
            self::assertLessThanOrEqual(32, strlen($format->value));
            self::assertSame($format, ImportFormat::from($format->value));
        }
    }
}
