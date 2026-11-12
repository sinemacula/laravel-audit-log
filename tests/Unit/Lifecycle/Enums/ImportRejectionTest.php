<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;

/**
 * Unit tests for the import rejection enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportRejection::class)]
final class ImportRejectionTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'MALFORMED_JSON'      => 'malformed_json',
            'UNSUPPORTED_FORMAT'  => 'unsupported_format',
            'UNSUPPORTED_VERSION' => 'unsupported_version',
            'UNKNOWN_FIELD'       => 'unknown_field',
            'MISSING_FIELD'       => 'missing_field',
            'INVALID_FIELD'       => 'invalid_field',
            'RESERVED_CODE'       => 'reserved_code',
            'UNREGISTERED_CODE'   => 'unregistered_code',
            'INVALID_TIME'        => 'invalid_time',
            'FUTURE_TIME'         => 'future_time',
            'OWN_SOURCE'          => 'own_source',
            'SOURCE_MISMATCH'     => 'source_mismatch',
            'OVERSIZED_LINE'      => 'oversized_line',
        ], array_column(ImportRejection::cases(), 'value', 'name'));
    }

    /**
     * Every value is its case's name in lower snake case.
     *
     * @return void
     */
    public function testEveryValueIsItsNameInSnakeCase(): void
    {
        foreach (ImportRejection::cases() as $rejection) {
            self::assertSame(strtolower($rejection->name), $rejection->value);
        }
    }
}
