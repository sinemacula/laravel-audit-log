<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * Unit tests for the envelope failure enum: its cases and the values a refused
 * envelope is counted under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeFailure::class)]
final class EnvelopeFailureTest extends TestCase
{
    /**
     * The cases, in order, with the values a drain or a replay counts each
     * refusal under.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'SIGNATURE_MISMATCH'  => 'signature_mismatch',
            'UNKNOWN_KEY'         => 'unknown_key',
            'UNSUPPORTED_VERSION' => 'unsupported_version',
            'MALFORMED'           => 'malformed',
            'TRUNCATED'           => 'truncated',
            'UNSIGNED'            => 'unsigned',
            'ID_MISMATCH'         => 'id_mismatch',
            'OVERSIZE'            => 'oversize',
        ], array_column(EnvelopeFailure::cases(), 'value', 'name'));
    }
}
