<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;

/**
 * Unit tests for the reasons an erasure is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureRefusal::class)]
final class ErasureRefusalTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'BLOCKED'               => 'blocked',
            'PENDING_DELIVERY'      => 'pending_delivery',
            'UNSUPPORTED_ENCRYPTER' => 'unsupported_encrypter',
            'KEY_UNVERIFIABLE'      => 'key_unverifiable',
            'TOO_MANY_KEYS'         => 'too_many_keys',
        ], array_column(ErasureRefusal::cases(), 'value', 'name'));
    }

    /**
     * Every value reads back as its case.
     *
     * @return void
     */
    public function testEveryValueReadsBackAsItsCase(): void
    {
        foreach (ErasureRefusal::cases() as $refusal) {
            self::assertSame($refusal, ErasureRefusal::from($refusal->value));
        }
    }
}
