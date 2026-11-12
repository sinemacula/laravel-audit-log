<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;

/**
 * Unit tests for the key state enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyState::class)]
final class KeyStateTest extends TestCase
{
    /**
     * The cases, in order, with their stored values, so a renamed, reordered or
     * added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'LIVE'       => 'live',
            'SUPERSEDED' => 'superseded',
            'ERASED'     => 'erased',
        ], array_column(KeyState::cases(), 'value', 'name'));
    }

    /**
     * A live and a superseded key still hold their wrapped key, and an erased
     * one never does.
     *
     * @return void
     */
    public function testOnlyLiveAndSupersededHoldAKey(): void
    {
        self::assertSame([
            'live'       => true,
            'superseded' => true,
            'erased'     => false,
        ], array_combine(
            array_column(KeyState::cases(), 'value'),
            array_map(static fn (KeyState $state): bool => $state->holdsAKey(), KeyState::cases()),
        ));
    }

    /**
     * Only a live key encrypts a new field: a superseded one only decrypts what
     * it encrypted before, and an erased one decrypts nothing.
     *
     * @return void
     */
    public function testOnlyLiveEncrypts(): void
    {
        self::assertSame([
            'live'       => true,
            'superseded' => false,
            'erased'     => false,
        ], array_combine(
            array_column(KeyState::cases(), 'value'),
            array_map(static fn (KeyState $state): bool => $state->encrypts(), KeyState::cases()),
        ));
    }
}
