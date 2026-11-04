<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * Unit tests for the states that keep an encrypted fragment sealed: the values
 * they are named by and the marker an entry shows for each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldState::class)]
final class FieldStateTest extends TestCase
{
    /**
     * The states are `encrypted`, `erased` and `unreadable`, in that order.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame(['encrypted', 'erased', 'unreadable'], array_map(static fn (FieldState $state): string => $state->value, FieldState::cases()));
    }

    /**
     * Each state's marker is its name in capitals, in brackets.
     *
     * @return void
     */
    public function testTheMarkers(): void
    {
        self::assertSame(['[ENCRYPTED]', '[ERASED]', '[UNREADABLE]'], array_map(static fn (FieldState $state): string => $state->marker(), FieldState::cases()));
    }
}
