<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;

/**
 * Unit tests for the key owner enum: the parties an encrypted field's key can
 * belong to and the values definitions name them by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyOwner::class)]
final class KeyOwnerTest extends TestCase
{
    /**
     * A key is owned by the actor or the subject, by those values, and by no
     * other case.
     *
     * @return void
     */
    public function testTheCasesAndTheirStoredValues(): void
    {
        self::assertSame([KeyOwner::ACTOR, KeyOwner::SUBJECT], KeyOwner::cases());
        self::assertSame(['actor', 'subject'], array_map(static fn (KeyOwner $owner): string => $owner->value, KeyOwner::cases()));
    }
}
