<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\OutboxClaim;

/**
 * Unit tests for a drain's claim on an outbox row: the fields it keeps, and the
 * token and payload it hides from every stack frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxClaim::class)]
final class OutboxClaimTest extends TestCase
{
    /**
     * A claim keeps the row's id, its token, the payload and the attempts as
     * given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $claim = new OutboxClaim('01932b4e-8a40-7000-8000-000000000001', '5f0c6d2e-1a3b-4c5d-8e9f-0a1b2c3d4e5f', 'encrypted', 3);

        self::assertSame('01932b4e-8a40-7000-8000-000000000001', $claim->id);
        self::assertSame('5f0c6d2e-1a3b-4c5d-8e9f-0a1b2c3d4e5f', $claim->token);
        self::assertSame('encrypted', $claim->payload);
        self::assertSame(3, $claim->attempts);
    }

    /**
     * The token and the payload are marked sensitive, so a stack frame that
     * builds a claim never shows either; the id and the attempts are not.
     *
     * @return void
     */
    public function testTheTokenAndPayloadAreSensitive(): void
    {
        $sensitive = [];

        foreach ((new \ReflectionMethod(OutboxClaim::class, '__construct'))->getParameters() as $parameter) {
            $sensitive[$parameter->getName()] = $parameter->getAttributes(\SensitiveParameter::class) !== [];
        }

        self::assertSame(['id' => false, 'token' => true, 'payload' => true, 'attempts' => false], $sensitive);
    }
}
