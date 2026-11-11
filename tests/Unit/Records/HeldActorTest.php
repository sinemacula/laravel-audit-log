<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the actor a guard holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HeldActor::class)]
final class HeldActorTest extends TestCase
{
    /**
     * The actor alone needs no principal, tenant or session.
     *
     * @return void
     */
    public function testTheActorAloneIsEnough(): void
    {
        $actor = Reference::of('user', '42');
        $held  = new HeldActor($actor);

        self::assertSame($actor, $held->actor);
        self::assertNull($held->principal);
        self::assertNull($held->tenant);
        self::assertNull($held->session);
    }

    /**
     * Every part is kept as given, a 191-character session reference included.
     *
     * @return void
     */
    public function testKeepsEveryPart(): void
    {
        $principal = Reference::of('principal', 'p-1');
        $tenant    = Reference::of('tenant', 't-1');
        $session   = str_repeat('é', 191);
        $held      = new HeldActor(Reference::of('user', '42'), $principal, $tenant, $session);

        self::assertSame($principal, $held->principal);
        self::assertSame($tenant, $held->tenant);
        self::assertSame($session, $held->session);
    }

    /**
     * Rows of `[session]` a record could not store.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedSessions(): iterable
    {
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 192)];
        yield 'a control character' => ["sess\nion"];
        yield 'malformed UTF-8' => ["sess\xC3ion"];
    }

    /**
     * A session reference a record could not store is refused.
     *
     * @param  string  $session
     * @return void
     */
    #[DataProvider('provideRefusedSessions')]
    public function testRefusesASessionARecordCouldNotStore(string $session): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A session reference must be from 1 to 191 characters, with no control characters.');

        new HeldActor(Reference::of('user', '42'), session: $session);
    }
}
