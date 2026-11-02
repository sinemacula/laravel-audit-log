<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;

/**
 * Unit tests for the actor snapshot: the reference and guard it keeps, and the
 * guard names it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActorSnapshot::class)]
final class ActorSnapshotTest extends TestCase
{
    /**
     * A snapshot keeps the reference and the guard as given.
     *
     * @return void
     */
    public function testKeepsTheReferenceAndGuard(): void
    {
        $reference = Reference::of('App\Models\User', '42');

        $snapshot = new ActorSnapshot($reference, 'web');

        self::assertSame($reference, $snapshot->reference);
        self::assertSame('web', $snapshot->guard);
    }

    /**
     * Rows of `[guard]`: names at the bounds, counted in characters and not in
     * bytes, which protects against a mutation of the length check.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGuardsAtTheBounds(): iterable
    {
        yield from [
            'one character'             => ['a'],
            'sixty-four characters'     => [str_repeat('a', 64)],
            'sixty-four two-byte runes' => [str_repeat('é', 64)],
        ];
    }

    /**
     * A name from 1 to 64 characters is kept.
     *
     * @param  string  $guard
     * @return void
     */
    #[DataProvider('provideGuardsAtTheBounds')]
    public function testKeepsAGuardAtTheBounds(string $guard): void
    {
        self::assertSame($guard, (new ActorSnapshot(Reference::of('App\Models\User', '42'), $guard))->guard);
    }

    /**
     * Rows of `[guard]`: names that are empty, too long or not clean text.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedGuards(): iterable
    {
        yield from [
            'empty'             => [''],
            '65 characters'     => [str_repeat('a', 65)],
            '65 two-byte runes' => [str_repeat('é', 65)],
            'a NUL'             => ["we\0b"],
            'a tab'             => ["we\tb"],
            'a line feed'       => ["web\n"],
            'a delete'          => ["we\x7Fb"],
            'a bidi override'   => ["we\u{202E}b"],
            'invalid UTF-8'     => ["we\xC3b"],
        ];
    }

    /**
     * Each malformed guard is refused, with the message naming the limit and
     * never the value.
     *
     * @param  string  $guard
     * @return void
     */
    #[DataProvider('provideMalformedGuards')]
    public function testRefusesEachMalformedGuard(string $guard): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A guard name must be from 1 to 64 characters, with no control characters.');

        new ActorSnapshot(Reference::of('App\Models\User', '42'), $guard);
    }
}
