<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\Enums\StubNumberedActivity;

/**
 * Unit tests for the machine-readable code a reason, a purpose and a channel
 * share: the strings and enum cases it keeps, each it refuses, and the messages
 * it refuses them with, which name what the code is and never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MachineCode::class)]
final class MachineCodeTest extends TestCase
{
    /** @var string The refusal of a malformed code, by what the code is. */
    private const string MALFORMED = '%s must be a machine-readable code of 1 to 64 characters:'
        . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /**
     * `MachineCode` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(MachineCode::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(MachineCode::class, $instance);
    }

    /**
     * Rows of `[code]`: the bounds of the length and the first character, and
     * every other character a code may hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideValidCodes(): iterable
    {
        yield from [
            'a word'               => ['card_declined'],
            'one letter'           => ['a'],
            'one digit'            => ['7'],
            'starting with z'      => ['z'],
            'starting with 9'      => ['9a'],
            '64 characters'        => [str_repeat('a', 64)],
            'each other character' => ['a0_b.c:d-e'],
            'ending in each'       => ['a_.:-'],
        ];
    }

    /**
     * A well-formed code is kept as given, neither cleaned nor cut.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideValidCodes')]
    public function testKeepsAValidCode(string $code): void
    {
        self::assertSame($code, MachineCode::of($code, 'A reason'));
    }

    /**
     * A string-backed enum case gives its value.
     *
     * @return void
     */
    public function testReadsAStringBackedEnum(): void
    {
        self::assertSame('invoice.approved', MachineCode::of(StubActivity::APPROVED, 'A purpose'));
    }

    /**
     * An enum backed by integers has no code to give.
     *
     * @return void
     */
    public function testRefusesAnIntegerBackedEnum(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reason enum must be backed by strings.');

        MachineCode::of(StubNumberedActivity::FIRST, 'A reason');
    }

    /**
     * Rows of `[code]`: the bounds of the length, a first character the pattern
     * reserves, characters outside it, and line breaks at either end, which an
     * unanchored pattern would let through.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedCodes(): iterable
    {
        yield from [
            'empty'              => [''],
            '65 characters'      => [str_repeat('a', 65)],
            'upper case'         => ['Card_declined'],
            'upper case later'   => ['card_Declined'],
            'leading underscore' => ['_declined'],
            'leading dot'        => ['.declined'],
            'leading colon'      => [':declined'],
            'leading hyphen'     => ['-declined'],
            'trailing newline'   => ["card_declined\n"],
            'leading newline'    => ["\ncard_declined"],
            'space'              => ['card declined'],
            'non-ASCII'          => ['card_déclined'],
            'slash'              => ['card/declined'],
            'a NUL byte'         => ["card\0declined"],
        ];
    }

    /**
     * Each malformed code is refused rather than cleaned, cut or kept.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideMalformedCodes')]
    public function testRefusesEachMalformedCode(string $code): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(self::MALFORMED, 'A reason'));

        MachineCode::of($code, 'A reason');
    }

    /**
     * Rows of `[what the code is]`: every name a code is given under.
     *
     * @return iterable<string, array{0: 'A channel'|'A purpose'|'A reason'}>
     */
    public static function provideNames(): iterable
    {
        yield from [
            'a reason'  => ['A reason'],
            'a purpose' => ['A purpose'],
            'a channel' => ['A channel'],
        ];
    }

    /**
     * Both refusals open with what was given, and neither holds the value.
     *
     * @param  'A channel'|'A purpose'|'A reason'  $name
     * @return void
     */
    #[DataProvider('provideNames')]
    public function testTheMessageNamesWhatWasGiven(string $name): void
    {
        try {
            MachineCode::of('NOT A CODE', $name);
            self::fail('Expected the malformed code to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf(self::MALFORMED, $name), $exception->getMessage());
        }

        try {
            MachineCode::of(StubNumberedActivity::FIRST, $name);
            self::fail('Expected the integer-backed enum to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($name . ' enum must be backed by strings.', $exception->getMessage());
        }
    }
}
