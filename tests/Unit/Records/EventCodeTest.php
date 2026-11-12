<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\Enums\StubNumberedActivity;

/**
 * Unit tests for the event code and the prefix reserved for the package's own
 * codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventCode::class)]
final class EventCodeTest extends TestCase
{
    /** @var string The message a code outside the grammar fails with. */
    private const string GRAMMAR_MESSAGE = 'An event code must be lower-case dotted segments, such as `invoice.approved`:'
        . ' each a letter, then letters, digits or underscores, in at least two segments.';

    /** @var string The message a code longer than the column fails with. */
    private const string LENGTH_MESSAGE = 'An event code must be at most 191 bytes.';

    /** @var string The message a caller's code under the reserved prefix fails with. */
    private const string RESERVED_MESSAGE = 'The `audit_log.` prefix is reserved for the package\'s own event codes.';

    /**
     * The longest code is the `event` column's 191 bytes, and the package's own
     * codes begin `audit_log.`.
     *
     * @return void
     */
    public function testTheLimitAndTheReservedPrefix(): void
    {
        self::assertSame(191, EventCode::MAX_BYTES);
        self::assertSame('audit_log.', EventCode::RESERVED_PREFIX);
    }

    /**
     * Rows of `[code]`: codes within the grammar and the column, from the
     * shortest to the longest.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideValidCodes(): iterable
    {
        yield from [
            'two segments'          => ['invoice.approved'],
            'digits and three'      => ['app.v2.user_created'],
            'underscores'           => ['user.password_reset'],
            'shortest'              => ['a.b'],
            'trailing underscore'   => ['invoice.approved_'],
            'longest, in 191 bytes' => ['a.' . str_repeat('b', 189)],
        ];
    }

    /**
     * A valid code keeps its value exactly, neither cleaned nor cut.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideValidCodes')]
    public function testKeepsAValidCode(string $code): void
    {
        self::assertSame($code, EventCode::of($code)->value);
    }

    /**
     * A string-backed enum case gives its value as the code.
     *
     * @return void
     */
    public function testTakesAStringBackedEnum(): void
    {
        self::assertSame('invoice.approved', EventCode::of(StubActivity::APPROVED)->value);
    }

    /**
     * An integer-backed enum case gives no code.
     *
     * @return void
     */
    public function testRefusesAnIntegerBackedEnum(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event code enum must be backed by strings.');

        EventCode::of(StubNumberedActivity::FIRST);
    }

    /**
     * Rows of `[code]`: codes outside the grammar, within the column.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidCodes(): iterable
    {
        yield from [
            'empty'                               => [''],
            'one segment'                         => ['invoice'],
            'upper case'                          => ['Invoice.approved'],
            'upper case in a later segment'       => ['invoice.Approved'],
            'trailing newline'                    => ["invoice.approved\n"],
            'inner newline'                       => ["invoice.\napproved"],
            'leading digit'                       => ['1nvoice.approved'],
            'segment starting with a digit'       => ['invoice.2fa'],
            'leading underscore'                  => ['_invoice.approved'],
            'segment starting with an underscore' => ['invoice._approved'],
            'empty segment'                       => ['invoice..approved'],
            'trailing dot'                        => ['invoice.'],
            'leading dot'                         => ['.invoice.approved'],
            'hyphen'                              => ['invoice.re-fund'],
            'space'                               => ['invoice. approved'],
            'tab'                                 => ["invoice.\tapproved"],
            'colon'                               => ['invoice:approved'],
            'unicode'                             => ['invoice.apprové'],
            'NUL'                                 => ["invoice.approved\0"],
            'leading whitespace'                  => [' invoice.approved'],
        ];
    }

    /**
     * Each code outside the grammar is refused with the grammar message.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideInvalidCodes')]
    public function testRefusesAnInvalidCode(string $code): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        EventCode::of($code);
    }

    /**
     * A code of 192 bytes, one past the column, is refused with the length
     * message.
     *
     * @return void
     */
    public function testRefusesACodeOf192Bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::LENGTH_MESSAGE);

        EventCode::of('a.' . str_repeat('b', 190));
    }

    /**
     * Rows of `[code]`: codes past the column that are also outside the
     * grammar, or within 191 characters but not 191 bytes.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLongInvalidCodes(): iterable
    {
        yield from [
            'upper case, 192 bytes'               => [str_repeat('A', 192)],
            'one segment, 192 bytes'              => [str_repeat('a', 192)],
            'unicode, 97 characters in 192 bytes' => ['a.' . str_repeat('é', 95)],
            'reserved prefix, 192 bytes'          => ['audit_log.' . str_repeat('b', 182)],
        ];
    }

    /**
     * The length is checked first, in bytes, so a long code is refused with the
     * length message whatever else is wrong.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideLongInvalidCodes')]
    public function testTheLengthIsCheckedFirstAndInBytes(string $code): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::LENGTH_MESSAGE);

        EventCode::of($code);
    }

    /**
     * A caller may not give a code under the reserved prefix, as a string or as
     * an enum case.
     *
     * @return void
     */
    public function testRefusesTheReservedPrefix(): void
    {
        foreach (['audit_log.pruned', StubActivity::RESERVED] as $code) {
            try {
                EventCode::of($code);

                self::fail('Expected the reserved code to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::RESERVED_MESSAGE, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[code]`: codes that resemble the reserved prefix without
     * beginning with it exactly.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLookalikeCodes(): iterable
    {
        yield from [
            'a longer first segment' => ['audit_logs.pruned'],
            'the prefix inside'      => ['app.audit_log.pruned'],
            'the words apart'        => ['audit.log'],
            'the prefix last'        => ['app.audit_log'],
        ];
    }

    /**
     * Only the exact prefix is reserved: a code that merely resembles it is an
     * ordinary code and keeps its value.
     *
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideLookalikeCodes')]
    public function testAcceptsCodesThatOnlyResembleTheReservedPrefix(string $code): void
    {
        self::assertSame($code, EventCode::of($code)->value);
    }

    /**
     * The reserved prefix alone is refused with the grammar message, as the
     * grammar is checked first.
     *
     * @return void
     */
    public function testTheReservedPrefixIsCheckedAfterTheGrammar(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        EventCode::of('audit_log.');
    }

    /**
     * Each of the package's own activities mints its code, under the reserved
     * prefix.
     *
     * @return void
     */
    public function testPackageMintsAReservedCode(): void
    {
        self::assertSame('audit_log.trail_read', EventCode::package(PackageActivity::TRAIL_READ)->value);

        foreach (PackageActivity::cases() as $activity) {
            $code = EventCode::package($activity);

            self::assertSame($activity->value, $code->value, $activity->name);
            self::assertStringStartsWith(EventCode::RESERVED_PREFIX, $code->value, $activity->name);
        }
    }

    /**
     * `of()` still refuses the package's own codes, given as the activity or as
     * its value, so minting one is no way for a caller to record one.
     *
     * @return void
     */
    public function testOfStillRefusesTheReservedPrefix(): void
    {
        foreach ([PackageActivity::TRAIL_READ, PackageActivity::EXPORT_PUBLISH_FAILED->value] as $code) {
            try {
                EventCode::of($code);

                self::fail('Expected the package code to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::RESERVED_MESSAGE, $exception->getMessage());
            }
        }
    }

    /**
     * A code read for a lookup may be under the reserved prefix; an ordinary
     * code is read as `of()` reads it.
     *
     * @return void
     */
    public function testForReadingAcceptsAReservedCode(): void
    {
        self::assertSame('audit_log.trail_read', EventCode::forReading('audit_log.trail_read')->value);
        self::assertSame('audit_log.trail_exported', EventCode::forReading(PackageActivity::TRAIL_EXPORTED)->value);
        self::assertSame('audit_log.pruned', EventCode::forReading(StubActivity::RESERVED)->value);
        self::assertSame('invoice.approved', EventCode::forReading(StubActivity::APPROVED)->value);
        self::assertSame('invoice.approved', EventCode::forReading('invoice.approved')->value);
    }

    /**
     * Rows of `[code, message]`: codes a lookup still refuses, outside the
     * grammar, past the column, or backed by integers.
     *
     * @return iterable<string, array{0: \BackedEnum|string, 1: string}>
     */
    public static function provideCodesReadingRefuses(): iterable
    {
        yield from [
            'empty'                       => ['', self::GRAMMAR_MESSAGE],
            'one segment'                 => ['audit_log', self::GRAMMAR_MESSAGE],
            'the prefix alone'            => ['audit_log.', self::GRAMMAR_MESSAGE],
            'upper case under the prefix' => ['audit_log.Trail_read', self::GRAMMAR_MESSAGE],
            'trailing newline'            => ["audit_log.trail_read\n", self::GRAMMAR_MESSAGE],
            'a wildcard'                  => ['audit_log.%', self::GRAMMAR_MESSAGE],
            'reserved, 192 bytes'         => ['audit_log.' . str_repeat('b', 182), self::LENGTH_MESSAGE],
            'ordinary, 192 bytes'         => ['a.' . str_repeat('b', 190), self::LENGTH_MESSAGE],
            'an integer-backed enum'      => [StubNumberedActivity::FIRST, 'An event code enum must be backed by strings.'],
        ];
    }

    /**
     * A lookup still holds a code to the grammar and the length, so a malformed
     * code is refused rather than read as one that matches nothing.
     *
     * @param  \BackedEnum|string  $code
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideCodesReadingRefuses')]
    public function testForReadingStillChecksTheGrammarAndLength(\BackedEnum|string $code, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        EventCode::forReading($code);
    }

    /**
     * The longest reserved code a lookup takes is the column's 191 bytes.
     *
     * @return void
     */
    public function testForReadingTakesTheLongestReservedCode(): void
    {
        $code = 'audit_log.' . str_repeat('b', 181);

        self::assertSame($code, EventCode::forReading($code)->value);
    }
}
