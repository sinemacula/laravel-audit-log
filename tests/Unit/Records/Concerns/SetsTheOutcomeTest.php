<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Concerns;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Concerns\SetsTheOutcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\Enums\StubPriority;

/**
 * Unit tests for a pending record's outcome and its reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRecord::class)]
#[CoversTrait(SetsTheOutcome::class)]
final class SetsTheOutcomeTest extends TestCase
{
    /** @var string The refusal of a reason that is not a machine-readable code. */
    private const string REASON = 'A reason must be a machine-readable code of 1 to 64 characters:'
        . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /**
     * A record succeeds, with no reason, unless told otherwise.
     *
     * @return void
     */
    public function testTheOutcomeIsSuccessByDefault(): void
    {
        $snapshot = (new PendingRecord)->snapshot();

        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertNull($snapshot->reason);
    }

    /**
     * `succeeded()` sets success and clears a reason an earlier outcome gave.
     *
     * @return void
     */
    public function testSucceededClearsTheReason(): void
    {
        $snapshot = (new PendingRecord)->denied('policy')->succeeded()->snapshot();

        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertNull($snapshot->reason);
    }

    /**
     * Rows of `[call, outcome]`: the two outcomes that take a reason, each
     * given one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 1: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'failed' => [static fn (PendingRecord $pending): PendingRecord => $pending->failed('insufficient_funds'), Outcome::FAILURE],
            'denied' => [static fn (PendingRecord $pending): PendingRecord => $pending->denied('insufficient_funds'), Outcome::DENIED],
        ];
    }

    /**
     * `failed()` and `denied()` each set their outcome and the reason given.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $call
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testFailedAndDeniedSetTheirOutcomeAndReason(\Closure $call, Outcome $outcome): void
    {
        $snapshot = $call(new PendingRecord)->snapshot();

        self::assertSame($outcome, $snapshot->outcome);
        self::assertSame('insufficient_funds', $snapshot->reason);
    }

    /**
     * A failure or a denial may have no reason.
     *
     * @return void
     */
    public function testAReasonIsOptional(): void
    {
        self::assertNull((new PendingRecord)->failed()->snapshot()->reason);
        self::assertNull((new PendingRecord)->denied()->snapshot()->reason);
        self::assertNull((new PendingRecord)->failed('policy')->denied(null)->snapshot()->reason);
    }

    /**
     * A reason may be a string-backed enum case, which gives its value.
     *
     * @return void
     */
    public function testAReasonMayBeAStringBackedEnum(): void
    {
        self::assertSame('red', (new PendingRecord)->denied(StubColour::RED)->snapshot()->reason);
    }

    /**
     * An enum backed by integers is refused as a reason.
     *
     * @return void
     */
    public function testAnIntegerBackedReasonIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reason enum must be backed by strings.');

        (new PendingRecord)->failed(StubPriority::HIGH);
    }

    /**
     * Rows of `[reason]`: machine-readable codes, the longest included.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReasons(): iterable
    {
        yield from [
            'snake case'        => ['insufficient_funds'],
            'one word'          => ['policy'],
            'a hyphen'          => ['rate-limit'],
            'a colon and a dot' => ['app:quota.exceeded'],
            'a leading digit'   => ['2fa_required'],
            'one character'     => ['x'],
            '64 characters'     => [str_repeat('r', 64)],
        ];
    }

    /**
     * Each machine-readable reason is kept exactly.
     *
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('provideReasons')]
    public function testKeepsAMachineReadableReason(string $reason): void
    {
        self::assertSame($reason, (new PendingRecord)->failed($reason)->snapshot()->reason);
    }

    /**
     * Rows of `[reason]`: reasons that are empty, too long, words, or start
     * with anything but a letter or a digit.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedReasons(): iterable
    {
        yield from [
            'empty'                => [''],
            '65 characters'        => [str_repeat('r', 65)],
            'upper case'           => ['Insufficient'],
            'a space'              => ['with space'],
            'a trailing new line'  => ["policy\n"],
            'a leading underscore' => ['_leading'],
            'a leading hyphen'     => ['-leading'],
            'a non-ASCII letter'   => ['é'],
        ];
    }

    /**
     * Each reason that is not a machine-readable code is refused, never cleaned
     * or cut, by either method.
     *
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('provideRefusedReasons')]
    public function testRefusesAReasonThatIsNotAMachineCode(string $reason): void
    {
        try {
            (new PendingRecord)->denied($reason);
            self::fail('Expected the denial\'s reason to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::REASON, $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::REASON);

        (new PendingRecord)->failed($reason);
    }

    /**
     * A refused reason leaves the outcome and reason given before it.
     *
     * @return void
     */
    public function testARefusedReasonChangesNothing(): void
    {
        $pending = (new PendingRecord)->denied('policy');

        try {
            $pending->failed('Not A Code');
            self::fail('Expected the reason to be refused.');
        } catch (\InvalidArgumentException) {
            // The refusal is the point; the state is checked below
        }

        self::assertSame(Outcome::DENIED, $pending->snapshot()->outcome);
        self::assertSame('policy', $pending->snapshot()->reason);
    }

    /**
     * The last outcome given wins, its reason with it.
     *
     * @return void
     */
    public function testTheLastOutcomeWins(): void
    {
        $denied = (new PendingRecord)->failed('timeout')->denied('policy')->snapshot();
        $failed = (new PendingRecord)->succeeded()->denied('policy')->failed()->snapshot();

        self::assertSame([Outcome::DENIED, 'policy'], [$denied->outcome, $denied->reason]);
        self::assertSame([Outcome::FAILURE, null], [$failed->outcome, $failed->reason]);
    }
}
