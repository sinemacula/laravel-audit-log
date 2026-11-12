<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Concerns;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Concerns\ChoosesDelivery;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Unit tests for a pending record's timing, connection and fail-closed state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRecord::class)]
#[CoversTrait(ChoosesDelivery::class)]
final class ChoosesDeliveryTest extends TestCase
{
    /** @var string The refusal of a fail-closed record after commit. */
    private const string FAIL_CLOSED = 'A fail-closed record is written immediately or transactionally, never after commit or after the transaction.';

    /**
     * A record has no timing, no connection and is not fail-closed until told
     * otherwise: the recorder applies its default.
     *
     * @return void
     */
    public function testTimingIsUnsetByDefault(): void
    {
        $snapshot = (new PendingRecord)->snapshot();

        self::assertNull($snapshot->timing);
        self::assertNull($snapshot->connection);
        self::assertFalse($snapshot->failClosed);
    }

    /**
     * Rows of `[call, timing, connection]`: each timing, with and without a
     * connection where it takes one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 1: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 2: ?string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideTimings(): iterable
    {
        yield from [
            'after commit'                  => [static fn (PendingRecord $pending): PendingRecord => $pending->afterCommit(), Timing::AFTER_COMMIT, null],
            'after commit on a connection'  => [static fn (PendingRecord $pending): PendingRecord => $pending->afterCommit('business'), Timing::AFTER_COMMIT, 'business'],
            'immediately'                   => [static fn (PendingRecord $pending): PendingRecord => $pending->immediately(), Timing::IMMEDIATE, null],
            'transactional'                 => [static fn (PendingRecord $pending): PendingRecord => $pending->transactional(), Timing::TRANSACTIONAL, null],
            'transactional on a connection' => [static fn (PendingRecord $pending): PendingRecord => $pending->transactional('business'), Timing::TRANSACTIONAL, 'business'],
            'on a 64-character connection'  => [
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional(str_repeat('é', 64)),
                Timing::TRANSACTIONAL,
                str_repeat('é', 64),
            ],
        ];
    }

    /**
     * Each timing is kept with its connection, and does not make the record
     * fail-closed.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $call
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @return void
     */
    #[DataProvider('provideTimings')]
    public function testEachTimingIsKept(\Closure $call, Timing $timing, ?string $connection): void
    {
        $snapshot = $call(new PendingRecord)->snapshot();

        self::assertSame($timing, $snapshot->timing);
        self::assertSame($connection, $snapshot->connection);
        self::assertFalse($snapshot->failClosed);
    }

    /**
     * The same timing on the same connection again changes nothing.
     *
     * @return void
     */
    public function testRepeatingTheSameTimingIsIdempotent(): void
    {
        $afterCommit   = (new PendingRecord)->afterCommit()->afterCommit()->snapshot();
        $transactional = (new PendingRecord)->transactional('business')->transactional('business')->snapshot();
        $immediately   = (new PendingRecord)->immediately()->immediately()->snapshot();

        self::assertSame([Timing::AFTER_COMMIT, null], [$afterCommit->timing, $afterCommit->connection]);
        self::assertSame([Timing::TRANSACTIONAL, 'business'], [$transactional->timing, $transactional->connection]);
        self::assertSame([Timing::IMMEDIATE, null], [$immediately->timing, $immediately->connection]);
    }

    /**
     * Rows of `[first, second, the first timing's value]`: a different mode, or
     * the same mode on another connection.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 1: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 2: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideConflictingTimings(): iterable
    {
        yield from [
            'after commit, then immediately' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->afterCommit(),
                static fn (PendingRecord $pending): PendingRecord => $pending->immediately(),
                'after_commit',
            ],
            'immediately, then transactional' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->immediately(),
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional(),
                'immediate',
            ],
            'after commit, then on another' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->afterCommit(),
                static fn (PendingRecord $pending): PendingRecord => $pending->afterCommit('other'),
                'after_commit',
            ],
            'transactional on one, then another' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional('a'),
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional('b'),
                'transactional',
            ],
            'transactional on one, then the default' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional('a'),
                static fn (PendingRecord $pending): PendingRecord => $pending->transactional(),
                'transactional',
            ],
        ];
    }

    /**
     * A second, different timing is refused, naming the first, which stays.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $first
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $second
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideConflictingTimings')]
    public function testASecondDifferentTimingIsALogicError(\Closure $first, \Closure $second, string $value): void
    {
        $pending  = $first(new PendingRecord);
        $snapshot = $pending->snapshot();

        try {
            $second($pending);
            self::fail('Expected the second timing to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame("A record has one timing, and this one is already `{$value}`.", $exception->getMessage());
        }

        self::assertEquals($snapshot, $pending->snapshot());
    }

    /**
     * A fail-closed record with no timing is written immediately.
     *
     * @return void
     */
    public function testFailClosedAloneResolvesToImmediately(): void
    {
        $snapshot = (new PendingRecord)->failClosed()->snapshot();

        self::assertSame(Timing::IMMEDIATE, $snapshot->timing);
        self::assertNull($snapshot->connection);
        self::assertTrue($snapshot->failClosed);
    }

    /**
     * A fail-closed record set to be written immediately keeps that timing, in
     * either order.
     *
     * @return void
     */
    public function testFailClosedKeepsAnImmediateTiming(): void
    {
        $before = (new PendingRecord)->failClosed()->immediately()->snapshot();
        $after  = (new PendingRecord)->immediately()->failClosed()->snapshot();

        self::assertSame([Timing::IMMEDIATE, true], [$before->timing, $before->failClosed]);
        self::assertSame([Timing::IMMEDIATE, true], [$after->timing, $after->failClosed]);
    }

    /**
     * A fail-closed record that is transactional stays transactional, in either
     * order.
     *
     * @return void
     */
    public function testFailClosedKeepsATransactionalTiming(): void
    {
        $before = (new PendingRecord)->failClosed()->transactional('business')->snapshot();
        $after  = (new PendingRecord)->transactional('business')->failClosed()->snapshot();

        self::assertSame([Timing::TRANSACTIONAL, 'business', true], [$before->timing, $before->connection, $before->failClosed]);
        self::assertSame([Timing::TRANSACTIONAL, 'business', true], [$after->timing, $after->connection, $after->failClosed]);
    }

    /**
     * A fail-closed record is never written after commit, whichever is called
     * first, and the refusal leaves the record as it was.
     *
     * @return void
     */
    public function testFailClosedAfterCommitIsALogicError(): void
    {
        $failClosed  = (new PendingRecord)->failClosed();
        $afterCommit = (new PendingRecord)->afterCommit('business');

        foreach ([static fn (): PendingRecord => $failClosed->afterCommit(), static fn (): PendingRecord => $afterCommit->failClosed()] as $call) {
            try {
                $call();
                self::fail('Expected after commit and fail-closed to be refused together.');
            } catch (\LogicException $exception) {
                self::assertSame(self::FAIL_CLOSED, $exception->getMessage());
            }
        }

        self::assertSame([Timing::IMMEDIATE, true], [$failClosed->snapshot()->timing, $failClosed->snapshot()->failClosed]);
        self::assertSame([Timing::AFTER_COMMIT, false], [$afterCommit->snapshot()->timing, $afterCommit->snapshot()->failClosed]);
    }

    /**
     * Calling `failClosed()` again changes nothing.
     *
     * @return void
     */
    public function testFailClosedTwiceIsIdempotent(): void
    {
        $snapshot = (new PendingRecord)->failClosed()->failClosed()->snapshot();

        self::assertSame([Timing::IMMEDIATE, true], [$snapshot->timing, $snapshot->failClosed]);
    }

    /**
     * Rows of `[connection]`: names that are empty, too long or not clean.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedConnections(): iterable
    {
        yield from [
            'empty'               => [''],
            '65 characters'       => [str_repeat('c', 65)],
            'a trailing new line' => ["db\n"],
        ];
    }

    /**
     * Each refused connection name fails for both timings that take one, and
     * leaves the timing unset.
     *
     * @param  string  $connection
     * @return void
     */
    #[DataProvider('provideRefusedConnections')]
    public function testRefusesAnInvalidConnectionName(string $connection): void
    {
        $pending = new PendingRecord;

        foreach ([static fn (): PendingRecord => $pending->afterCommit($connection), static fn (): PendingRecord => $pending->transactional($connection)] as $call) {
            try {
                $call();
                self::fail('Expected the connection name to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A connection name must be from 1 to 64 characters, with no control characters.', $exception->getMessage());
            }
        }

        self::assertNull($pending->snapshot()->timing);
    }
}
