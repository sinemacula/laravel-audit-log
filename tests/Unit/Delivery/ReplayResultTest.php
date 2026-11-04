<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * Unit tests for the tally of one replay: each outcome counted apart, a pruned
 * record among them, the bounded list of events and what an event may hold, how
 * a drain's tally maps across, and which outcomes make a replay unsuccessful.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReplayResult::class)]
final class ReplayResultTest extends TestCase
{
    /** @var string A record id in the one form every record id takes. */
    private const string ID = '019a4b2e-7c10-7000-8000-000000000001';

    /**
     * A new tally has counted nothing and listed nothing.
     *
     * @return void
     */
    public function testStartsAtZero(): void
    {
        $result = new ReplayResult;

        self::assertSame([0, 0, 0, 0, 0, []], self::tally($result));
        self::assertSame([], $result->events());
        self::assertSame(0, $result->omittedEvents());
        self::assertFalse($result->hasSkippedOrFailed());
    }

    /**
     * Each outcome counts under itself and no other, and each failure that
     * refused a line under its own value.
     *
     * @return void
     */
    public function testCountsEachOutcomeApart(): void
    {
        $result = new ReplayResult;

        $result->addReplayed('line 1', self::ID);
        $result->addReplayed('line 2', self::ID);
        $result->addWouldReplay('line 3', self::ID);
        $result->addPruned('line 8', self::ID);
        $result->addPruned('line 9', self::ID);
        $result->addPruned('line 10', self::ID);
        $result->addFailed('line 4', self::ID, \DomainException::class);
        $result->addSkipped('line 5', EnvelopeFailure::SIGNATURE_MISMATCH);
        $result->addSkipped('line 6', EnvelopeFailure::SIGNATURE_MISMATCH);
        $result->addSkipped('line 7', EnvelopeFailure::UNSIGNED);

        self::assertSame([2, 1, 3, 1, 0, ['signature_mismatch' => 2, 'unsigned' => 1]], self::tally($result));
    }

    /**
     * Each outcome lists an event, in order, naming where, what and which
     * record, and a failure's class.
     *
     * @return void
     */
    public function testListsWhatHappened(): void
    {
        $result = new ReplayResult;

        $result->addReplayed('line 1', self::ID);
        $result->addWouldReplay('outbox', self::ID);
        $result->addPruned('line 2', self::ID);
        $result->addFailed('line 3', self::ID, \DomainException::class);
        $result->addSkipped('line 4', EnvelopeFailure::UNSIGNED, self::ID);
        $result->addSkipped('line 5', EnvelopeFailure::TRUNCATED);

        self::assertSame([
            'line 1: replayed ' . self::ID,
            'outbox: would_replay ' . self::ID,
            'line 2: pruned ' . self::ID,
            'line 3: failed ' . self::ID . ' (DomainException)',
            'line 4: unsigned ' . self::ID,
            'line 5: truncated',
        ], $result->events());
    }

    /**
     * Rows of `[id]`: ids that are not a lower-case UUID, and so never reach an
     * event.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHostileIds(): iterable
    {
        yield from [
            'an escape sequence' => ["\e[31m" . self::ID],
            'a line break after' => [self::ID . "\n"],
            'upper case'         => [strtoupper(self::ID)],
            'empty'              => [''],
        ];
    }

    /**
     * An id that is not a lower-case UUID is left out of the event, and the
     * outcome is still counted.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideHostileIds')]
    public function testAHostileIdIsLeftOutOfTheEvent(string $id): void
    {
        $result = new ReplayResult;

        $result->addWouldReplay('outbox', $id);

        self::assertSame(['outbox: would_replay'], $result->events());
        self::assertSame(1, $result->wouldReplay());
    }

    /**
     * The list stops at its bound, keeping the oldest, and the rest are counted
     * and every outcome is still tallied.
     *
     * @return void
     */
    public function testTheEventsAreBounded(): void
    {
        $result = new ReplayResult;

        foreach (range(1, ReplayResult::MAX_EVENTS + 2) as $number) {
            $result->addReplayed('line ' . $number, self::ID);
        }

        self::assertSame(1000, ReplayResult::MAX_EVENTS);
        self::assertCount(ReplayResult::MAX_EVENTS, $result->events());
        self::assertSame('line 1: replayed ' . self::ID, $result->events()[0]);
        self::assertSame('line 1000: replayed ' . self::ID, $result->events()[999]);
        self::assertSame(2, $result->omittedEvents());
        self::assertSame(1002, $result->replayed());
    }

    /**
     * A drain's rows delivered are replayed; those whose record was pruned are
     * pruned; those failed, or released for a later attempt because a
     * destination failed again, were not delivered; and those another drain
     * took over or claimed first are that drain's. It lists no event, since it
     * does not say which row ended how.
     *
     * @return void
     */
    public function testMapsADrainAcross(): void
    {
        $drain = new DrainResult;

        $drain->addDelivered();
        $drain->addDelivered();
        $drain->addDelivered();
        $drain->addPruned();
        $drain->addPruned();
        $drain->addPruned();
        $drain->addPruned();
        $drain->addPruned();
        $drain->addPruned();
        $drain->addFailed();
        $drain->addRetried();
        $drain->addRetried();
        $drain->addStale();
        $drain->addMissed();
        $drain->addMissed();
        $drain->addMissed();
        $drain->addMissed();

        $result = new ReplayResult;

        $result->addReplayed('line 1', self::ID);
        $result->addFailed('line 2', self::ID, \DomainException::class);
        $result->addDrain($drain);

        self::assertSame([4, 0, 6, 4, 5, []], self::tally($result));
        self::assertCount(2, $result->events());

        $result->addDrain($drain);

        self::assertSame([7, 0, 12, 7, 10, []], self::tally($result));
    }

    /**
     * Only a skipped line or a failed record makes a replay unsuccessful: a
     * pruned record, counted on its own or by a drain, is complete.
     *
     * @return void
     */
    public function testHasSkippedOrFailedOnlyWithOne(): void
    {
        $counted = new ReplayResult;
        $drained = new DrainResult;

        $drained->addStale();
        $drained->addMissed();
        $drained->addPruned();

        $counted->addReplayed('line 1', self::ID);
        $counted->addWouldReplay('line 2', self::ID);
        $counted->addPruned('line 3', self::ID);
        $counted->addDrain($drained);

        $failed  = new ReplayResult;
        $skipped = new ReplayResult;

        $failed->addFailed('line 1', self::ID, \DomainException::class);
        $skipped->addSkipped('line 1', EnvelopeFailure::UNSIGNED);

        self::assertFalse($counted->hasSkippedOrFailed());
        self::assertTrue($failed->hasSkippedOrFailed());
        self::assertTrue($skipped->hasSkippedOrFailed());
    }

    /**
     * The tally's counts: replayed, would replay, pruned, failed, deferred and
     * skipped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return array{0: int, 1: int, 2: int, 3: int, 4: int, 5: array<string, int>}
     */
    private static function tally(ReplayResult $result): array
    {
        return [$result->replayed(), $result->wouldReplay(), $result->pruned(), $result->failed(), $result->deferred(), $result->skipped()];
    }
}
