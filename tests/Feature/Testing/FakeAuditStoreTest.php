<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Container\Container;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\Enums\StubNumberedActivity;

/**
 * Feature tests for the audit store tests bind in place of the database store:
 * how it is bound, what it holds and gives back, that a failing one throws and
 * holds nothing, and that it says it is durable and joins any transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeAuditStore::class)]
final class FakeAuditStoreTest extends TestCase
{
    use InteractsWithAuditStore;

    /**
     * `fake()` binds a fresh instance on the application each time, and returns
     * it.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeOnTheApplication(): void
    {
        $first = FakeAuditStore::fake();

        self::assertSame($first, app(AuditStore::class));

        $second = FakeAuditStore::fake();

        self::assertNotSame($first, $second);
        self::assertSame($second, app(AuditStore::class));
    }

    /**
     * `fake()` and `failing()` bind on the container given, and leave the
     * application's store alone.
     *
     * @return void
     */
    public function testFakeBindsOnTheContainerGiven(): void
    {
        $application = FakeAuditStore::fake();
        $container   = new Container;
        $fake        = FakeAuditStore::fake($container);

        self::assertSame($fake, $container->make(AuditStore::class));
        self::assertSame($application, app(AuditStore::class));

        $failing = FakeAuditStore::failing(new \RuntimeException('The store is down.'), $container);

        self::assertSame($failing, $container->make(AuditStore::class));
        self::assertSame($application, app(AuditStore::class));
    }

    /**
     * `failing()` binds on the application when no container is given.
     *
     * @return void
     */
    public function testFailingBindsOnTheApplication(): void
    {
        $failing = FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        self::assertSame($failing, app(AuditStore::class));
    }

    /**
     * Records come back as captured records, in the order they were stored.
     *
     * @return void
     */
    public function testRecordedListsOldestFirst(): void
    {
        $fake   = FakeAuditStore::fake();
        $first  = $this->finalised('invoice.sent');
        $second = $this->finalised('invoice.approved');

        $fake->store($first);
        $fake->store($second);

        self::assertSame([$first->record, $second->record], $fake->recorded());
    }

    /**
     * A filter keeps the records it accepts, as a list with no gaps.
     *
     * @return void
     */
    public function testRecordedFiltersWithTheClosure(): void
    {
        $fake   = FakeAuditStore::fake();
        $first  = $this->finalised('invoice.sent');
        $second = $this->finalised('invoice.approved');

        $fake->store($first);
        $fake->store($second);

        self::assertSame([$second->record], $fake->recorded(static fn (AuditRecord $record): bool => $record->event === 'invoice.approved'));
    }

    /**
     * `finalised()` gives back the very records the store received.
     *
     * @return void
     */
    public function testFinalisedGivesWhatTheStoreReceived(): void
    {
        $fake   = FakeAuditStore::fake();
        $first  = $this->finalised('invoice.sent');
        $second = $this->finalised('invoice.approved');

        $fake->store($first);
        $fake->store($second);

        self::assertSame([$first, $second], $fake->finalised());
    }

    /**
     * A code may be given as a string or as a string-backed enum case.
     *
     * @return void
     */
    public function testHasRecordedTakesAStringOrAnEnum(): void
    {
        $fake = FakeAuditStore::fake();

        $fake->store($this->finalised('invoice.approved'));

        self::assertTrue($fake->hasRecorded('invoice.approved'));
        self::assertTrue($fake->hasRecorded(StubActivity::APPROVED));
    }

    /**
     * Only a record of the code counts.
     *
     * @return void
     */
    public function testHasRecordedIsFalseForAnotherCode(): void
    {
        $fake = FakeAuditStore::fake();

        self::assertFalse($fake->hasRecorded('invoice.approved'));

        $fake->store($this->finalised('invoice.sent'));

        self::assertFalse($fake->hasRecorded('invoice.approved'));
    }

    /**
     * A code `event()` would refuse is refused here too, so a mistyped code
     * fails rather than reads as nothing recorded.
     *
     * @return void
     */
    public function testHasRecordedRefusesAnInvalidCode(): void
    {
        $fake = FakeAuditStore::fake();

        try {
            $fake->hasRecorded('Not A Code');

            self::fail('Expected the code to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('An event code must be lower-case dotted segments', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event code enum must be backed by strings.');

        $fake->hasRecorded(StubNumberedActivity::FIRST);
    }

    /**
     * `count()` counts every record stored.
     *
     * @return void
     */
    public function testCountCounts(): void
    {
        $fake = FakeAuditStore::fake();

        self::assertSame(0, $fake->count());

        $fake->store($this->finalised('invoice.sent'));
        $fake->store($this->finalised('invoice.approved'));

        self::assertSame(2, $fake->count());
    }

    /**
     * `forget()` clears every read, and the fake takes records again after it.
     *
     * @return void
     */
    public function testForgetForgets(): void
    {
        $fake = FakeAuditStore::fake();

        $fake->store($this->finalised('invoice.sent'));

        $fake->forget();

        self::assertSame([], $fake->recorded());
        self::assertSame([], $fake->finalised());
        self::assertSame(0, $fake->count());
        self::assertFalse($fake->hasRecorded('invoice.sent'));

        $fake->store($this->finalised('invoice.approved'));

        self::assertSame(1, $fake->count());
    }

    /**
     * A failing fake throws the very exception it was given.
     *
     * @return void
     */
    public function testFailingThrowsTheExceptionGiven(): void
    {
        $exception = new \RuntimeException('The store is down.');
        $fake      = FakeAuditStore::failing($exception);

        $this->expectExceptionObject($exception);

        $fake->store($this->finalised('invoice.approved'));
    }

    /**
     * A failing fake holds nothing of what it refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingFakeHoldsNothing(): void
    {
        $fake = FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            $fake->store($this->finalised('invoice.approved'));
        } catch (\RuntimeException) {
            // Another test pins the exception; only what is held counts here
        }

        self::assertSame(0, $fake->count());
        self::assertSame([], $fake->finalised());
    }

    /**
     * `forget()` clears records, not the failure.
     *
     * @return void
     */
    public function testForgetLeavesAFailureInForce(): void
    {
        $exception = new \RuntimeException('The store is down.');
        $fake      = FakeAuditStore::failing($exception);

        $fake->forget();

        $this->expectExceptionObject($exception);

        $fake->store($this->finalised('invoice.approved'));
    }

    /**
     * The fake says a return is durable, failing or not, so a fail-closed
     * record can be tested against it.
     *
     * @return void
     */
    public function testIsDurable(): void
    {
        self::assertInstanceOf(DurableAuditStore::class, FakeAuditStore::fake());
        self::assertTrue(FakeAuditStore::fake()->isDurable());
        self::assertTrue(FakeAuditStore::failing(new \RuntimeException('The store is down.'))->isDurable());
    }

    /**
     * Rows of `[connection]`: the storage connection, another and an empty
     * name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConnections(): iterable
    {
        yield from [
            'the storage connection' => [self::CONNECTION],
            'another'                => ['audit'],
            'an empty name'          => [''],
        ];
    }

    /**
     * The fake says it joins a transaction on any connection, so a
     * transactional record can be tested against it whatever its connection.
     *
     * @param  string  $connection
     * @return void
     */
    #[DataProvider('provideConnections')]
    public function testParticipatesInAnyConnection(string $connection): void
    {
        self::assertTrue(FakeAuditStore::fake()->participatesIn($connection));
        self::assertTrue(FakeAuditStore::failing(new \RuntimeException('The store is down.'))->participatesIn($connection));
    }

    /**
     * The fake is shipped and an application's production dependencies have no
     * PHPUnit, so it must not name it; only the assertions trait does.
     *
     * @return void
     */
    public function testUsesNoPhpUnit(): void
    {
        $source = file_get_contents(dirname(__DIR__, 3) . '/src/Testing/FakeAuditStore.php');

        self::assertIsString($source);
        self::assertStringNotContainsStringIgnoringCase('phpunit', $source);
    }

    /**
     * Binding, storing, reading and forgetting make no query.
     *
     * @return void
     */
    public function testMakesNoQuery(): void
    {
        $queries = 0;

        Event::listen(QueryExecuted::class, static function () use (&$queries): void {
            $queries++;
        });

        $fake = FakeAuditStore::fake();

        $fake->store($this->finalised('invoice.approved'));

        self::assertCount(1, $fake->recorded());
        self::assertCount(1, $fake->finalised());
        self::assertTrue($fake->hasRecorded('invoice.approved'));
        self::assertSame(1, $fake->count());

        $fake->forget();

        self::assertSame(0, $queries);
    }

    /**
     * A record of the code, finalised.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(string $code): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::withFields(['event' => $code]));
    }
}
