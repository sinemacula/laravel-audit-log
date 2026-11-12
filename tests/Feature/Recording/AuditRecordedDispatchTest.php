<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Events\CallQueuedListener;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\TestCase;

/**
 * End-to-end tests for when `AuditRecorded` is dispatched and what it carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRecorded::class)]
#[CoversClass(RecordDelivery::class)]
final class AuditRecordedDispatchTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code the tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The message of what a listener throws. */
    private const string LISTENER_FAILED = 'The listener failed.';

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditRecorded> The events a test's listener saw. */
    private array $events = [];

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A listener runs once the row exists.
     *
     * @return void
     */
    public function testDispatchedAfterAWrite(): void
    {
        $rowsWhenDispatched = [];

        Event::listen(AuditRecorded::class, function () use (&$rowsWhenDispatched): void {
            $rowsWhenDispatched[] = $this->entryCount();
        });

        AuditLog::record(self::CODE);

        self::assertSame([1], $rowsWhenDispatched);
    }

    /**
     * The event carries only the record's id, code and category.
     *
     * @return void
     */
    public function testCarriesOnlyTheIdCodeAndCategory(): void
    {
        $this->listen();

        $record = AuditLog::record(self::CODE, Reference::of('invoice', '42'), ['amount' => '1200.00']);

        self::assertCount(1, $this->events);

        $event = $this->events[0];

        self::assertSame($record->id, $event->id);
        self::assertSame(self::CODE, $event->code);
        self::assertSame($record->category, $event->category);

        $properties = (new \ReflectionObject($event))->getProperties();

        self::assertSame(['id', 'code', 'category'], array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $properties));
    }

    /**
     * A synchronous listener's failure is reported, and the row stands.
     *
     * @return void
     */
    public function testAThrowingListenerIsReportedAndTheRowExists(): void
    {
        Exceptions::fake();

        Event::listen(AuditRecorded::class, static function (): void {
            throw new \RuntimeException(self::LISTENER_FAILED);
        });

        AuditLog::record(self::CODE);

        Exceptions::assertReported(static fn (\RuntimeException $exception): bool => $exception->getMessage() === self::LISTENER_FAILED);

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A synchronous listener's failure never reaches the recording code.
     *
     * @return void
     */
    public function testAThrowingListenerNeverReachesTheCaller(): void
    {
        Exceptions::fake();

        Event::listen(AuditRecorded::class, static function (): void {
            throw new \RuntimeException(self::LISTENER_FAILED);
        });

        self::assertSame(self::CODE, AuditLog::record(self::CODE)->event);
    }

    /**
     * The event means accepted, not durable: it fires before a rollback.
     *
     * @return void
     */
    public function testDispatchedForAWriteLaterRolledBack(): void
    {
        $this->listen();

        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertCount(1, $this->events);

        $connection->rollBack();

        self::assertCount(1, $this->events);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An after-commit record dropped by a rollback dispatches nothing.
     *
     * @return void
     */
    public function testNotDispatchedForADroppedRecord(): void
    {
        $this->listen();

        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        AuditLog::record(self::CODE);

        $connection->rollBack();

        self::assertSame([], $this->events);
        self::assertSame(0, AuditEntry::query()->count());
    }

    /**
     * A failed write says nothing of a written record.
     *
     * @return void
     */
    public function testNotDispatchedForAFailedWrite(): void
    {
        $this->listen();

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        AuditLog::record(self::CODE);

        self::assertSame([], $this->events);
    }

    /**
     * A queued listener is queued as usual and does not run inside the write.
     *
     * @return void
     */
    public function testAQueuedListenerFollowsLaravelsHandling(): void
    {
        Queue::fake();

        $listener = new class implements ShouldQueue {
            /**
             * Fail, which a queued listener only does on the queue's own time.
             *
             * @return void
             *
             * @throws \RuntimeException
             */
            public function handle(): void
            {
                throw new \RuntimeException('The queued listener failed.');
            }
        };

        Event::listen(AuditRecorded::class, $listener::class);

        AuditLog::record(self::CODE);

        Queue::assertPushed(CallQueuedListener::class, static fn (CallQueuedListener $job): bool => $job->class === $listener::class);

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Collect every event in this test.
     *
     * @return void
     */
    private function listen(): void
    {
        Event::listen(AuditRecorded::class, function (AuditRecorded $event): void {
            $this->events[] = $event;
        });
    }
}
