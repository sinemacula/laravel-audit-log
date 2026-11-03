<?php

declare(strict_types = 1);

namespace Tests\Integration\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelChangeDescriber;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Integration tests for when a watched model's change is written, on every
 * engine the suite runs on: only once the transaction it happened in commits on
 * the model's own connection, never when it rolls back, a nested rollback
 * taking only its own changes; each save with the snapshot and the actor of its
 * moment, built when the event fired; in outbox mode inside the transaction
 * when the outbox shares its connection; and a deferred write's failure said
 * once, at the commit, which stands.
 *
 * The test binds the watcher and the capture state as the provider does, and
 * watches its own models while the application boots.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelChangeDescriber::class)]
#[CoversClass(RecordModelChange::class)]
final class ModelChangeTimingTest extends TestCase
{
    use CapturesLogLines, CreatesWatchedModels, InteractsWithOutbox;

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Bind the reporter, capture the log lines and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Roll back any transaction a failed test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        parent::tearDown();
    }

    /**
     * A change inside a transaction is written when it commits, not before.
     *
     * @return void
     */
    public function testAChangeIsWrittenOnlyWhenItsTransactionCommits(): void
    {
        $connection = $this->models();

        $connection->beginTransaction();

        self::invoice();

        self::assertSame([], $this->entries());

        $connection->commit();

        self::assertSame([['invoice.created', ['amount' => 1250, 'number' => 'INV-1']]], $this->entries());
    }

    /**
     * A change rolled back is never written, and nothing of it waits.
     *
     * @return void
     */
    public function testARolledBackChangeIsNeverRecorded(): void
    {
        $connection = $this->models();

        $connection->beginTransaction();

        self::invoice()->update(['amount' => 990]);

        $connection->rollBack();

        $connection->beginTransaction();
        $connection->commit();

        self::assertSame([], $this->entries());
        self::assertSame(0, $connection->table(WatchedInvoice::TABLE)->count());
    }

    /**
     * A nested transaction rolled back takes its own changes, and the outermost
     * commit writes the rest.
     *
     * @return void
     */
    public function testANestedRollbackDropsOnlyItsChanges(): void
    {
        $connection = $this->models();

        $connection->beginTransaction();

        self::invoice();

        $connection->beginTransaction();

        self::invoice(['number' => 'INV-2']);

        $connection->rollBack();
        $connection->commit();

        self::assertSame([['invoice.created', ['amount' => 1250, 'number' => 'INV-1']]], $this->entries());
    }

    /**
     * A change on another connection waits for that connection to commit,
     * whatever the storage connection's transaction does.
     *
     * @return void
     */
    public function testAChangeOnAnotherConnectionWaitsForThatConnection(): void
    {
        $this->useSecondModelConnection();

        $other   = DB::connection(self::MODELS_CONNECTION);
        $storage = $this->models();

        $other->beginTransaction();
        $storage->beginTransaction();

        WatchedInvoice::on(self::MODELS_CONNECTION)->create(['number' => 'INV-1', 'amount' => 1250]);

        $storage->commit();

        self::assertSame([], $this->entries());

        $other->commit();

        self::assertSame([['invoice.created', ['amount' => 1250, 'number' => 'INV-1']]], $this->entries());
    }

    /**
     * Two saves before a commit are two records, each with the changes of its
     * own save.
     *
     * @return void
     */
    public function testTwoSavesBeforeCommitGiveTwoRecordsEachWithItsSnapshot(): void
    {
        $invoice    = self::invoice();
        $connection = $this->models();

        $connection->beginTransaction();

        $invoice->update(['amount' => 990]);
        $invoice->update(['amount' => 800]);

        $connection->commit();

        $updates = array_values(array_filter($this->entries(), static fn (array $entry): bool => $entry[0] === 'invoice.updated'));

        usort($updates, static fn (array $a, array $b): int => json_encode($b) <=> json_encode($a));

        self::assertSame([
            ['invoice.updated', ['changes' => ['amount' => ['after' => 990, 'before' => 1250]]]],
            ['invoice.updated', ['changes' => ['amount' => ['after' => 800, 'before' => 990]]]],
        ], $updates);
    }

    /**
     * The snapshot is taken when the event fires: a change made after the save
     * and before the commit is not in it.
     *
     * @return void
     */
    public function testTheSnapshotIsTakenAtTheEvent(): void
    {
        $connection = $this->models();

        $connection->beginTransaction();

        $invoice = self::invoice();

        $invoice->number = 'CHANGED';
        $invoice->amount = 1;

        $connection->commit();

        self::assertSame([['invoice.created', ['amount' => 1250, 'number' => 'INV-1']]], $this->entries());
    }

    /**
     * The actor is the guard's user when the change happened, not the one it
     * holds when the transaction commits.
     *
     * @return void
     */
    public function testTheActorIsTheOneAtTheChange(): void
    {
        $connection = $this->models();

        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 7]));

        $connection->beginTransaction();

        self::invoice();

        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 8]));

        $connection->commit();

        $row = $connection->table(EntrySettings::table())->first(['actor_type', 'actor_id']);

        self::assertSame([StubAuthUser::class, '7'], [$row->actor_type ?? null, $row->actor_id ?? null]);
    }

    /**
     * In outbox mode a change on the outbox's connection is inserted into the
     * outbox inside its transaction, so it commits and rolls back with it.
     *
     * @return void
     */
    public function testInOutboxModeAChangeOnTheOutboxConnectionIsInsertedInsideItsTransaction(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $connection = $this->outboxConnection();

        $connection->beginTransaction();

        self::invoice();

        self::assertSame(1, $this->outboxCount());

        $connection->rollBack();

        self::assertSame(0, $this->outboxCount());

        $connection->beginTransaction();

        self::invoice();

        $connection->commit();

        self::assertSame(1, $this->outboxCount());
        self::assertSame([], $this->entries());
        self::assertSame([], $this->failures);
    }

    /**
     * In outbox mode every change on the outbox's connection is inserted inside
     * its transaction, each in a savepoint of its own, which on PostgreSQL is a
     * subtransaction held until the transaction ends. More than 64 of them in
     * one transaction, past the point where PostgreSQL's snapshots overflow,
     * still give one outbox row each, leave the host at its own level, and
     * commit with it; the cost is the overflow the guides warn of, never a lost
     * or a failed record.
     *
     * @return void
     */
    public function testInOutboxModeManyChangesInOneTransactionAreEachInsertedInsideIt(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $connection = $this->outboxConnection();
        $invoice    = self::invoice();

        $connection->beginTransaction();

        for ($save = 1; $save <= 65; $save++) {
            $invoice->update(['amount' => $save]);
        }

        self::assertSame(1, $connection->transactionLevel());
        self::assertSame(66, $this->outboxCount());

        $connection->commit();

        self::assertSame(66, $this->outboxCount());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A deferred write that fails is said once, at the commit, naming the model
     * and the listener; it is reported and spilled once, and the commit stands.
     *
     * @return void
     */
    public function testADeferredWriteFailureIsSignalledAfterCommit(): void
    {
        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        $connection = $this->models();

        $connection->beginTransaction();

        self::invoice();

        self::assertSame(0, $this->failureCount());

        $connection->commit();

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(1, $connection->table(WatchedInvoice::TABLE)->count());
        self::assertSame(1, $this->failureCount());
        self::assertSame([WatchedInvoice::class, RecordModelChange::class], [$this->failures[0]->eventClass, $this->failures[0]->mapperClass]);
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A change committed on its own connection while a transaction is still
     * open on the storage connection is written at that commit, inside the
     * storage transaction. A deadlock of that write has ended the storage
     * transaction, yet the change it records has committed, so the record is
     * spilled once for replay, the sanitised deadlock reported once and said
     * once, and nothing leaves the commit.
     *
     * @return void
     */
    public function testADeferredDeadlockInsideAStorageTransactionIsSpilledAndReported(): void
    {
        $deadlock = new QueryException(self::CONNECTION, 'insert into entries values (?)', [], new \PDOException(self::DEADLOCK));

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith($deadlock));
        $this->useSecondModelConnection();

        $other   = DB::connection(self::MODELS_CONNECTION);
        $storage = $this->models();

        $storage->beginTransaction();
        $other->beginTransaction();

        WatchedInvoice::on(self::MODELS_CONNECTION)->create(['number' => 'INV-1', 'amount' => 1250]);

        $other->commit();

        self::assertSame(1, $other->table(WatchedInvoice::TABLE)->count());
        self::assertSame(1, $this->failureCount());
        self::assertSame([WatchedInvoice::class, RecordModelChange::class], [$this->failures[0]->eventClass, $this->failures[0]->mapperClass]);
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(DeadlockException::class, $this->reporter->reports()[0]);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Bind the watcher and the capture state as the provider does, and watch
     * the invoices while the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->singletonIf(ModelWatcher::class);
        app()->instance(MapperRegistry::class, new MapperRegistry);
        app()->scopedIf(CapturedEvents::class);

        app()->booting(static function (Application $app): void {
            $app->make(ModelWatcher::class)->watch(WatchedInvoice::class, 'invoice', ['number', 'amount']);
        });
    }

    /**
     * The entries written, each as its code and its properties with every map
     * sorted by key, since an engine may store a map's keys in its own order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return list<array{0: string, 1: array<array-key, mixed>}>
     */
    private function entries(): array
    {
        $entries = [];

        foreach ($this->models()->table(EntrySettings::table())->get(['event', 'properties']) as $row) {
            $properties = is_string($row->properties ?? null) ? json_decode($row->properties, true, 16, JSON_THROW_ON_ERROR) : null;

            $entries[] = [is_string($row->event ?? null) ? $row->event : '', is_array($properties) ? self::sorted($properties) : []];
        }

        return $entries;
    }

    /**
     * The map with its keys sorted, at every depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $map
     * @return array<array-key, mixed>
     */
    private static function sorted(array $map): array
    {
        ksort($map, SORT_STRING);

        return array_map(static fn (mixed $value): mixed => is_array($value) ? self::sorted($value) : $value, $map);
    }

    /**
     * How many `AuditCaptureFailed` events have been heard.
     *
     * @return int
     */
    private function failureCount(): int
    {
        return count($this->failures);
    }

    /**
     * The connection the invoices and the entries are on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function models(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * A saved invoice: the number and the amount, with the attributes given.
     *
     * @param  array<string, scalar|null>  $attributes
     * @return \Tests\Fixtures\Capture\Models\WatchedInvoice
     */
    private static function invoice(array $attributes = []): WatchedInvoice
    {
        return WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250, ...$attributes]);
    }
}
