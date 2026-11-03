<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for a worker killed by `SIGKILL` at every receipt and
 * delete boundary of a drain: each kill leaves exactly what the boundary says,
 * and once the lease has passed a later drain finishes the work, with one entry
 * row, no outbox row and every receipt delivered. A destination whose receipt
 * says it has the record is not called again, one whose receipt does not may be
 * (a log line can repeat), and a database destination's insert and receipt
 * share a transaction, so a kill between them leaves neither. A kill after the
 * delete loses only the `AuditRecorded` event. A record that kills every worker
 * that takes it is abandoned at its attempts and kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(DeliveryCoordinator::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(Receipts::class)]
final class DrainCrashBoundariesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var int How far past a kill the clock moves, past the default lease, in seconds. */
    private const int PAST_THE_LEASE_SECONDS = 301;

    /** @var string The claim: the one update of the outbox that counts an attempt. */
    private const string CLAIM = '/^update \S*audit_log_outbox\S* set \S*attempts/';

    /** @var string The update that releases a row for a retry. */
    private const string RETRY = '/^update \S*audit_log_outbox\S* set \S*available_at/';

    /** @var string The first attempt of any destination. */
    private const string ATTEMPT = '/^insert into \S*audit_log_deliveries/';

    /** @var string The first attempt of the log destination. */
    private const string LOG_ATTEMPT = '/^insert into \S*audit_log_deliveries.*\'log\'/';

    /** @var string The insert of the entry. */
    private const string ENTRY = '/^insert into \S*audit_log_entries/';

    /** @var string The update that marks a receipt delivered. */
    private const string DELIVERED = '/^update \S*audit_log_deliveries\S* set \S*delivered_at/';

    /** @var string The delete of the outbox row. */
    private const string DELETE = '/^delete from \S*outbox/';

    /** @var string The commit of the shared transaction, the first of a drain. */
    private const string COMMIT = '/^commit$/';

    /** @var string The file each destination call is named in. */
    private const string CALLS = 'calls';

    /** @var string The file each `AuditRecorded` is named in. */
    private const string RECORDED = 'recorded';

    /** @var string The log the log destination writes. */
    private const string LOG_FILE = 'destination.log';

    /** @var string The log destination's channel. */
    private const string LOG_CHANNEL = 'audit_destination';

    /**
     * Stop the clock, register the command, point the log destination at its
     * file, and name each `AuditRecorded` in a file, whichever process says it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new DrainCommand);

        app(ConfigRepository::class)->set('logging.channels.' . self::LOG_CHANNEL, [
            'driver' => 'single',
            'path'   => $this->childFile(self::LOG_FILE),
        ]);

        Event::listen(AuditRecorded::class, function (AuditRecorded $event): void {
            $this->appendToChildFile(self::RECORDED, $event->id);
        });
    }

    /**
     * Put the clock and the outbox back, and remove what the children shared
     * once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Rows of `[kill point, destinations, what the kill leaves, calls expected
     * of each destination by the end]`, one per boundary. A kill point is
     * before or after the statement its pattern matches. A lone destination is
     * the bound store itself, so its receipt is under `store`; two are a stack,
     * so their receipts are under their names.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: array{before?: string, after?: string}, 1: list<string>, 2: array{row: bool, entries: int, receipts: array<string, array{0: int, 1: bool}>, calls: array<string, int>}, 3: array<string, int>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideBoundaries(): iterable
    {
        $bothDelivered = ['database' => [1, true], 'log' => [1, true]];
        $bothCalled    = ['database' => 1, 'log' => 1];

        yield from [
            'after the claim' => [
                ['after' => self::CLAIM],
                ['database'],
                ['row' => true, 'entries' => 0, 'receipts' => [], 'calls' => []],
                ['database' => 1],
            ],
            'before the first attempt is recorded' => [
                ['before' => self::ATTEMPT],
                ['database'],
                ['row' => true, 'entries' => 0, 'receipts' => [], 'calls' => []],
                ['database' => 1],
            ],
            'attempt recorded, before the store' => [
                ['after' => self::ATTEMPT],
                ['database'],
                ['row' => true, 'entries' => 0, 'receipts' => ['store' => [1, false]], 'calls' => []],
                ['database' => 1],
            ],
            'database destination, insert done, receipt not' => [
                ['before' => self::DELIVERED],
                ['database'],
                ['row' => true, 'entries' => 0, 'receipts' => ['store' => [1, false]], 'calls' => ['database' => 1]],
                ['database' => 2],
            ],
            'database destination, committed' => [
                ['after' => self::COMMIT],
                ['database'],
                ['row' => true, 'entries' => 1, 'receipts' => ['store' => [1, true]], 'calls' => ['database' => 1]],
                ['database' => 1],
            ],
            'log destination, called, receipt not' => [
                ['before' => self::DELIVERED],
                ['log', 'database'],
                ['row' => true, 'entries' => 0, 'receipts' => ['log' => [1, false]], 'calls' => ['log' => 1]],
                ['log' => 2, 'database' => 1],
            ],
            'between two destinations' => [
                ['before' => self::LOG_ATTEMPT],
                ['database', 'log'],
                ['row' => true, 'entries' => 1, 'receipts' => ['database' => [1, true]], 'calls' => ['database' => 1]],
                $bothCalled,
            ],
            'after the last receipt, before the delete' => [
                ['before' => self::DELETE],
                ['database', 'log'],
                ['row' => true, 'entries' => 1, 'receipts' => $bothDelivered, 'calls' => $bothCalled],
                $bothCalled,
            ],
            'after the delete' => [
                ['after' => self::DELETE],
                ['database', 'log'],
                ['row' => false, 'entries' => 1, 'receipts' => $bothDelivered, 'calls' => $bothCalled],
                $bothCalled,
            ],
        ];
    }

    /**
     * A worker killed at the boundary leaves what the boundary says, and once
     * the clock has passed the lease a drain leaves one entry row, no outbox
     * row and every receipt delivered, having called each destination as often
     * as it says. `AuditRecorded` is said once, by whichever worker deleted the
     * row, unless the kill came after that delete, when it is lost.
     *
     * @param  array{before?: string, after?: string}  $kill
     * @param  list<string>  $destinations
     * @param  array{row: bool, entries: int, receipts: array<string, array{0: int, 1: bool}>, calls: array<string, int>}  $leaves
     * @param  array<string, int>  $calls
     * @return void
     */
    #[DataProvider('provideBoundaries')]
    public function testACrashAtEveryBoundaryRecovers(array $kill, array $destinations, array $leaves, array $calls): void
    {
        $this->bindDestinations($destinations);

        $id = $this->enqueue($this->finalisedRecord());

        $this->crash($kill);

        $this->assertLeaves($id, $leaves);

        $this->pastTheLease();

        self::assertSame(0, Artisan::call('audit-log:drain'));

        $this->assertRecovered($id);
        self::assertSame(self::sorted($calls), $this->calls());
        self::assertSame($this->calls()['log'] ?? 0, $this->logLines());
        self::assertSame($leaves['row'] ? [$id] : [], $this->childFileLines(self::RECORDED));
    }

    /**
     * Each worker killed after its attempt was recorded and before the store
     * counts on the row and on the receipt, and the drain that finishes counts
     * as one more.
     *
     * @return void
     */
    public function testAttemptsCountTheCrashedAttempt(): void
    {
        $this->bindDestinations(['database']);

        $id = $this->enqueue($this->finalisedRecord());

        $this->crash(['after' => self::ATTEMPT]);

        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame(1, $this->receipt($id, 'store')['attempts'] ?? null);

        $this->pastTheLease();

        // The receipt exists, so the attempt is an update of it this time
        $this->crash(['after' => '/^update \S*audit_log_deliveries\S* set \S*attempts/']);

        self::assertSame(2, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame(2, $this->receipt($id, 'store')['attempts'] ?? null);

        $this->pastTheLease();

        self::assertSame(0, Artisan::call('audit-log:drain'));

        self::assertSame(3, $this->receipt($id, 'store')['attempts'] ?? null);
        $this->assertRecovered($id);
    }

    /**
     * In the statements a drain runs, each destination's receipt is marked
     * delivered before the outbox row is deleted.
     *
     * @return void
     */
    public function testASuccessfulReceiptPrecedesTheDelete(): void
    {
        $this->bindDestinations(['database', 'log']);
        $this->enqueue($this->finalisedRecord());

        /** @var list<string> $statements */
        $statements = [];

        DB::listen(static function (QueryExecuted $event) use (&$statements): void {
            $statements[] = $event->sql;
        });

        $this->drain();

        $delivered = array_keys(array_filter($statements, static fn (string $statement): bool => preg_match(self::DELIVERED, $statement) === 1));
        $deleted   = array_keys(array_filter($statements, static fn (string $statement): bool => preg_match(self::DELETE, $statement) === 1));

        self::assertCount(2, $delivered);
        self::assertCount(1, $deleted);
        self::assertLessThan($deleted[0], max($delivered));
    }

    /**
     * A delivered receipt outlives its row, whether the delete was the last
     * thing the worker did or the drain ran to its end.
     *
     * @return void
     */
    public function testADeliveredReceiptIsNeverDeletedWithTheRow(): void
    {
        $this->bindDestinations(['database', 'log']);

        $killed = $this->enqueue($this->finalisedRecord());

        $this->crash(['after' => self::DELETE]);

        $drained = $this->enqueue($this->finalisedRecord());

        $this->drain();

        self::assertSame(0, $this->outboxCount());
        self::assertSame(['database' => [1, true], 'log' => [1, true]], $this->receiptsOf($killed));
        self::assertSame(['database' => [1, true], 'log' => [1, true]], $this->receiptsOf($drained));
    }

    /**
     * Kills at every boundary in turn, each on a record of its own, lose none:
     * in the end there is one entry for each and no row is left.
     *
     * @return void
     */
    public function testNoCrashLosesARecord(): void
    {
        $ids = [];

        foreach (self::provideBoundaries() as [$kill, $destinations]) {
            $this->bindDestinations($destinations);

            $ids[] = $this->enqueue($this->finalisedRecord());

            $this->crash($kill);

            $this->pastTheLease();

            self::assertSame(0, Artisan::call('audit-log:drain'));
        }

        self::assertCount(iterator_count(self::provideBoundaries()), array_unique($ids));
        self::assertSame(count($ids), $this->entryCount());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A record that kills every worker that takes it counts an attempt each
     * time. With two attempts allowed, the first two workers die calling the
     * store, and the third finds the row past its attempts and fails it as
     * abandoned without calling anything. The row is kept, the kill loop ends,
     * and no drain takes it again.
     *
     * @return void
     */
    public function testARecordKillingItsWorkerIsAbandonedAtItsAttempts(): void
    {
        $maxAttempts = 2;

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', $maxAttempts);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->bindDestinations(['database']);

        $id = $this->enqueue($this->finalisedRecord());

        foreach (range(1, $maxAttempts + 1) as $ignored) {
            $this->crash(['before' => self::ENTRY]);
            $this->pastTheLease();
        }

        $row = $this->outboxRow($id);

        self::assertSame($maxAttempts + 1, $row['attempts'] ?? null);
        self::assertSame('abandoned', $row['last_error_class'] ?? null);
        self::assertNotNull($row['failed_at'] ?? null);
        self::assertNull($row['claimed_by'] ?? null);
        self::assertSame(['database' => $maxAttempts], $this->calls());
        self::assertSame(0, $this->entryCount());

        $result = $this->drain();

        self::assertSame(0, $result->delivered() + $result->failed() + $result->missed());
        self::assertSame($maxAttempts + 1, $this->outboxRow($id)['attempts'] ?? null);
    }

    /**
     * A worker killed once its destination has failed and its receipt says so,
     * before its row is released for a retry, leaves the row claimed and due at
     * once when its lease has passed; the failure it left is cleared when the
     * destination delivers.
     *
     * @return void
     */
    public function testACrashBetweenAFailureAndItsRetryRecovers(): void
    {
        $parent   = posix_getpid();
        $database = $this->destination('database');

        $this->bindStore(new CallbackStore(static function (FinalisedRecord $record) use ($parent, $database): void {
            if (posix_getpid() !== $parent) {
                throw new \DomainException('Down.');
            }

            $database->store($record);
        }, participatesOn: [StorageConnection::resolvedName()]));

        $id = $this->enqueue($this->finalisedRecord());

        $this->crash(['before' => self::RETRY]);

        self::assertSame(\DomainException::class, $this->receipt($id, 'store')['last_error_class'] ?? null);
        self::assertNotNull($this->outboxRow($id)['claimed_by'] ?? null);
        self::assertSame(self::NOW, $this->outboxRow($id)['available_at'] ?? null);

        $this->pastTheLease();
        $this->drain();

        $receipt = $this->receipt($id, 'store');

        self::assertNotNull($receipt);
        self::assertNull($receipt['last_error_class']);
        $this->assertRecovered($id);
    }

    /**
     * The worker that recovers a row can be killed too: each kill counts, what
     * the last one left stays, and a third worker finishes without calling a
     * destination that has the record.
     *
     * @return void
     */
    public function testACrashDuringARecoveryRecovers(): void
    {
        $this->bindDestinations(['database', 'log']);

        $id = $this->enqueue($this->finalisedRecord());

        $this->crash(['before' => self::LOG_ATTEMPT]);
        $this->pastTheLease();
        $this->crash(['before' => self::DELETE]);

        self::assertSame(2, $this->outboxRow($id)['attempts'] ?? null);

        $this->pastTheLease();

        self::assertSame(0, Artisan::call('audit-log:drain'));

        $this->assertRecovered($id);
        self::assertSame(['database' => 1, 'log' => 1], $this->calls());
        self::assertSame([$id], $this->childFileLines(self::RECORDED));
    }

    /**
     * With the outbox on a connection of its own the delete cannot share the
     * entry's transaction: a kill before it leaves the entry and the delivered
     * receipt on the storage connection and the row on the other, and a drain
     * deletes the row without calling the store again.
     *
     * @return void
     */
    public function testACrashWithTheOutboxOnItsOwnConnectionRecovers(): void
    {
        $this->moveOutboxToItsOwnConnection();
        $this->giveTheMovedOutboxItsOwnFileOnSqlite();
        $this->bindDestinations(['database']);

        $id = $this->enqueue($this->finalisedRecord());

        $this->crash(['before' => self::DELETE]);

        $this->assertLeaves($id, ['row' => true, 'entries' => 1, 'receipts' => ['store' => [1, true]], 'calls' => ['database' => 1]]);

        $this->pastTheLease();
        $this->drain();

        $this->assertRecovered($id);
        self::assertSame(['database' => 1], $this->calls());
    }

    /**
     * Put the database on a file SQLite can share across a fork.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }

    /**
     * On SQLite, move the moved outbox on again, to a file of its own. Two
     * connections to one file share its one write lock, so a renewal on the
     * outbox connection, inside the transaction the storage connection holds,
     * would wait on itself; a separate database server has no such lock.
     *
     * @return void
     */
    private function giveTheMovedOutboxItsOwnFileOnSqlite(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            return;
        }

        $path = $this->childFile('outbox.sqlite');

        touch($path);

        app(ConfigRepository::class)->set('database.connections.' . self::MOVED_OUTBOX_CONNECTION . '.database', $path);

        DB::purge(self::MOVED_OUTBOX_CONNECTION);

        self::runMigration(self::OUTBOX_MIGRATION);
    }

    /**
     * Run a drain in a child killed at the point given, and assert it was.
     *
     * @param  array{before?: string, after?: string}  $kill
     * @return void
     */
    private function crash(array $kill): void
    {
        $this->assertKilled($this->runChild(function (): void {
            $this->drain();
        }, $kill['before'] ?? null, $kill['after'] ?? null));
    }

    /**
     * Assert the row, the entries, the receipts and the destination calls are
     * what a kill at the boundary leaves. A row left behind has the one attempt
     * of its one worker and that worker's claim, which nothing released.
     *
     * @param  string  $id
     * @param  array{row: bool, entries: int, receipts: array<string, array{0: int, 1: bool}>, calls: array<string, int>}  $leaves
     * @return void
     */
    private function assertLeaves(string $id, array $leaves): void
    {
        $row = $this->outboxRow($id);

        if ($leaves['row']) {
            self::assertNotNull($row);
            self::assertSame(1, $row['attempts']);
            self::assertNotNull($row['claimed_by']);
        } else {
            self::assertNull($row);
        }

        self::assertSame($leaves['entries'], $this->entryCount());
        self::assertSame(self::sorted($leaves['receipts']), $this->receiptsOf($id));
        self::assertSame(self::sorted($leaves['calls']), $this->calls());
    }

    /**
     * Assert the record is safe: one entry row, no outbox row, and every
     * receipt it has delivered.
     *
     * @param  string  $id
     * @return void
     */
    private function assertRecovered(string $id): void
    {
        self::assertSame($id, $this->storedRow($id)['id']);
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());

        $receipts = $this->receiptsOf($id);

        self::assertNotSame([], $receipts);

        foreach ($receipts as $destination => [, $delivered]) {
            self::assertTrue($delivered, "The receipt of {$destination} is not delivered.");
        }
    }

    /**
     * The attempts and the delivery of each receipt of the entry, by
     * destination.
     *
     * @param  string  $id
     * @return array<string, array{0: int, 1: bool}>
     */
    private function receiptsOf(string $id): array
    {
        $receipts = [];

        foreach (app(Receipts::class)->forEntry($id) as $destination => $receipt) {
            $receipts[$destination] = [$receipt->attempts, $receipt->delivered];
        }

        return self::sorted($receipts);
    }

    /**
     * How many times each destination was called, by name, whichever process
     * called it.
     *
     * @return array<string, int>
     */
    private function calls(): array
    {
        return self::sorted(array_count_values($this->childFileLines(self::CALLS)));
    }

    /**
     * How many lines the log destination has written.
     *
     * @return int
     */
    private function logLines(): int
    {
        return count(array_filter($this->childFileLines(self::LOG_FILE), static fn (string $line): bool => str_contains($line, LogAuditStore::MARKER)));
    }

    /**
     * The map in key order, so two are compared whatever order they were built
     * in.
     *
     * @template TValue
     *
     * @param  array<string, TValue>  $map
     * @return array<string, TValue>
     */
    private static function sorted(array $map): array
    {
        ksort($map);

        return $map;
    }

    /**
     * Bind the store the names describe: a lone destination as the store
     * itself, and more as a stack of them under their names.
     *
     * @param  list<string>  $names
     * @return void
     */
    private function bindDestinations(array $names): void
    {
        $destinations = [];

        foreach ($names as $name) {
            $destinations[$name] = $this->destination($name);
        }

        $this->bindStore(count($destinations) === 1 ? reset($destinations) : new StackAuditStore($destinations));
    }

    /**
     * The real store of the name, the database or a log on its own file, that
     * names each call in a file first, whichever process makes it, and says
     * what the real store says of itself.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private function destination(string $name): CallbackStore
    {
        $connection = StorageConnection::resolvedName();

        $store = $name === 'database'
            ? app(DatabaseAuditStore::class)
            : new LogAuditStore(app(LogManager::class), new NdjsonFormatter, self::LOG_CHANNEL);

        return new CallbackStore(function (FinalisedRecord $record) use ($name, $store): void {
            $this->appendToChildFile(self::CALLS, $name);

            $store->store($record);
        }, $store->isDurable(), $store->participatesIn($connection) ? [$connection] : []);
    }

    /**
     * Bind the store.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @return void
     */
    private function bindStore(AuditStore $store): void
    {
        app()->instance(AuditStore::class, $store);
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     *
     * @throws \LogicException
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * Move the clock past any lease taken so far.
     *
     * @return void
     */
    private function pastTheLease(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(self::PAST_THE_LEASE_SECONDS));
    }
}
