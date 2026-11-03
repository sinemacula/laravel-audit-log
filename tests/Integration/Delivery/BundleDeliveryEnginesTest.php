<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Connection;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * Integration tests for bundles, records with their attachment, delivered on
 * the engine the suite runs against: an outbox row drained to one entry and one
 * artifact, whether the row was written inside the host's transaction on the
 * outbox connection or at the commit of one on another; a bundle a real failed
 * write spilled replays whole; two replays racing one bundle leave one entry
 * and one artifact; a drain killed between the store and the receipt
 * redelivers without a duplicate; a destination that keeps no attachments
 * keeps the row; and each receipt follows its destination's write. On SQLite,
 * MySQL and PostgreSQL alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryCoordinator::class)]
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(Replayer::class)]
final class BundleDeliveryEnginesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var int How far past a kill the clock moves, past the default lease, in seconds. */
    private const int PAST_THE_LEASE_SECONDS = 301;

    /** @var string The update that marks a receipt delivered. */
    private const string DELIVERED = '/^update \S*audit_log_deliveries\S* set \S*delivered_at/';

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The file each destination call is named in. */
    private const string CALLS = 'calls';

    /** @var string The file the racing child leaves its outcome in. */
    private const string OUTCOME = 'outcome';

    /** @var string The gate that starts the racing child. */
    private const string START = 'start';

    /** @var int How long the first replay holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second replay must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int The members of every bundle. */
    private const int MEMBERS = 3;

    /** @var list<string> What happened during a delivery, in order. */
    private array $steps = [];

    /**
     * Stop the clock and keep what a report would say out of the output.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Roll back any transaction a failed test left open, undo what the test
     * changed, put the clock back, and remove what the children shared once the
     * migrations have rolled back.
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

        $this->removeProbeTable();
        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A bundle written to the outbox, encrypted as its whole envelope, is
     * drained to one entry, which verifies, and one artifact, whose members
     * open to the manifest's canonical form; the row goes.
     *
     * @return void
     */
    public function testAnOutboxBundleIsDrainedWhole(): void
    {
        $this->outboxModeOn();

        $id = $this->deliverBundle(Timing::IMMEDIATE);

        $row = $this->outboxRow($id);

        self::assertIsArray($row);
        self::assertStringNotContainsString(RecordFactory::MEMBER_TYPE, (string) $row['payload']);
        self::assertSame(EnvelopeCodec::BUNDLE_VERSION, self::bundleVersionIn((string) $row['payload']));

        self::assertSame(1, $this->drain()->delivered());

        $this->assertStoredWhole($id);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A bundle written inside the host's transaction on the outbox connection
     * goes with it: a rollback leaves no row, and a commit keeps the row, which
     * is then drained whole.
     *
     * @return void
     */
    public function testAnOutboxBundleOnTheOutboxConnectionCommitsWithTheHost(): void
    {
        $this->outboxModeOn();

        $host = $this->outboxConnection();

        $host->beginTransaction();

        $this->deliverBundle(Timing::AFTER_COMMIT);

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->beginTransaction();

        $id = $this->deliverBundle(Timing::AFTER_COMMIT);

        self::assertSame(1, $this->outboxCount());

        $host->commit();

        self::assertSame(1, $this->outboxCount());
        self::assertSame(1, $this->drain()->delivered());

        $this->assertStoredWhole($id);
    }

    /**
     * With the outbox on a connection of its own, a bundle recorded inside a
     * host's transaction on another waits for its commit: no row while it is
     * open or once it rolls back, and a row once it commits, which is then
     * drained whole.
     *
     * @return void
     */
    public function testAnOutboxBundleOnAnotherConnectionWaitsForItsCommit(): void
    {
        $this->moveOutboxToItsOwnConnection();
        $this->giveTheMovedOutboxItsOwnFileOnSqlite();
        $this->outboxModeOn();

        $host = DB::connection(self::CONNECTION);

        $host->beginTransaction();

        $this->deliverBundle(Timing::AFTER_COMMIT);

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->beginTransaction();

        $id = $this->deliverBundle(Timing::AFTER_COMMIT);

        self::assertSame(0, $this->outboxCount());

        $host->commit();

        self::assertSame(1, $this->outboxCount());
        self::assertSame(1, $this->drain()->delivered());

        $this->assertStoredWhole($id);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A bundle whose write the engine really refused, its entry's insert
     * failing after its artifact's inside one transaction, leaves neither row
     * and one line in the documented channel's file, which replays to one entry
     * and one artifact; a second replay adds nothing.
     *
     * @return void
     */
    public function testASpilledBundleReplaysWhole(): void
    {
        $file = $this->spillToTheDocumentedChannel();

        $this->pointAtProbeTable();

        $id = $this->deliverBundle(Timing::IMMEDIATE);

        $this->removeProbeTable();

        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
        self::assertSame(1, substr_count((string) file_get_contents($file), FailureSpill::MARKER));

        self::assertSame([1, 0, []], self::tally($this->replay($file)));

        $this->assertStoredWhole($id);

        self::assertSame([1, 0, []], self::tally($this->replay($file)));
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
    }

    /**
     * Two replays of one spilled bundle race, each in a process and on a
     * connection of its own: the second's artifact insert waits on the first's
     * uncommitted artifact, or on SQLite on the file's one write lock, and,
     * once both of the first's rows are committed, finds the bundle stored
     * already, so both are replayed and one entry and one artifact are left.
     *
     * @return void
     */
    public function testTwoConcurrentReplaysOfOneBundleLeaveOneEntryAndOneArtifact(): void
    {
        $record = $this->finalisedRecord(RecordFactory::bundled(self::MEMBERS));
        $file   = $this->childFile('spill.log');

        file_put_contents($file, self::bundleLineOf($record) . "\n");

        $child = $this->startChild(function () use ($file): void {
            $this->awaitGate(self::START);

            $started = microtime(true);
            $result  = $this->replay($file);

            file_put_contents($this->childFile(self::OUTCOME), json_encode(['tally' => self::tally($result), 'waited' => microtime(true) - $started], JSON_THROW_ON_ERROR));
        });

        $storage = DB::connection(StorageConnection::name());

        $storage->beginTransaction();

        $first = $this->replay($file);

        $this->openGate(self::START);

        usleep(self::HOLD_MICROSECONDS);

        $storage->commit();

        $this->assertKilled($this->waitForChild($child));

        /** @var array{tally: array{0: int, 1: int, 2: array<string, int>}, waited: float} $second */
        $second = json_decode((string) file_get_contents($this->childFile(self::OUTCOME)), true, flags: JSON_THROW_ON_ERROR);

        self::assertSame([1, 0, []], self::tally($first));
        self::assertSame([1, 0, []], $second['tally']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $this->assertStoredWhole($record->record->id);
    }

    /**
     * A drain killed after a destination that joins no transaction stored the
     * bundle, both of its rows committed, and before its receipt was marked
     * delivered, leaves the row and both rows; once the lease has passed the
     * next drain hands the destination the bundle again, which the database
     * finds stored already, so one entry and one artifact are left and the
     * receipt is delivered.
     *
     * @return void
     */
    public function testADrainKilledBetweenTheStoreAndTheReceiptRedeliversWithoutADuplicate(): void
    {
        $database = app(DatabaseAuditStore::class);

        $this->bindStore($this->storeKeepingAttachments(function (FinalisedRecord $record) use ($database): void {
            $this->appendToChildFile(self::CALLS, 'database');

            $database->store($record);
        }));

        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled(self::MEMBERS)));

        $this->assertKilled($this->runChild(function (): void {
            $this->drain();
        }, self::DELIVERED));

        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
        self::assertNull($this->receipt($id, DeliveryCoordinator::STORE_DESTINATION)['delivered_at'] ?? null);

        $this->pastTheLease();

        self::assertSame(1, $this->drain()->delivered());

        $this->assertStoredWhole($id);
        self::assertSame(['database', 'database'], $this->childFileLines(self::CALLS));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(2, $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION)['attempts'] ?? null);
        self::assertNotNull($this->receipt($id, DeliveryCoordinator::STORE_DESTINATION)['delivered_at'] ?? null);
    }

    /**
     * A drain killed inside the transaction a database destination shares with
     * its receipt, after both inserts and before the receipt, leaves neither
     * row; the next drain stores the bundle once.
     *
     * @return void
     */
    public function testADrainKilledInsideTheSharedTransactionLeavesNeitherRow(): void
    {
        $this->bindStore(app(DatabaseAuditStore::class));

        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled(self::MEMBERS)));

        $this->assertKilled($this->runChild(function (): void {
            $this->drain();
        }, self::DELIVERED));

        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
        self::assertNotNull($this->outboxRow($id));

        $this->pastTheLease();

        self::assertSame(1, $this->drain()->delivered());

        $this->assertStoredWhole($id);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A stack whose log destination keeps no attachments keeps the bundle's
     * row: retried with the refusal's class while the database has both rows,
     * then failed and kept at its last attempt, the database never called
     * again; a replay to the database alone then removes it.
     *
     * @return void
     */
    public function testADrainToAStoreKeepingNoAttachmentsKeepsTheRow(): void
    {
        $this->bindStore(new StackAuditStore([
            'database' => app(DatabaseAuditStore::class),
            'log'      => new LogAuditStore(app(LogManager::class), new NdjsonFormatter, 'null'),
        ]));

        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled(self::MEMBERS)));

        self::assertSame(1, $this->drain()->retried());
        self::assertSame(\LogicException::class, $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame(\LogicException::class, $this->receipt($id, 'log')['last_error_class'] ?? null);
        self::assertNotNull($this->receipt($id, 'database')['delivered_at'] ?? null);

        $this->outboxConnection()->table(DeliveryTables::outboxTable())->where('id', $id)->update(['attempts' => 9]);
        $this->pastTheLease();

        $result = $this->drain();
        $row    = $this->outboxRow($id);

        self::assertSame(1, $result->failed());
        self::assertIsArray($row);
        self::assertNotNull($row['failed_at']);
        self::assertSame(1, $this->receipt($id, 'database')['attempts'] ?? null);
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());

        $this->bindStore(new StackAuditStore(['database' => app(DatabaseAuditStore::class)]));

        self::assertSame(1, app(Replayer::class)->outbox(false)->replayed());

        $this->assertStoredWhole($id);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Each destination's receipt is marked delivered only after its own write:
     * the database's after its artifact and its entry, which its transaction
     * holds when the receipt is written, and the next destination's after it
     * was handed the bundle.
     *
     * @return void
     */
    public function testReceiptsFollowEachDestinationsWrite(): void
    {
        $held  = null;
        $other = $this->storeKeepingAttachments(function (): void {
            $this->steps[] = 'call other';
        });

        $this->bindStore(new StackAuditStore(['database' => app(DatabaseAuditStore::class), 'other' => $other]));

        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled(self::MEMBERS)));

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query, array $bindings, Connection $connection) use ($id, &$held): void {
            $step = self::stepOf($query, $bindings);

            if ($step === null) {
                return;
            }

            $this->steps[] = $step;

            if ($step !== 'delivered database') {
                return;
            }

            $held = [self::rawCount($connection, EntrySettings::table(), 'id', $id), self::rawCount($connection, EntrySettings::artifactsTable(), 'entry_id', $id)];
        });

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(['insert artifact', 'insert entry', 'delivered database', 'call other', 'delivered other'], $this->steps);
        self::assertSame([1, 1], $held);

        $this->assertStoredWhole($id);
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
     * Deliver a bulk record as the recorder does, with the timing given and no
     * connection named, and give back its id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @return string
     */
    private function deliverBundle(Timing $timing): string
    {
        $record = RecordFactory::bundled(self::MEMBERS);

        app(RecordDelivery::class)->deliver($record, $timing, null);

        return $record->id;
    }

    /**
     * Assert the bundle is stored whole and once: one entry, which verifies,
     * and one artifact under it, whose members open to the canonical form of
     * the bundle's members.
     *
     * @param  string  $id
     * @return void
     */
    private function assertStoredWhole(string $id): void
    {
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($id)));

        $artifact = $this->storageConnection()->table(EntrySettings::artifactsTable())->where('entry_id', $id)->first();

        self::assertNotNull($artifact, "The entry {$id} has no artifact.");

        $members = array_map(static fn (int $member): array => [RecordFactory::MEMBER_TYPE, (string) $member], range(1, self::MEMBERS));

        self::assertSame(self::MEMBERS, (int) $artifact->member_count);
        self::assertSame(json_encode($members, Manifest::JSON_FLAGS), app(StringEncrypter::class)->decryptString((string) $artifact->members));
    }

    /**
     * The rows of the artifacts table.
     *
     * @return int
     */
    private function artifactCount(): int
    {
        return $this->storageConnection()->table(EntrySettings::artifactsTable())->count();
    }

    /**
     * A store that keeps attachments and joins no transaction, handing each
     * record to the work given.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\FinalisedRecord): void  $work
     * @return \SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments
     */
    private function storeKeepingAttachments(\Closure $work): AcceptsAttachments
    {
        return new readonly class ($work) implements AcceptsAttachments {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\FinalisedRecord): void  $work
             */
            public function __construct(

                /** What each record is handed to. */
                private \Closure $work,
            ) {}

            /**
             * Hand the record to the work.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                ($this->work)($record);
            }

            /**
             * Keep every attachment.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return true;
            }
        };
    }

    /**
     * Spill to the documented channel, in a file of the test's own, and give
     * back its path.
     *
     * @return string
     */
    private function spillToTheDocumentedChannel(): string
    {
        $file = $this->childFile('spill.log');

        touch($file);

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($file),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);

        return $file;
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
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * Replay the spill file with the replayer the container builds.
     *
     * @param  string  $file
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     */
    private function replay(string $file): ReplayResult
    {
        return app(Replayer::class)->spill($file, false);
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

    /**
     * The tally's counts: replayed, failed and skipped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return array{0: int, 1: int, 2: array<string, int>}
     */
    private static function tally(ReplayResult $result): array
    {
        return [$result->replayed(), $result->failed(), $result->skipped()];
    }

    /**
     * The spill line of the finalised bulk record: its whole bundle.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    private static function bundleLineOf(FinalisedRecord $record): string
    {
        return FailureSpill::line(EnvelopeCodec::envelopeOf($record));
    }

    /**
     * The bundle version of the envelope an outbox payload holds, decrypted and
     * decoded, or `null` when it holds none.
     *
     * @param  string  $payload
     * @return ?int
     */
    private static function bundleVersionIn(string $payload): ?int
    {
        $envelope = json_decode(app(StringEncrypter::class)->decryptString($payload), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($envelope);

        $version = $envelope['bundle_version'] ?? null;

        return is_int($version) ? $version : null;
    }

    /**
     * What the statement does to a bundle's delivery: inserts its artifact,
     * inserts its entry, or marks a destination's receipt delivered, by the
     * destination's name; otherwise nothing.
     *
     * @param  string  $query
     * @param  array<int, int|string|null>  $bindings
     * @return ?string
     */
    private static function stepOf(string $query, array $bindings): ?string
    {
        if (preg_match(self::DELIVERED, $query) === 1) {
            return 'delivered ' . (in_array('database', $bindings, true) ? 'database' : 'other');
        }

        if (!str_starts_with($query, 'insert into ')) {
            return null;
        }

        return match (true) {
            str_contains($query, EntrySettings::artifactsTable()) => 'insert artifact',
            str_contains($query, EntrySettings::table())          => 'insert entry',
            default                                               => null,
        };
    }

    /**
     * The rows of the table whose column holds the id, counted over the
     * connection's own PDO, so the count is seen inside its open transaction
     * and is not itself a statement the connection reports.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $column
     * @param  string  $id
     * @return int
     */
    private static function rawCount(Connection $connection, string $table, string $column, string $id): int
    {
        $grammar   = $connection->getQueryGrammar();
        $statement = $connection->getPdo()->prepare(sprintf('select count(*) from %s where %s = ?', $grammar->wrapTable($table), $grammar->wrap($column)));

        $statement->execute([$id]);

        return (int) $statement->fetchColumn();
    }
}
