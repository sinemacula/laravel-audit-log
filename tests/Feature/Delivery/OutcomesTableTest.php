<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Querying\AccessRecorder;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for the outcomes note's guarantee table, one per row. Only the
 * aborted PostgreSQL host depends on the engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
#[CoversClass(OutboxWriter::class)]
#[CoversClass(FailureHandler::class)]
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(CaptureCoordinator::class)]
#[CoversClass(ReadGate::class)]
#[CoversClass(AccessRecorder::class)]
final class OutcomesTableTest extends TestCase
{
    use CapturesLogLines, CreatesWatchedModels, InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The code a record made inside a store has. */
    private const string INNER_CODE = 'invoice.voided';

    /** @var string A second connection a host transacts on. */
    private const string OTHER = 'audit_other';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The table holding the host's business data. */
    private const string INVOICES = 'outcome_invoices';

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string When a first retry falls due, by the default backoff. */
    private const string RETRY_DUE = '2026-11-01T12:01:00.000000Z';

    /** @var string An application key other than the one the tests start with. */
    private const string OTHER_APP_KEY = 'base64:b3RoZXIgYXBwbGljYXRpb24ga2V5IGZvciB0ZXN0cyE=';

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string A failure Laravel reads as a lost connection. */
    private const string LOST = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /** @var string A record with the default timing. */
    private const string AFTER_COMMIT = 'after commit';

    /** @var string A record asked to be written now. */
    private const string IMMEDIATELY = 'immediately';

    /** @var string A record asked to join the open transaction. */
    private const string TRANSACTIONAL = 'transactional';

    /** @var string A record asked to fail closed. */
    private const string FAIL_CLOSED = 'fail closed';

    /** @var string A record asked to fail closed, inside the open transaction. */
    private const string FAIL_CLOSED_TRANSACTIONAL = 'fail closed transactional';

    /** @var string The synchronous delivery mode. */
    private const string SYNC = 'sync';

    /** @var string The outbox delivery mode. */
    private const string OUTBOX = 'outbox';

    /** @var string The failure mode that lets the recording code go on. */
    private const string REPORT = 'report';

    /** @var string The failure mode that throws to the recording code. */
    private const string THROW = 'throw';

    /** @var string The note the table is in. */
    private const string NOTE = __DIR__ . '/../../../docs/design/outcomes.md';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> The failed writes said, in order. */
    private array $failures = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> The failed captures said, in order. */
    private array $captures = [];

    /** @var int How many times a written record was said. */
    private int $recorded = 0;

    /** @var list<string> The spill files a test wrote, to remove. */
    private array $files = [];

    /**
     * Bind the reporter, capture the spill lines, keep what is said, stop the
     * clock and create the table holding the host's business data.
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
        $this->moveClockTo(self::NOW);

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $event): void {
            $this->failures[] = $event;
        });

        Event::listen(AuditRecorded::class, function (): void {
            $this->recorded++;
        });

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $event): void {
            $this->captures[] = $event;
        });

        Schema::connection(self::CONNECTION)->create(self::INVOICES, static function (Blueprint $table): void {
            $table->string('number', 16);
        });
    }

    /**
     * Roll back any transaction a test left open, drop what it added, remove
     * its files and release the clock.
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
        $this->removeOutboxProbeTable();

        Schema::connection(self::CONNECTION)->dropIfExists(self::INVOICES);

        foreach ($this->files as $file) {
            @unlink($file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * `after-commit-sync-report`: written at the commit, dropped on rollback; a
     * failed write spills, reports and says it, and the commit stands.
     *
     * @return void
     */
    public function testRowAfterCommitSyncReport(): void
    {
        $this->assertWaitsForTheCommit($this->host(), entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();
        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome();

        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
        $this->assertOutcome(spills: 1, reports: 1, events: 1);
    }

    /**
     * `after-commit-sync-throw`: as above, but a failed write reports nothing
     * and throws from the commit, whose work has committed.
     *
     * @return void
     */
    public function testRowAfterCommitSyncThrow(): void
    {
        $this->failureMode(self::THROW);

        $this->assertWaitsForTheCommit($this->host(), entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();
        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome();

        self::assertSanitised($this->thrownBy(fn () => $this->host()->commit()));
        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(1, $this->businessRows());
        $this->assertOutcome(spills: 1, events: 1);
    }

    /**
     * `after-commit-none-open`: with no transaction open the record is written
     * now, or it is in the spill with a report and an event.
     *
     * @return void
     */
    public function testRowAfterCommitNoneOpen(): void
    {
        $record = $this->recordAs(self::AFTER_COMMIT);

        self::assertSame($record->id, $this->storedRow($record->id)['id']);
        $this->assertOutcome(entries: 1, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome(spills: 1, reports: 1, events: 1);
    }

    /**
     * `after-commit-outbox-same`: inserted now inside the selected transaction;
     * a failed insert is reported at once and its spill waits for the commit.
     *
     * @return void
     */
    public function testRowAfterCommitOutboxSame(): void
    {
        $this->outboxModeOn();

        $this->assertJoinsTheHost(self::AFTER_COMMIT, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();
        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome(reports: 1, events: 1);

        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
        $this->assertOutcome(spills: 1, reports: 1, events: 1);

        $this->startOver();

        $this->host()->beginTransaction();
        $this->recordAs(self::AFTER_COMMIT);
        $this->host()->rollBack();

        $this->assertOutcome(reports: 1, events: 1);
    }

    /**
     * `after-commit-outbox-same-throw`: written as above; a failed insert is
     * thrown now and its spill waits for the commit.
     *
     * @return void
     */
    public function testRowAfterCommitOutboxSameThrow(): void
    {
        $this->outboxModeOn();
        $this->failureMode(self::THROW);

        $this->assertJoinsTheHost(self::AFTER_COMMIT, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();

        self::assertSanitised($this->thrownBy(fn () => $this->recordAs(self::AFTER_COMMIT)));
        $this->assertOutcome(events: 1);

        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
        $this->assertOutcome(spills: 1, events: 1);

        $this->startOver();

        $this->host()->beginTransaction();

        self::assertSanitised($this->thrownBy(fn () => $this->recordAs(self::AFTER_COMMIT)));

        $this->host()->rollBack();

        $this->assertOutcome(events: 1);
    }

    /**
     * `after-commit-outbox-other`: waits in memory for the other connection's
     * commit; a failed insert spills, reports and says it.
     *
     * @return void
     */
    public function testRowAfterCommitOutboxOther(): void
    {
        $this->outboxModeOn();

        $other = DB::connection(self::OTHER);

        self::assertInstanceOf(Connection::class, $other);

        $this->assertWaitsForTheCommit($other, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        $other->beginTransaction();
        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome();

        $other->commit();

        self::assertSame(0, $other->transactionLevel());
        $this->assertOutcome(spills: 1, reports: 1, events: 1);
    }

    /**
     * `immediately-sync-report`: stored now; a failed write spills, reports and
     * says it at once, and the host stays usable.
     *
     * @return void
     */
    public function testRowImmediatelySyncReport(): void
    {
        $this->assertWrittenNowAndRolledBack(self::IMMEDIATELY, entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();
        $this->recordAs(self::IMMEDIATELY);

        $this->assertOutcome(spills: 1, reports: 1, events: 1);

        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
    }

    /**
     * `immediately-sync-throw`: a return means stored; a failed write spills,
     * says it and throws, reporting nothing.
     *
     * @return void
     */
    public function testRowImmediatelySyncThrow(): void
    {
        $this->failureMode(self::THROW);

        $this->assertWrittenNowAndRolledBack(self::IMMEDIATELY, entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();
        $this->businessChange();

        self::assertSanitised($this->thrownBy(fn () => $this->recordAs(self::IMMEDIATELY)));
        $this->assertOutcome(spills: 1, events: 1);

        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
    }

    /**
     * `immediately-outbox`: a row now, rolled back with the host on the shared
     * connection, and a failed insert spills, reports and says it at once.
     *
     * @return void
     */
    public function testRowImmediatelyOutbox(): void
    {
        $this->outboxModeOn();

        $this->assertWrittenNowAndRolledBack(self::IMMEDIATELY, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        $this->recordAs(self::IMMEDIATELY);

        $this->assertOutcome(spills: 1, reports: 1, events: 1);
    }

    /**
     * Rows of `[failure mode]`: each way the failure mode can be set, for the
     * rows that hold under either.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailureModes(): iterable
    {
        yield from [
            'report' => [self::REPORT],
            'throw'  => [self::THROW],
        ];
    }

    /**
     * `transactional-sync`: stored inside the transaction; a failed write
     * throws with no spill and, uncaught, rolls the change back.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowTransactionalSync(string $mode): void
    {
        $this->failureMode($mode);

        $this->assertJoinsTheHost(self::TRANSACTIONAL, entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $this->assertThrowsAndSpillsNothing(self::TRANSACTIONAL);
    }

    /**
     * `transactional-outbox`: a row inside the transaction; a failed insert
     * throws with no spill and, uncaught, rolls the change back.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowTransactionalOutbox(string $mode): void
    {
        $this->outboxModeOn();
        $this->failureMode($mode);

        $this->assertJoinsTheHost(self::TRANSACTIONAL, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        $this->assertThrowsAndSpillsNothing(self::TRANSACTIONAL);
    }

    /**
     * `fail-closed-sync`: a return means stored now; a failed write spills,
     * says it and throws, reporting nothing.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowFailClosedSync(string $mode): void
    {
        $this->failureMode($mode);

        $this->assertWrittenNowAndRolledBack(self::FAIL_CLOSED, entries: 1, outbox: 0, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        self::assertSanitised($this->thrownBy(fn () => $this->recordAs(self::FAIL_CLOSED)));
        $this->assertOutcome(spills: 1, events: 1);
    }

    /**
     * `fail-closed-outbox`: a return means a row written now; a failed insert
     * spills, says it and throws, reporting nothing.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowFailClosedOutbox(string $mode): void
    {
        $this->outboxModeOn();
        $this->failureMode($mode);

        $this->assertWrittenNowAndRolledBack(self::FAIL_CLOSED, entries: 0, outbox: 1, recorded: 0);

        $this->startOver();
        $this->pointOutboxAtProbeTable();

        self::assertSanitised($this->thrownBy(fn () => $this->recordAs(self::FAIL_CLOSED)));
        $this->assertOutcome(spills: 1, events: 1);
    }

    /**
     * Rows of `[delivery mode, failure mode]`: every pairing.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideDeliveryAndFailureModes(): iterable
    {
        yield from [
            'sync, report'   => [self::SYNC, self::REPORT],
            'sync, throw'    => [self::SYNC, self::THROW],
            'outbox, report' => [self::OUTBOX, self::REPORT],
            'outbox, throw'  => [self::OUTBOX, self::THROW],
        ];
    }

    /**
     * `fail-closed-transactional`: stays transactional in every mode, so a
     * failed write throws and leaves no spill.
     *
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideDeliveryAndFailureModes')]
    public function testRowFailClosedTransactional(string $delivery, string $mode): void
    {
        $outbox = $delivery === self::OUTBOX;

        if ($outbox) {
            $this->outboxModeOn();
        }

        $this->failureMode($mode);

        $this->assertJoinsTheHost(self::FAIL_CLOSED_TRANSACTIONAL, entries: $outbox ? 0 : 1, outbox: $outbox ? 1 : 0, recorded: $outbox ? 0 : 1);

        $this->startOver();

        $outbox ? $this->pointOutboxAtProbeTable() : $this->pointAtProbeTable();

        $this->assertThrowsAndSpillsNothing(self::FAIL_CLOSED_TRANSACTIONAL);
    }

    /**
     * Rows of `[how it is recorded, delivery mode, failure mode]`: each way a
     * record is written while the host's transaction is open.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideWritesInsideAHost(): iterable
    {
        yield from [
            'after commit, outbox, report'  => [self::AFTER_COMMIT, self::OUTBOX, self::REPORT],
            'after commit, outbox, throw'   => [self::AFTER_COMMIT, self::OUTBOX, self::THROW],
            'immediately, sync, report'     => [self::IMMEDIATELY, self::SYNC, self::REPORT],
            'immediately, sync, throw'      => [self::IMMEDIATELY, self::SYNC, self::THROW],
            'immediately, outbox, report'   => [self::IMMEDIATELY, self::OUTBOX, self::REPORT],
            'transactional, sync, report'   => [self::TRANSACTIONAL, self::SYNC, self::REPORT],
            'transactional, outbox, report' => [self::TRANSACTIONAL, self::OUTBOX, self::REPORT],
            'fail closed, sync, report'     => [self::FAIL_CLOSED, self::SYNC, self::REPORT],
            'fail closed, outbox, report'   => [self::FAIL_CLOSED, self::OUTBOX, self::REPORT],
        ];
    }

    /**
     * `host-deadlock`: a deadlock inside the host's transaction is said, never
     * spilled or reported, and escapes as `DeadlockException`.
     *
     * @param  string  $how
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWritesInsideAHost')]
    public function testRowHostDeadlock(string $how, string $delivery, string $mode): void
    {
        $thrown = $this->thrownByAFatalWrite($how, $delivery, $mode, self::DEADLOCK, '40001', 1213);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertNull($thrown->getPrevious());
        self::assertSame(0, $this->businessRows());
        self::assertSame(0, $this->host()->transactionLevel());
        $this->assertOutcome(events: 1);
    }

    /**
     * `host-connection-lost`: a lost connection inside the host's transaction
     * is said, never spilled or reported, and escapes sanitised.
     *
     * @param  string  $how
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWritesInsideAHost')]
    public function testRowHostConnectionLost(string $how, string $delivery, string $mode): void
    {
        $thrown = $this->thrownByAFatalWrite($how, $delivery, $mode, self::LOST, 'HY000', 2006);

        self::assertSanitised($thrown);
        self::assertSame(0, $this->businessRows());
        self::assertSame(0, $this->host()->transactionLevel());
        $this->assertOutcome(events: 1);
    }

    /**
     * `aborted-postgres-host`: an aborted PostgreSQL host refuses the write
     * without a fatal error; spill, report and event follow its rollback.
     *
     * @return void
     */
    public function testRowAbortedPostgresHost(): void
    {
        $host = $this->host();

        if ($host->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL leaves a transaction aborted by a failed statement.');
        }

        $host->beginTransaction();

        self::assertInstanceOf(QueryException::class, $this->thrownBy(static fn () => $host->statement('select * from audit_no_such_table')));

        $record = $this->recordAs(self::IMMEDIATELY);

        self::assertSame(self::CODE, $record->event);

        $host->rollBack();

        $this->assertOutcome(spills: 1, reports: 1, events: 1);
        self::assertSame('25P02', $this->firstReport()->sqlState);
    }

    /**
     * `failed-finalise`: a key ring that cannot sign leaves an unsigned spill,
     * a report and an event, and a replay skips that line.
     *
     * @return void
     */
    public function testRowFailedFinalise(): void
    {
        $config = app(ConfigRepository::class);
        $keys   = $config->get('audit-log.integrity.keys');

        $config->set('audit-log.integrity.keys', 'not a map');

        $this->forgetTheKeyRing();

        $record = $this->recordAs(self::IMMEDIATELY);

        self::assertSame(self::CODE, $record->event);
        $this->assertOutcome(spills: 1, reports: 1, events: 1);
        self::assertSame('finalise', $this->firstReport()->operation);

        $line = $this->spillLines()[0];

        self::assertStringContainsString('"unsigned":true', $line);
        self::assertStringNotContainsString('"hmac"', $line);

        $config->set('audit-log.integrity.keys', $keys);

        $this->forgetTheKeyRing();

        $result = app(Replayer::class)->spill($this->spillFile($line), false);

        self::assertSame(0, $result->replayed());
        self::assertSame(['unsigned' => 1], $result->skipped());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[how the inner record is made, delivery mode]`: each ordinary
     * timing, inside a store run by each delivery mode.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideOrdinaryRecordsInsideAStore(): iterable
    {
        yield from [
            'after commit, sync'   => [self::AFTER_COMMIT, self::SYNC],
            'after commit, outbox' => [self::AFTER_COMMIT, self::OUTBOX],
            'immediately, sync'    => [self::IMMEDIATELY, self::SYNC],
            'immediately, outbox'  => [self::IMMEDIATELY, self::OUTBOX],
        ];
    }

    /**
     * `inside-a-store`: a record made inside a store comes back unwritten, with
     * one `\LogicException` report, and the outer write goes on.
     *
     * @param  string  $how
     * @param  string  $delivery
     * @return void
     */
    #[DataProvider('provideOrdinaryRecordsInsideAStore')]
    public function testRowInsideAStore(string $how, string $delivery): void
    {
        $inner = [];

        $this->bindStore(new CallbackStore(function () use (&$inner, $how): void {
            $inner[] = $this->recordAs($how, self::INNER_CODE);
            $inner[] = $this->recordAs($how, self::INNER_CODE);
        }));

        $this->recordThroughTheStore($delivery);

        self::assertCount(2, $inner);
        self::assertSame(self::INNER_CODE, $inner[0]->event);
        self::assertSame(self::INNER_CODE, $inner[1]->event);
        $this->assertOutcome(reports: 1, recorded: 1);

        $report = $this->reporter->reports()[0];

        self::assertSame(\LogicException::class, $report::class);
        self::assertStringContainsString(self::INNER_CODE, $report->getMessage());
    }

    /**
     * Rows of `[how the inner record is made, delivery mode, failure mode]`:
     * each strict record, inside a store run by each delivery mode.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideStrictRecordsInsideAStore(): iterable
    {
        yield from [
            'fail closed, sync, report'     => [self::FAIL_CLOSED, self::SYNC, self::REPORT],
            'fail closed, sync, throw'      => [self::FAIL_CLOSED, self::SYNC, self::THROW],
            'fail closed, outbox, report'   => [self::FAIL_CLOSED, self::OUTBOX, self::REPORT],
            'transactional, sync, report'   => [self::TRANSACTIONAL, self::SYNC, self::REPORT],
            'transactional, sync, throw'    => [self::TRANSACTIONAL, self::SYNC, self::THROW],
            'transactional, outbox, report' => [self::TRANSACTIONAL, self::OUTBOX, self::REPORT],
        ];
    }

    /**
     * `inside-a-store-strict`: a strict record made inside a store does not
     * return: it is refused with a `\LogicException`, and nothing is reported.
     *
     * @param  string  $how
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideStrictRecordsInsideAStore')]
    public function testRowInsideAStoreStrict(string $how, string $delivery, string $mode): void
    {
        $this->failureMode($mode);

        $refused = null;

        $this->bindStore(new CallbackStore(function () use (&$refused, $how): void {
            $refused = $this->thrownBy(fn () => $this->recordAs($how, self::INNER_CODE));
        }));

        $this->recordThroughTheStore($delivery);

        self::assertInstanceOf(\Throwable::class, $refused);
        self::assertSame(\LogicException::class, $refused::class);
        self::assertStringContainsString('its guarantee cannot be met', $refused->getMessage());
        $this->assertOutcome(recorded: 1);
    }

    /**
     * `drain-transient`: a failed attempt keeps its error class and waits out
     * its backoff unreported, and a later attempt writes the record.
     *
     * @return void
     */
    public function testRowDrainTransient(): void
    {
        $this->outboxModeOn();
        $this->pointAtProbeTable();

        $id = $this->recordAs(self::AFTER_COMMIT)->id;

        self::assertSame(1, $this->drain()->retried());

        $row     = $this->outboxRow($id);
        $receipt = $this->receipt($id, 'store');

        self::assertIsArray($row);
        self::assertIsArray($receipt);
        self::assertSame(QueryException::class, $row['last_error_class']);
        self::assertSame(1, $row['attempts']);
        self::assertSame(self::RETRY_DUE, $row['available_at']);
        self::assertNull($row['failed_at']);
        self::assertSame(QueryException::class, $receipt['last_error_class']);
        self::assertNull($receipt['delivered_at']);
        $this->assertOutcome(outbox: 1);

        $this->removeProbeTable();

        self::assertSame(0, $this->drain()->delivered());

        $this->moveClockTo(self::RETRY_DUE);

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame($id, $this->storedRow($id)['id']);
        $this->assertOutcome(entries: 1, recorded: 1);
    }

    /**
     * `drain-final`: a failed last attempt fails the row and keeps it, with a
     * report and an event, and no later drain deletes it or tries it again.
     *
     * @return void
     */
    public function testRowDrainFinal(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $this->outboxModeOn();
        $this->pointAtProbeTable();

        $id = $this->recordAs(self::AFTER_COMMIT)->id;

        self::assertSame(1, $this->drain()->failed());

        $row = $this->outboxRow($id);

        self::assertIsArray($row);
        self::assertSame(self::NOW, $row['failed_at']);
        self::assertSame(QueryException::class, $row['last_error_class']);
        self::assertSame($id, $this->firstReport()->recordId);
        self::assertSame('drain', $this->firstReport()->operation);
        self::assertSame($id, $this->failures[0]->id);
        $this->assertOutcome(outbox: 1, reports: 1, events: 1);

        $this->removeProbeTable();
        $this->moveClockTo(self::RETRY_DUE);

        self::assertSame(0, $this->drain()->delivered());
        $this->assertOutcome(outbox: 1, reports: 1, events: 1);
    }

    /**
     * `drain-undecryptable`: a row whose key is gone is failed, kept as found
     * and reported by id alone; no later drain deletes it.
     *
     * @return void
     */
    public function testRowDrainUndecryptable(): void
    {
        $this->outboxModeOn();

        $id      = $this->recordAs(self::AFTER_COMMIT)->id;
        $payload = $this->outboxRow($id)['payload'] ?? null;

        app(ConfigRepository::class)->set(['app.key' => self::OTHER_APP_KEY, 'app.previous_keys' => []]);
        app()->forgetInstance('encrypter');

        self::assertSame(1, $this->drain()->failed());

        $row = $this->outboxRow($id);

        self::assertIsArray($row);
        self::assertSame(self::NOW, $row['failed_at']);
        self::assertSame('undecryptable', $row['last_error_class']);
        self::assertSame($payload, $row['payload']);
        self::assertSame($id, $this->firstReport()->recordId);
        self::assertNull($this->firstReport()->eventCode);
        $this->assertOutcome(outbox: 1, reports: 1);

        $this->moveClockTo(self::RETRY_DUE);

        self::assertSame(0, $this->drain()->delivered());
        $this->assertOutcome(outbox: 1, reports: 1);
    }

    /**
     * `captured-report`: written now inside the host; a failed write, even
     * under `throw`, is spilled, reported and said, and nothing escapes.
     *
     * @return void
     */
    public function testRowCapturedReport(): void
    {
        $this->failureMode(self::THROW);
        $this->mapPortalSignIns();

        $this->host()->beginTransaction();

        self::assertSame(PortalMapper::CODE, $this->capture()?->event);
        $this->assertOutcome(entries: 1, recorded: 1);

        $this->host()->rollBack();

        $this->assertOutcome(recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        self::assertNull($this->capture());
        $this->assertOutcome(spills: 1, reports: 1, events: 1, captures: 1);
        self::assertSame(PortalMapper::CODE, $this->firstReport()->eventCode);
        self::assertSame([PortalSignedIn::class, PortalMapper::class, QueryException::class], self::namesOf($this->captures[0]));
    }

    /**
     * Rows of `[failure message, SQLSTATE, driver code, what is thrown, failure
     * mode]`: each host-fatal failure under each mode.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int, 3: class-string<\Throwable>, 4: string}>
     */
    public static function provideCapturedHostFailures(): iterable
    {
        yield from [
            'a deadlock, report'        => [self::DEADLOCK, '40001', 1213, DeadlockException::class, self::REPORT],
            'a deadlock, throw'         => [self::DEADLOCK, '40001', 1213, DeadlockException::class, self::THROW],
            'a lost connection, report' => [self::LOST, 'HY000', 2006, AuditWriteFailedException::class, self::REPORT],
            'a lost connection, throw'  => [self::LOST, 'HY000', 2006, AuditWriteFailedException::class, self::THROW],
        ];
    }

    /**
     * `captured-host-fatal`: a capture's host-fatal failure is said, never
     * spilled or reported, and reaches the caller sanitised.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @param  class-string<\Throwable>  $thrownClass
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideCapturedHostFailures')]
    public function testRowCapturedHostFatal(string $message, string $state, int $code, string $thrownClass, string $mode): void
    {
        $this->failureMode($mode);
        $this->mapPortalSignIns();
        $this->breakWrites($message, $state, $code);

        $thrown = $this->thrownBy(fn () => $this->host()->transaction(function (): void {
            $this->businessChange();
            $this->capture();
        }));

        self::assertSame($thrownClass, $thrown::class);
        self::assertNull($thrown->getPrevious());
        self::assertSame(0, $this->businessRows());
        self::assertSame(0, $this->host()->transactionLevel());
        $this->assertOutcome(events: 1, captures: 1);
    }

    /**
     * `captured-model-after-commit`: a watched model's change is written at its
     * connection's commit; a failed write there is never thrown.
     *
     * @return void
     */
    public function testRowCapturedModelAfterCommit(): void
    {
        $this->failureMode(self::THROW);

        $host = $this->host();

        $host->beginTransaction();
        self::watchedInvoice();

        $this->assertOutcome();

        $host->rollBack();

        $this->assertOutcome();

        $host->beginTransaction();
        self::watchedInvoice();

        $this->assertOutcome();

        $host->commit();

        $this->assertOutcome(entries: 1, recorded: 1);

        $this->startOver();
        $this->pointAtProbeTable();

        $host->beginTransaction();
        self::watchedInvoice();
        $host->commit();

        self::assertSame(0, $host->transactionLevel());
        self::assertSame(2, $host->table(WatchedInvoice::TABLE)->count());
        $this->assertOutcome(spills: 1, reports: 1, events: 1, captures: 1);
        self::assertSame([WatchedInvoice::class, RecordModelChange::class, QueryException::class], self::namesOf($this->captures[0]));
    }

    /**
     * `read-sync`: the page is returned once the read's record is stored and
     * its `AuditRecorded` said.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowReadSync(string $mode): void
    {
        $this->failureMode($mode);
        $this->allowEveryViewer();

        $id = $this->recordAs(self::IMMEDIATELY)->id;

        self::assertSame([$id], self::idsOf($this->trail()->cursorPaginate()));
        self::assertSame([PackageActivity::TRAIL_READ->value], $this->readCodes());
        $this->assertOutcome(entries: 2, recorded: 2);
    }

    /**
     * `read-outbox`: the page is returned once the read's record is a committed
     * outbox row, said only once a drain runs.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testRowReadOutbox(string $mode): void
    {
        $this->failureMode($mode);
        $this->allowEveryViewer();

        $id = $this->recordAs(self::IMMEDIATELY)->id;

        $this->outboxModeOn();

        self::assertSame([$id], self::idsOf($this->trail()->cursorPaginate()));
        self::assertSame([], $this->readCodes());
        $this->assertOutcome(entries: 1, outbox: 1, recorded: 1);

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame([PackageActivity::TRAIL_READ->value], $this->readCodes());
        $this->assertOutcome(entries: 2, recorded: 2);
    }

    /**
     * Rows of `[delivery mode, failure mode]`: each delivery mode under each
     * failure mode, for the read rows that hold under any.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideReadModes(): iterable
    {
        yield from [
            'sync, report'   => [self::SYNC, self::REPORT],
            'sync, throw'    => [self::SYNC, self::THROW],
            'outbox, report' => [self::OUTBOX, self::REPORT],
            'outbox, throw'  => [self::OUTBOX, self::THROW],
        ];
    }

    /**
     * `read-open-transaction`: a read inside a transaction on the storage
     * connection is refused before anything is queried.
     *
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideReadModes')]
    public function testRowReadOpenTransaction(string $delivery, string $mode): void
    {
        $this->failureMode($mode);

        $policy = $this->allowEveryViewer();
        $id     = $this->recordAs(self::IMMEDIATELY)->id;

        if ($delivery === self::OUTBOX) {
            $this->outboxModeOn();
        }

        $this->host()->beginTransaction();

        $thrown = $this->thrownBy(fn () => $this->trail()->cursorPaginate());

        self::assertInstanceOf(AuditReadRefusedException::class, $thrown);
        self::assertSame(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), $thrown->getMessage());
        self::assertNull($thrown->getPrevious());
        self::assertSame([], $policy->asked());
        $this->assertOutcome(entries: 1, recorded: 1);

        $this->host()->rollBack();

        $other = DB::connection(self::OTHER);

        $other->beginTransaction();

        self::assertSame([$id], self::idsOf($this->trail()->cursorPaginate()));

        $other->rollBack();
    }

    /**
     * `read-failed-write`: a read whose record cannot be written is spilled,
     * said and reported once, and refused as unrecorded.
     *
     * @param  string  $delivery
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideReadModes')]
    public function testRowReadFailedWrite(string $delivery, string $mode): void
    {
        $this->failureMode($mode);
        $this->allowEveryViewer();
        $this->recordAs(self::IMMEDIATELY);

        if ($delivery === self::OUTBOX) {
            $this->outboxModeOn();
            $this->pointOutboxAtProbeTable();
        }

        if ($delivery === self::SYNC) {
            $this->pointAtProbeTable();
        }

        $thrown = $this->thrownBy(fn () => $this->trail()->cursorPaginate());

        self::assertInstanceOf(AuditReadRefusedException::class, $thrown);
        self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $thrown->getMessage());
        self::assertNull($thrown->getPrevious());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->firstReport());
        $this->assertOutcome(entries: $delivery === self::OUTBOX ? 1 : 0, spills: 1, reports: 1, events: 1, recorded: 1);
    }

    /**
     * Every row of the note's guarantee table has its test here, and every row
     * test has its row.
     *
     * @return void
     */
    public function testEveryRowOfTheTableHasATest(): void
    {
        preg_match_all('/^\| `([a-z-]+)` +\|/m', self::guarantees(), $rows);

        self::assertNotSame([], $rows[1]);

        $expected = array_map(static fn (string $id): string => 'testRow' . Str::studly($id), $rows[1]);
        $methods  = array_map(static fn (\ReflectionMethod $method): string => $method->getName(), (new \ReflectionClass(self::class))->getMethods());
        $actual   = array_values(array_filter($methods, static fn (string $method): bool => str_starts_with($method, 'testRow')));

        sort($expected);
        sort($actual);

        self::assertSame($expected, $actual);
    }

    /**
     * The table has the columns each row asserts, in order, and every row fills
     * each of them.
     *
     * @return void
     */
    public function testEveryRowOfTheTableHasEachColumn(): void
    {
        $columns = ['Row id', 'Timing', 'Mode', 'Policy', 'Written', 'On a failed write', 'On the host\'s rollback', '`record()` returning means'];
        $lines   = array_values(array_filter(explode("\n", self::guarantees()), static fn (string $line): bool => str_starts_with($line, '|')));

        self::assertSame($columns, self::cellsOf($lines[0]));

        foreach (array_slice($lines, 2) as $line) {
            $cells = self::cellsOf($line);

            self::assertCount(count($columns), $cells, $line);
            self::assertNotContains('', $cells, $line);
        }
    }

    /**
     * A deadlock at the host's commit, with nothing left open, ended no
     * transaction, so it follows the policy.
     *
     * @return void
     */
    public function testADeadlockAtACommitWithNothingOpenFollowsThePolicy(): void
    {
        $this->breakWrites(self::DEADLOCK, '40001', 1213);

        $this->host()->beginTransaction();
        $this->businessChange();
        $this->recordAs(self::AFTER_COMMIT);
        $this->host()->commit();

        self::assertSame(1, $this->businessRows());
        $this->assertOutcome(spills: 1, reports: 1, events: 1);
    }

    /**
     * An after-commit write at another connection's commit is inside a host
     * still open on the storage connection, so its deadlock escapes.
     *
     * @return void
     */
    public function testADeadlockAtAnotherCommitInsideAHostIsTheHosts(): void
    {
        $this->breakWrites(self::DEADLOCK, '40001', 1213);

        $other = DB::connection(self::OTHER);

        $this->host()->beginTransaction();
        $other->beginTransaction();
        $this->recordAs(self::AFTER_COMMIT);

        self::assertInstanceOf(DeadlockException::class, $this->thrownBy(static fn () => $other->commit()));
        $this->assertOutcome(events: 1);
    }

    /**
     * Rows of `[whether the host commits, spill lines once it has ended]`: each
     * way the host can end.
     *
     * @return iterable<string, array{0: bool, 1: int}>
     */
    public static function provideHostEndings(): iterable
    {
        yield from [
            'it commits'    => [true, 1],
            'it rolls back' => [false, 0],
        ];
    }

    /**
     * An after-commit record's spill waits for any transaction open on its
     * connection, written at its commit and never after its rollback.
     *
     * @param  bool  $commits
     * @param  int  $spills
     * @return void
     */
    #[DataProvider('provideHostEndings')]
    public function testAnAfterCommitSpillWaitsForATransactionStillOpenOnItsConnection(bool $commits, int $spills): void
    {
        $this->pointAtProbeTable();

        $other = DB::connection(self::OTHER);

        $this->host()->beginTransaction();
        $other->beginTransaction();
        $this->recordAs(self::AFTER_COMMIT);
        $other->commit();

        $this->assertOutcome(reports: 1, events: 1);

        $commits ? $this->host()->commit() : $this->host()->rollBack();

        $this->assertOutcome(spills: $spills, reports: 1, events: 1);
    }

    /**
     * Rows of `[how it is recorded, what the failure mode is]`: each way a
     * record's spill is written at once, inside a host.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSpillsWrittenAtOnce(): iterable
    {
        yield from [
            'immediately, report' => [self::IMMEDIATELY, self::REPORT],
            'immediately, throw'  => [self::IMMEDIATELY, self::THROW],
            'fail closed'         => [self::FAIL_CLOSED, self::REPORT],
        ];
    }

    /**
     * An immediate or fail-closed record's spill is written at once, so it
     * outlives an enclosing rollback as evidence of an attempt.
     *
     * @param  string  $how
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideSpillsWrittenAtOnce')]
    public function testASpillWrittenAtOnceOutlivesAnEnclosingRollback(string $how, string $mode): void
    {
        $this->failureMode($mode);
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        // The rule may throw it, and what stays behind is what this pins
        rescue(fn (): AuditRecord => $this->recordAs($how), report: false);

        self::assertCount(1, $this->spillLines());

        $this->host()->rollBack();

        self::assertCount(1, $this->spillLines());
    }

    /**
     * A strict record left uncaught inside a store is a failure of the write
     * around it, which then follows that write's own policy.
     *
     * @return void
     */
    public function testAStrictRecordLeftUncaughtInsideAStoreFailsTheOuterWrite(): void
    {
        $this->bindStore(new CallbackStore(function (): void {
            $this->recordAs(self::FAIL_CLOSED, self::INNER_CODE);
        }));

        AuditLog::record(self::CODE);

        $this->assertOutcome(spills: 1, reports: 1, events: 1);
        self::assertSame(\LogicException::class, $this->firstReport()->exceptionClass);
        self::assertSame(self::CODE, $this->firstReport()->eventCode);
    }

    /**
     * A store not saying it is durable refuses a fail-closed record in sync
     * mode, while in outbox mode the row is the acknowledgement.
     *
     * @return void
     */
    public function testTheOutboxAcknowledgesForAStoreThatIsNotDurable(): void
    {
        $this->bindStore(new PlainStore);

        self::assertSame(\LogicException::class, $this->thrownBy(fn () => $this->recordAs(self::FAIL_CLOSED))::class);
        $this->assertOutcome();

        $this->outboxModeOn();

        $this->recordAs(self::FAIL_CLOSED);

        $this->assertOutcome(outbox: 1);
    }

    /**
     * Spill to a channel that writes nowhere, define a second connection for a
     * host to transact on, and watch the invoices while the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        app()->booting(static function (): void {
            AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number', 'amount']);
        });
    }

    /**
     * Bind an access policy that lets every viewer see every entry, and return
     * it so a test can read what it was asked.
     *
     * @return \Tests\Fixtures\Querying\ClosurePolicy
     */
    private function allowEveryViewer(): ClosurePolicy
    {
        $policy = new ClosurePolicy(static fn (): AccessScope => AccessScope::all());

        app()->instance(AuditAccessPolicy::class, $policy);

        return $policy;
    }

    /**
     * The trail of the code every test records, read for a viewer the tests
     * name by reference.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo(Reference::of('App\Models\User', '7'))->forEvent(self::CODE);
    }

    /**
     * The ids of a page's entries, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return list<string>
     */
    private static function idsOf(TrailPage $page): array
    {
        return array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);
    }

    /**
     * The codes of the package's own records in the entries table, in the order
     * they were recorded.
     *
     * @return list<string>
     */
    private function readCodes(): array
    {
        $codes = $this->storageConnection()->table(EntrySettings::table())
            ->where('event', 'like', EventCode::RESERVED_PREFIX . '%')
            ->orderBy('recorded_at')
            ->pluck('event')
            ->all();

        return array_values(array_map(static fn (mixed $code): string => is_string($code) ? $code : '', $codes));
    }

    /**
     * Assert what the write has left: entries and outbox rows, spill lines,
     * reports, and the failed, written and captured events.
     *
     * @param  int  $entries
     * @param  int  $outbox
     * @param  int  $spills
     * @param  int  $reports
     * @param  int  $events
     * @param  int  $recorded
     * @param  int  $captures
     * @return void
     */
    private function assertOutcome(int $entries = 0, int $outbox = 0, int $spills = 0, int $reports = 0, int $events = 0, int $recorded = 0, int $captures = 0): void
    {
        self::assertSame(
            ['entries' => $entries, 'outbox' => $outbox, 'spills' => $spills, 'reports' => $reports, 'events' => $events, 'recorded' => $recorded, 'captures' => $captures],
            [
                'entries'  => $this->entryCount(),
                'outbox'   => $this->outboxCount(),
                'spills'   => count($this->spillLines()),
                'reports'  => count($this->reporter->reports()),
                'events'   => count($this->failures),
                'recorded' => $this->recorded,
                'captures' => count($this->captures),
            ],
        );
    }

    /**
     * Assert an after-commit record waits in memory for the commit: dropped by
     * a rollback, written once it commits.
     *
     * @param  \Illuminate\Database\Connection  $host
     * @param  int  $entries
     * @param  int  $outbox
     * @param  int  $recorded
     * @return void
     */
    private function assertWaitsForTheCommit(Connection $host, int $entries, int $outbox, int $recorded): void
    {
        $host->beginTransaction();

        self::assertSame(self::CODE, $this->recordAs(self::AFTER_COMMIT)->event);
        $this->assertOutcome();

        $host->rollBack();

        $this->assertOutcome();

        $host->beginTransaction();
        $this->recordAs(self::AFTER_COMMIT);

        $this->assertOutcome();

        $host->commit();

        $this->assertOutcome(entries: $entries, outbox: $outbox, recorded: $recorded);
    }

    /**
     * Assert the record is written before `record()` returns and goes with the
     * host's rollback on the shared connection.
     *
     * @param  string  $how
     * @param  int  $entries
     * @param  int  $outbox
     * @param  int  $recorded
     * @return void
     */
    private function assertWrittenNowAndRolledBack(string $how, int $entries, int $outbox, int $recorded): void
    {
        $this->host()->beginTransaction();
        $this->recordAs($how);

        $this->assertOutcome(entries: $entries, outbox: $outbox, recorded: $recorded);

        $this->host()->rollBack();

        $this->assertOutcome(recorded: $recorded);

        $this->startOver();

        $this->recordAs($how);

        $this->assertOutcome(entries: $entries, outbox: $outbox, recorded: $recorded);
    }

    /**
     * Assert the record is written inside the host's transaction before
     * `record()` returns, goes with its rollback and stays with its commit.
     *
     * @param  string  $how
     * @param  int  $entries
     * @param  int  $outbox
     * @param  int  $recorded
     * @return void
     */
    private function assertJoinsTheHost(string $how, int $entries, int $outbox, int $recorded): void
    {
        $this->host()->beginTransaction();
        $this->recordAs($how);

        $this->assertOutcome(entries: $entries, outbox: $outbox, recorded: $recorded);

        $this->host()->rollBack();

        $this->assertOutcome(recorded: $recorded);

        $this->startOver();

        $this->host()->beginTransaction();
        $this->recordAs($how);
        $this->host()->commit();

        $this->assertOutcome(entries: $entries, outbox: $outbox, recorded: $recorded);
    }

    /**
     * Assert a failed write inside the host's `transaction()` is thrown
     * sanitised with no spill or report, and rolls the change back.
     *
     * @param  string  $how
     * @return void
     */
    private function assertThrowsAndSpillsNothing(string $how): void
    {
        $thrown = $this->thrownBy(fn () => $this->host()->transaction(function () use ($how): void {
            $this->businessChange();
            $this->recordAs($how);
        }));

        self::assertSanitised($thrown);
        self::assertSame(0, $this->businessRows());
        self::assertSame(0, $this->host()->transactionLevel());
        $this->assertOutcome(events: 1);
    }

    /**
     * Assert what escaped is the sanitised exception of a failed statement,
     * with nothing behind it.
     *
     * @param  \Throwable  $thrown
     * @return void
     */
    private static function assertSanitised(\Throwable $thrown): void
    {
        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertNull($thrown->getPrevious());
    }

    /**
     * What escapes the host's `transaction()` around a business change and a
     * failing record, under the delivery and failure modes.
     *
     * @param  string  $how
     * @param  string  $delivery
     * @param  string  $mode
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @return \Throwable
     */
    private function thrownByAFatalWrite(string $how, string $delivery, string $mode, string $message, string $state, int $code): \Throwable
    {
        if ($delivery === self::OUTBOX) {
            $this->outboxModeOn();
        }

        $this->failureMode($mode);
        $this->breakWrites($message, $state, $code);

        return $this->thrownBy(fn () => $this->host()->transaction(function () use ($how): void {
            $this->businessChange();
            $this->recordAs($how);
        }));
    }

    /**
     * What the work throws; it must throw.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return \Throwable
     */
    private function thrownBy(\Closure $work): \Throwable
    {
        try {
            $work();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('Expected the work to throw.');
    }

    /**
     * Record through the public API, as asked.
     *
     * @param  string  $how
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function recordAs(string $how, string $code = self::CODE): AuditRecord
    {
        $pending = AuditLog::event($code);

        return match ($how) {
            self::IMMEDIATELY               => $pending->immediately()->record(),
            self::TRANSACTIONAL             => $pending->transactional()->record(),
            self::FAIL_CLOSED               => $pending->failClosed()->record(),
            self::FAIL_CLOSED_TRANSACTIONAL => $pending->failClosed()->transactional()->record(),
            default                         => $pending->record(),
        };
    }

    /**
     * Map the portal's sign-ins, on a registry of the test's own, since the
     * application's is frozen once it has booted.
     *
     * @return void
     */
    private function mapPortalSignIns(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalSignedIn::class, PortalMapper::class);

        app()->instance(MapperRegistry::class, $registry);
    }

    /**
     * Capture a portal sign-in through the public API.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function capture(): ?AuditRecord
    {
        return AuditLog::capture(new PortalSignedIn);
    }

    /**
     * The class names a failed capture carries: the event's, the mapper's and
     * the exception's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed  $failure
     * @return array{0: string, 1: ?string, 2: string}
     */
    private static function namesOf(AuditCaptureFailed $failure): array
    {
        return [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass];
    }

    /**
     * Save a watched invoice, whose creation is captured.
     *
     * @return void
     */
    private static function watchedInvoice(): void
    {
        WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);
    }

    /**
     * Record so the bound store is called: at once in sync mode, and in outbox
     * mode by a drain of the row the record leaves.
     *
     * @param  string  $delivery
     * @return void
     */
    private function recordThroughTheStore(string $delivery): void
    {
        if ($delivery === self::SYNC) {

            $this->recordAs(self::AFTER_COMMIT);

            return;
        }

        $this->outboxModeOn();
        $this->recordAs(self::AFTER_COMMIT);

        self::assertSame(1, $this->drain()->delivered());
    }

    /**
     * Make an insert into the entries table or the outbox throw a query failure
     * with the SQLSTATE and driver code.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @return void
     */
    private function breakWrites(string $message, string $state, int $code): void
    {
        $previous = new \PDOException($message);

        $previous->errorInfo = [$state, $code, $message];

        $failure = new QueryException(self::CONNECTION, 'insert into "audit_log_entries" ("id") values (?)', ['id'], $previous);
        $tables  = [EntrySettings::table(), DeliveryTables::outboxTable()];

        $this->host()->beforeExecuting(static function (string $query) use ($failure, $tables): void {
            if (!str_starts_with($query, 'insert into') || !Str::contains($query, $tables)) {
                return;
            }

            throw $failure;
        });
    }

    /**
     * Forget everything a part of a test has seen, so the next part asserts its
     * own: the spill lines, the reports, the events and the rows written.
     *
     * @return void
     */
    private function startOver(): void
    {
        $this->captureLogLines();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->failures = [];
        $this->recorded = 0;
        $this->captures = [];

        $this->storageConnection()->table(EntrySettings::table())->delete();
        $this->outboxConnection()->table(DeliveryTables::outboxTable())->delete();
    }

    /**
     * The connection the host transacts on, which the storage and the outbox
     * share unless a test says otherwise.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * Make the host's business change.
     *
     * @return void
     */
    private function businessChange(): void
    {
        $this->host()->table(self::INVOICES)->insert(['number' => 'INV-1']);
    }

    /**
     * The number of business changes that have committed or are in the host's
     * open transaction.
     *
     * @return int
     */
    private function businessRows(): int
    {
        return $this->host()->table(self::INVOICES)->count();
    }

    /**
     * Set the failure mode.
     *
     * @param  string  $mode
     * @return void
     */
    private function failureMode(string $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);
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
     * Forget the key ring and what its settings read, so the next write reads
     * them again.
     *
     * @return void
     */
    private function forgetTheKeyRing(): void
    {
        app()->forgetInstance(KeyRing::class);
        app()->forgetInstance(IntegritySettings::class);
    }

    /**
     * Drain every row that is due.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * The first report, which must be the sanitised exception.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function firstReport(): AuditWriteFailedException
    {
        $report = $this->reporter->reports()[0] ?? null;

        self::assertInstanceOf(AuditWriteFailedException::class, $report);

        return $report;
    }

    /**
     * A file holding the spill line, removed once the test is over.
     *
     * @param  string  $line
     * @return string
     */
    private function spillFile(string $line): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-outcomes');

        self::assertIsString($path);

        file_put_contents($path, $line . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The guarantee table's section of the note.
     *
     * @return string
     */
    private static function guarantees(): string
    {
        $note = file_get_contents(self::NOTE);

        self::assertIsString($note);

        $section = preg_replace('/\A.*?^## Guarantees$(.*?)^## .*\z/ms', '$1', $note);

        self::assertIsString($section);
        self::assertNotSame($note, $section, 'The note has no section of guarantees.');

        return $section;
    }

    /**
     * The trimmed cells of a table line.
     *
     * @param  string  $line
     * @return list<string>
     */
    private static function cellsOf(string $line): array
    {
        return array_map(trim(...), explode('|', trim($line, "| \t")));
    }
}
