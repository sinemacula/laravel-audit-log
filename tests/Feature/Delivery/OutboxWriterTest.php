<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Encryption\MissingAppKeyException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for the outbox write path: where a record goes, what the row
 * holds and what a failed insert does under each rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxWriter::class)]
final class OutboxWriterTest extends TestCase
{
    use CapturesLogLines, InteractsWithOutbox, MockeryPHPUnitIntegration, SearchesForSecrets;

    /** @var string A second connection a host transacts on. */
    private const string OTHER = 'audit_other';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The instant a stand-in clock gives. */
    private const string STAMP = '2026-11-01T12:00:09.500000Z';

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string A failure Laravel reads as a lost connection. */
    private const string LOST = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> The failed writes said, in order. */
    private array $failures = [];

    /** @var list<string> The class each capture's signal passed on, in order. */
    private array $signalled = [];

    /** @var list<array{0: \SineMacula\Laravel\AuditLog\Records\FinalisedRecord, 1: int}> Each finalised record a package write was handed, with the outbox's row count then. */
    private array $acknowledged = [];

    /**
     * Bind the reporter, capture the spill lines and keep every failed write
     * that is said.
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

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $event): void {
            $this->failures[] = $event;
        });
    }

    /**
     * Roll back any transaction a test left open, drop what the test added and
     * release the clock.
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

        $this->removeOutboxProbeTable();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * With no transaction open, an after-commit record is inserted at once.
     *
     * @return void
     */
    public function testNoTransactionInsertsNow(): void
    {
        $record = $this->record();

        $this->write($record, Timing::AFTER_COMMIT);

        self::assertNotNull($this->outboxRow($record->id));
    }

    /**
     * An immediate record is inserted at once whatever is open, and leaves no
     * callback for a commit to run.
     *
     * @return void
     */
    public function testImmediatelyInsertsNow(): void
    {
        $other = $this->begin(self::OTHER);
        $mine  = $this->begin();

        $this->write($this->record(), Timing::IMMEDIATE);

        self::assertSame(1, $this->outboxCount());
        self::assertSame([], $other->getCallbacks());
        self::assertSame([], $mine->getCallbacks());
    }

    /**
     * A transactional record is inserted at once, inside the open transaction.
     *
     * @return void
     */
    public function testTransactionalInsertsNow(): void
    {
        $this->begin();

        $this->write($this->record(), Timing::TRANSACTIONAL, null, FailureRule::THROW);

        self::assertSame(1, $this->outboxCount());

        $this->outboxConnection()->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * An after-commit record whose selected transaction is on the outbox
     * connection is inserted at once inside it, and goes with its rollback.
     *
     * @return void
     */
    public function testAfterCommitOnTheOutboxConnectionInsertsInsideIt(): void
    {
        $selected = $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(1, $this->outboxCount());
        self::assertCount(1, $selected->getCallbacks(), 'Only the commit queue\'s place is held.');
        self::assertSame(1, $this->outboxConnection()->transactionLevel());

        $this->outboxConnection()->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * An after-commit record whose selected transaction is on another
     * connection is inserted when that transaction commits, and never before.
     *
     * @return void
     */
    public function testAfterCommitOnAnotherConnectionWaitsForItsCommit(): void
    {
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(0, $this->outboxCount());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A rollback of the other connection's transaction drops the record, which
     * is never inserted.
     *
     * @return void
     */
    public function testARollbackOnAnotherConnectionDropsTheRecord(): void
    {
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        DB::connection(self::OTHER)->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A record pinned to the outbox connection is inserted inside its
     * transaction, though a later transaction is open elsewhere.
     *
     * @return void
     */
    public function testAfterCommitPinnedToTheOutboxConnectionInsertsInsideIt(): void
    {
        $selected = $this->begin();
        $other    = $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT, self::CONNECTION);

        self::assertSame(1, $this->outboxCount());
        self::assertCount(1, $selected->getCallbacks(), 'Only the commit queue\'s place is held.');
        self::assertSame([], $other->getCallbacks());

        $this->outboxConnection()->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A record pinned to another connection waits for that connection's commit,
     * though the outbox connection's transaction is the innermost.
     *
     * @return void
     */
    public function testAfterCommitPinnedToAnotherConnectionWaits(): void
    {
        $other = $this->begin(self::OTHER);

        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT, self::OTHER);

        self::assertSame(0, $this->outboxCount());
        self::assertCount(1, $other->getCallbacks());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A name given with a selector is the connection it selects, so it matches
     * an outbox on that connection and the record is inserted inside it.
     *
     * @return void
     */
    public function testASelectorMatchesItsConnection(): void
    {
        $selected = $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT, DB::connection(self::CONNECTION . '::write')->getName());

        self::assertSame(1, $this->outboxCount());
        self::assertCount(1, $selected->getCallbacks(), 'Only the commit queue\'s place is held.');
    }

    /**
     * An outbox set to a selector is a separate connection instance that cannot
     * join the host's transaction, so it waits for the commit.
     *
     * @return void
     */
    public function testAnOutboxOnASecondInstanceOfTheHostsConnectionWaits(): void
    {
        $selected = $this->begin(self::CONNECTION);

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.connection', self::CONNECTION . '::write');

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertCount(1, $selected->getCallbacks());

        DB::connection(self::CONNECTION)->rollBack();

        self::assertSame(0, DB::connection(self::CONNECTION)->table(DeliveryTables::outboxTable())->count());
    }

    /**
     * With no name given the innermost transaction decides, whichever way round
     * the two were opened.
     *
     * @return void
     */
    public function testTheInnermostDecidesWithNoNameGiven(): void
    {
        $outbox = $this->begin();
        $other  = $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(0, $this->outboxCount());
        self::assertCount(1, $other->getCallbacks());
        self::assertSame([], $outbox->getCallbacks());

        DB::connection(self::OTHER)->rollBack();

        $this->outboxConnection()->rollBack();

        $this->begin(self::OTHER);
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * With no transactions manager bound nothing can be selected, so the record
     * is inserted at once.
     *
     * @return void
     */
    public function testAContainerWithoutATransactionsManagerInsertsNow(): void
    {
        $this->begin(self::OTHER);

        $writer = $this->writer();

        $this->app?->offsetUnset('db.transactions');

        $writer->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * The payload is the record's envelope encrypted, so nothing of the record
     * is readable in the row.
     *
     * @return void
     */
    public function testThePayloadIsEncrypted(): void
    {
        $record = $this->record();

        $this->write($record, Timing::AFTER_COMMIT);

        $payload = $this->payloadOf($record);

        self::assertStringNotContainsString(self::SECRET, $payload);
        self::assertStringNotContainsString('invoice.approved', $payload);
        self::assertStringNotContainsString($record->id, $payload);
        self::assertStringNotContainsString(self::SECRET, (string) base64_decode($payload, true));
    }

    /**
     * The payload is encrypted as a string: decrypting it as a string gives the
     * JSON itself, and no PHP serialisation is involved.
     *
     * @return void
     */
    public function testThePayloadIsEncryptedAsAString(): void
    {
        $record = $this->record();

        $this->write($record, Timing::AFTER_COMMIT);

        $json = app(StringEncrypter::class)->decryptString($this->payloadOf($record));

        self::assertStringStartsWith('{', $json);
        self::assertStringContainsString(self::SECRET, $json);
        self::assertFalse(@unserialize($json));
    }

    /**
     * The row's id is the envelope's id, which a decode that expects it holds
     * the envelope to, and the envelope is the record's.
     *
     * @return void
     */
    public function testTheOutboxIdEqualsTheEnvelopeId(): void
    {
        $record = $this->record();

        $this->write($record, Timing::AFTER_COMMIT);

        self::assertSame($record->id, $this->enveloped($record)->record->id);
        self::assertSame($record->id, $this->outboxRow($record->id)['id'] ?? null);
    }

    /**
     * The record is finalised once, when it is inserted.
     *
     * @return void
     */
    public function testFinalisesOnce(): void
    {
        $record = $this->record();
        $writer = $this->writer();

        $this->stampingClockOnce();

        $writer->write($record, Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame(self::STAMP, $this->enveloped($record)->recordedAt);
    }

    /**
     * A record deferred to another connection's commit is finalised when it is
     * inserted, not when it was captured, and only then.
     *
     * @return void
     */
    public function testADeferredRecordIsFinalisedAtItsInsert(): void
    {
        $record = $this->record();
        $writer = $this->writer();

        $this->begin(self::OTHER);

        $writer->write($record, Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        $this->stampingClockOnce();

        DB::connection(self::OTHER)->commit();

        self::assertSame(self::STAMP, $this->enveloped($record)->recordedAt);
    }

    /**
     * A failed insert does not finalise again: the spill holds the record as it
     * was finalised for the insert.
     *
     * @return void
     */
    public function testAFailedInsertDoesNotFinaliseAgain(): void
    {
        $this->pointOutboxAtProbeTable();

        $writer = $this->writer();

        $this->stampingClockOnce();

        $writer->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertStringContainsString(self::STAMP, $this->spillLines()[0]);
    }

    /**
     * Nothing says the record was written: the drain says that, once it has
     * delivered it.
     *
     * @return void
     */
    public function testDispatchesNoAuditRecorded(): void
    {
        $recorded = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$recorded): void {
            $recorded[] = $event;
        });

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(1, $this->outboxCount());
        self::assertSame([], $recorded);
    }

    /**
     * No store is called and no entry is written: the record waits in the
     * outbox.
     *
     * @return void
     */
    public function testCallsNoStore(): void
    {
        $calls = 0;

        $this->app?->instance(AuditStore::class, new CallbackStore(static function () use (&$calls): void {
            $calls++;
        }));

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame(0, $calls);
        self::assertSame(0, DB::table(EntrySettings::table())->count());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Under `REPORT`, a failed insert with no transaction open is spilled,
     * reported and said at once, and the code goes on.
     *
     * @return void
     */
    public function testAFailedInsertFollowsTheReportRule(): void
    {
        $this->pointOutboxAtProbeTable();

        $record = $this->record();

        $this->write($record, Timing::AFTER_COMMIT);

        self::assertCount(1, $this->spillLines());

        $report = $this->firstReport();

        self::assertSame($record->id, $report->recordId);
        self::assertSame('invoice.approved', $report->eventCode);
        self::assertSame('outbox', $report->operation);
        self::assertSame(Outbox::class, $report->store);
        self::assertSame(QueryException::class, $report->exceptionClass);
        self::assertSame(self::CONNECTION, $report->connection);
        self::assertCount(1, $this->failures);
        self::assertSame($record->id, $this->failures[0]->id);
        self::assertSame(Outbox::class, $this->failures[0]->store);
    }

    /**
     * A failed insert inside the selected transaction binds its spill to that
     * transaction's commit, which writes the finalised record.
     *
     * @return void
     */
    public function testAFailedInsertInTheSelectedTransactionBindsItsSpillToTheCommit(): void
    {
        $this->pointOutboxAtProbeTable();

        $selected = $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertCount(1, $selected->getCallbacks());

        $this->outboxConnection()->commit();

        self::assertCount(1, $this->spillLines());
        self::assertStringStartsWith(FailureSpill::MARKER, $this->spillLines()[0]);
        self::assertStringContainsString('"hmac"', $this->spillLines()[0]);
    }

    /**
     * Until that commit nothing is spilled.
     *
     * @return void
     */
    public function testAFailedInsertInTheSelectedTransactionSpillsNothingBeforeTheCommit(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame([], $this->spillLines());
    }

    /**
     * A rollback of the selected transaction discards the spill, so a replay
     * never brings back a record of work that was undone.
     *
     * @return void
     */
    public function testARolledBackHostDiscardsTheSpill(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $this->outboxConnection()->rollBack();

        self::assertSame([], $this->spillLines());
    }

    /**
     * A commit of the selected transaction writes the spill exactly once, and a
     * later transaction does not write it again.
     *
     * @return void
     */
    public function testACommittedHostSpillsOnce(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $this->outboxConnection()->commit();
        $this->outboxConnection()->beginTransaction();
        $this->outboxConnection()->commit();

        self::assertCount(1, $this->spillLines());
    }

    /**
     * The report and the event go out at once, without waiting for the commit
     * the spill is bound to, and whatever then becomes of it.
     *
     * @return void
     */
    public function testDiagnosticsGoOutAtOnce(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);

        $this->outboxConnection()->rollBack();

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * Finalising inside the selected transaction fails before its commit, named
     * as a failure to finalise, and leaves the host usable.
     *
     * @return void
     */
    public function testAFailedFinaliseOnThisPathFailsBeforeTheCommit(): void
    {
        $writer = $this->writer();

        $this->begin();
        $this->breakTheClock();

        $writer->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame('finalise', $this->firstReport()->operation);
        self::assertSame(1, $this->outboxConnection()->transactionLevel());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A record that could not be finalised is spilled at the commit marked
     * unsigned, with no signature.
     *
     * @return void
     */
    public function testAFailedFinaliseIsSpilledUnsignedAtTheCommit(): void
    {
        $record = $this->record();
        $writer = $this->writer();

        $this->begin();
        $this->breakTheClock();

        $writer->write($record, Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame([], $this->spillLines());

        $this->outboxConnection()->commit();

        self::assertSame([FailureSpill::line(['unsigned' => true, ...$record->toArray()])], $this->spillLines());
    }

    /**
     * A ring that cannot be built is resolved inside the attempt, so it follows
     * the rule as a failure to finalise rather than escaping.
     *
     * @return void
     */
    public function testAMalformedRingFollowsTheRule(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.keys', 'not a map');

        $this->app?->forgetInstance(KeyRing::class);
        $this->app?->forgetInstance(IntegritySettings::class);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame('finalise', $this->firstReport()->operation);
        self::assertSame(\InvalidArgumentException::class, $this->firstReport()->exceptionClass);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * With no application key the encrypter fails inside the attempt, so a
     * record signed under an explicit ring follows the rule.
     *
     * @return void
     */
    public function testAnEncryptionFailureFollowsTheRule(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.keys', ['ring-1' => str_repeat('k', 32)]);
        $config->set('audit-log.integrity.current', 'ring-1');
        $config->set('app.key', '');

        $this->app?->forgetInstance(KeyRing::class);
        $this->app?->forgetInstance(IntegritySettings::class);
        $this->app?->forgetInstance('encrypter');

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame('outbox', $this->firstReport()->operation);
        self::assertSame(MissingAppKeyException::class, $this->firstReport()->exceptionClass);
        self::assertCount(1, $this->spillLines());
        self::assertStringContainsString('"hmac"', $this->spillLines()[0]);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Rows of `[rule, whether it spills]`: each rule that throws.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule, 1: int}>
     */
    public static function provideThrowingRules(): iterable
    {
        yield from [
            'spill and throw' => [FailureRule::SPILL_AND_THROW, 1],
            'throw'           => [FailureRule::THROW, 0],
        ];
    }

    /**
     * A throwing rule throws the sanitised exception before the commit and
     * leaves the host able to commit; only a spilling rule spills there.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  int  $spills
     * @return void
     */
    #[DataProvider('provideThrowingRules')]
    public function testAThrowRuleThrowsBeforeTheCommit(FailureRule $rule, int $spills): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $thrown = $this->thrownBy($this->record(), Timing::AFTER_COMMIT, null, $rule);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertNull($thrown->getPrevious());
        self::assertSame(1, $this->outboxConnection()->transactionLevel());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());

        $this->outboxConnection()->commit();

        self::assertCount($spills, $this->spillLines());
    }

    /**
     * A transactional record's failed insert is thrown and never spilled, even
     * when the host commits: it describes work that had not committed.
     *
     * @return void
     */
    public function testAFailedTransactionalInsertNeverSpills(): void
    {
        $this->pointOutboxAtProbeTable();

        $selected = $this->begin();

        $thrown = $this->thrownBy($this->record(), Timing::TRANSACTIONAL, null, FailureRule::THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame([], $selected->getCallbacks());

        $this->outboxConnection()->commit();

        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->failures);
    }

    /**
     * An immediate record's failed insert is spilled at once, inside a host
     * that then rolls back, because its host may already have failed.
     *
     * @return void
     */
    public function testAFailedImmediateInsertSpillsAtOnce(): void
    {
        $this->pointOutboxAtProbeTable();

        $selected = $this->begin();

        $this->write($this->record(), Timing::IMMEDIATE);

        self::assertCount(1, $this->spillLines());
        self::assertSame([], $selected->getCallbacks());

        $this->outboxConnection()->rollBack();

        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed insert at another connection's commit, with no outbox
     * transaction open then, spills at once, as that commit runs it.
     *
     * @return void
     */
    public function testAFailedInsertOnAnotherConnectionSpillsAtOnce(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $beforeTheCommit = $this->spillLines();

        DB::connection(self::OTHER)->commit();

        self::assertSame([], $beforeTheCommit);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed insert at another connection's commit leaves that commit alone
     * under the `REPORT` rule, and later callbacks run.
     *
     * @return void
     */
    public function testAFailedInsertLeavesLaterCallbacksOfThatCommitRunning(): void
    {
        $later = false;

        $this->pointOutboxAtProbeTable();

        $other = $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $other->addCallback(static function () use (&$later): void {
            $later = true;
        });

        DB::connection(self::OTHER)->commit();

        self::assertTrue($later);
    }

    /**
     * A rule that throws reaches the code that commits, when the insert was
     * deferred to another connection's commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowRuleOnAnotherConnectionReachesItsCommit(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::SPILL_AND_THROW);

        try {
            DB::connection(self::OTHER)->commit();

            self::fail('Expected the commit to throw.');
        } catch (AuditWriteFailedException $thrown) {
            self::assertSame('outbox', $thrown->operation);
        }

        self::assertCount(1, $this->spillLines());
    }

    /**
     * An insert at another connection's commit is held by any outbox
     * transaction open when it runs, so its spill waits for that commit.
     *
     * @return void
     */
    public function testAnInsertAfterAnotherCommitInsideAnOpenOutboxTransactionBindsItsSpill(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $outbox = $this->begin();

        DB::connection(self::OTHER)->commit();

        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $outbox->getCallbacks());

        $this->outboxConnection()->commit();

        self::assertCount(1, $this->spillLines());
    }

    /**
     * That bound spill goes when the outbox transaction rolls back.
     *
     * @return void
     */
    public function testThatBoundSpillIsDiscardedWhenTheOutboxTransactionRollsBack(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $this->begin();

        DB::connection(self::OTHER)->commit();

        $this->outboxConnection()->rollBack();

        self::assertSame([], $this->spillLines());
    }

    /**
     * An after-commit record pinned to a connection with no transaction is
     * written now, and an open outbox transaction holds its spill.
     *
     * @return void
     */
    public function testAPinnedRecordWrittenNowInsideAnOpenOutboxTransactionBindsItsSpill(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT, self::OTHER);

        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->reporter->reports());

        $this->outboxConnection()->commit();

        self::assertCount(1, $this->spillLines());
    }

    /**
     * That spill goes when the outbox transaction rolls back.
     *
     * @return void
     */
    public function testThatPinnedSpillIsDiscardedOnRollback(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin();

        $this->write($this->record(), Timing::AFTER_COMMIT, self::OTHER);

        $this->outboxConnection()->rollBack();

        self::assertSame([], $this->spillLines());
    }

    /**
     * Rows of `[failure]`: each failure fatal to an open transaction.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int, 3: class-string<\RuntimeException>}>
     */
    public static function provideFatalFailures(): iterable
    {
        yield from [
            'a deadlock'        => [self::DEADLOCK, '40001', 1213, DeadlockException::class],
            'a lost connection' => [self::LOST, 'HY000', 2006, AuditWriteFailedException::class],
        ];
    }

    /**
     * A failure fatal to the open transaction is thrown sanitised under every
     * rule, never spilled, bound or reported, and is still said.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @param  class-string<\RuntimeException>  $expected
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testAFailureFatalToTheHostIsThrownSanitised(string $message, string $state, int $code, string $expected): void
    {
        $this->breakTheInsert($message, $state, $code);

        $selected = $this->begin();

        $thrown = $this->thrownBy($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertInstanceOf($expected, $thrown);
        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown, 'the thrown exception');
        self::assertCount(1, $selected->getCallbacks(), 'Only the commit queue\'s place is held.');
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A deadlock on the insert leaves a host's own `transaction()` able to
     * retry it, and the retry writes the one row.
     *
     * @return void
     */
    public function testADeadlockLetsTheHostsTransactionRetry(): void
    {
        $attempts = 0;
        $record   = $this->record();

        $this->breakTheInsert(self::DEADLOCK, '40001', 1213, once: true);

        $this->outboxConnection()->transaction(function () use (&$attempts, $record): void {
            $attempts++;

            $this->write($record, Timing::AFTER_COMMIT);
        }, 2);

        self::assertSame(2, $attempts);
        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->outboxConnection()->transactionLevel());
    }

    /**
     * With no transaction open a deadlock ended nothing, so it follows the
     * rule.
     *
     * @return void
     */
    public function testADeadlockWithNoTransactionFollowsTheRule(): void
    {
        $this->breakTheInsert(self::DEADLOCK, '40001', 1213);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * Neither what is thrown nor what is reported holds anything of the record
     * or of the failure's message and bindings.
     *
     * @return void
     */
    public function testAFailedInsertHoldsNoSecret(): void
    {
        $this->breakTheInsert('Duplicate entry', '23000', 1062);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $thrown = $this->thrownBy($this->record(), Timing::AFTER_COMMIT, null, FailureRule::SPILL_AND_THROW);

        self::assertHoldsNoSecret($thrown, 'the thrown exception');
        self::assertHoldsNoSecret($this->reporter->reports(), 'the reports');
        self::assertHoldsNoSecret($this->failures, 'the events');
    }

    /**
     * The callback a deferred insert leaves on the transaction holds the record
     * sealed, so a trace or a dump of the commit's frames cannot reach it.
     *
     * @return void
     */
    public function testADeferredInsertHoldsTheRecordSealed(): void
    {
        $other = $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertCount(1, $other->getCallbacks());
        self::assertHoldsNoSecret($other->getCallbacks(), 'the deferred callback');
    }

    /**
     * Every parameter of the writer that holds the record is marked sensitive,
     * so no frame of the writer shows it.
     *
     * @return void
     */
    public function testEveryPayloadParameterIsMarkedSensitive(): void
    {
        $checked = [];

        foreach ((new \ReflectionClass(OutboxWriter::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $type = $parameter->getType();
                $name = $type instanceof \ReflectionNamedType ? $type->getName() : '';

                if (!in_array($name, [AuditRecord::class, FinalisedRecord::class, \Throwable::class, \Closure::class], true)) {
                    continue;
                }

                $checked[] = $method->getName();

                self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), "{$method->getName()}() does not mark \${$parameter->getName()} sensitive.");
            }
        }

        self::assertSame(['write', 'insertAfterTransaction', 'abandonSealed', 'insert', 'enqueue'], $checked);
    }

    /**
     * An outbox connection that cannot be resolved fails the insert, which
     * follows the rule, and nothing escapes, with no connection to name.
     *
     * @return void
     */
    public function testAnUnresolvableOutboxFollowsTheRule(): void
    {
        $this->brokenWriter()->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame(\LogicException::class, $this->firstReport()->exceptionClass);
        self::assertSame('outbox', $this->firstReport()->operation);
        self::assertNull($this->firstReport()->connection);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * An unresolvable outbox connection cannot hold the insert, so the record
     * waits for its selected commit and fails there without stopping it.
     *
     * @return void
     */
    public function testAnUnresolvableOutboxWaitsForTheSelectedCommit(): void
    {
        $selected = $this->begin(self::OTHER);

        $this->brokenWriter()->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        $beforeTheCommit = $this->reporter->reports();

        self::assertCount(1, $selected->getCallbacks());

        DB::connection(self::OTHER)->commit();

        self::assertSame([], $beforeTheCommit);
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * An unresolvable outbox connection holds no transaction, so a spill
     * written now binds to nothing.
     *
     * @return void
     */
    public function testAnUnresolvableOutboxBindsNoSpill(): void
    {
        $other = $this->begin(self::OTHER);

        $this->brokenWriter()->write($this->record(), Timing::AFTER_COMMIT, 'audit_idle', FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertSame([], $other->getCallbacks());
    }

    /**
     * A malformed outbox table follows the rule, since the insert reads it
     * inside the attempt.
     *
     * @return void
     */
    public function testAMalformedOutboxTableFollowsTheRule(): void
    {
        $writer = $this->writer();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', 'Not A Table!');

        $writer->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertSame(\InvalidArgumentException::class, $this->firstReport()->exceptionClass);
        self::assertCount(1, $this->spillLines());

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', DeliveryTables::DEFAULT_OUTBOX);
    }

    /**
     * The write guard is active while the row is inserted, and released after,
     * so a record made from inside the insert is refused.
     *
     * @return void
     */
    public function testTheGuardIsActiveDuringTheInsert(): void
    {
        $during = [];

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$during): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $during[] = app(WriteGuard::class)->isActive();
        });

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertSame([true], $during);
        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * The write guard does not reach back over finalising, which runs before
     * the insert's window opens.
     *
     * @return void
     */
    public function testTheGuardIsNotHeldWhileFinalising(): void
    {
        $during = null;
        $writer = $this->writer();
        $clock  = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andReturnUsing(static function () use (&$during): CarbonImmutable {
            $during = app(WriteGuard::class)->isActive();

            return new CarbonImmutable(self::STAMP, 'UTC');
        });

        $this->app?->instance(Clock::class, $clock);

        $writer->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT);

        self::assertFalse($during);
    }

    /**
     * The write guard is released after a failed insert, under a rule that
     * returns and under one that throws.
     *
     * @return void
     */
    public function testTheGuardIsReleasedAfterAFailedInsert(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->write($this->record(), Timing::AFTER_COMMIT);

        self::assertFalse(app(WriteGuard::class)->isActive());

        $this->thrownBy($this->record(), Timing::AFTER_COMMIT, null, FailureRule::SPILL_AND_THROW);

        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * A capture's failed insert is spilled once, reported once and said once,
     * and its signal is told once, with the failure's class.
     *
     * @return void
     */
    public function testACapturesOutboxFailureIsSignalledOnce(): void
    {
        $this->pointOutboxAtProbeTable();

        $signal = $this->signal();

        $this->write($this->record(), Timing::IMMEDIATE, null, FailureRule::REPORT, $signal);

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertSame('outbox', $this->firstReport()->operation);
        self::assertCount(1, $this->failures);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertFalse($signal->isDeferred());
    }

    /**
     * A capture whose transaction is on the outbox connection is inserted at
     * once, inside it, and is not deferred: the rollback takes the row.
     *
     * @return void
     */
    public function testACaptureOnTheOutboxConnectionIsInsertedInsideTheHost(): void
    {
        $this->begin();

        $signal = $this->signal();

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        self::assertSame(1, $this->outboxCount());
        self::assertFalse($signal->isDeferred());

        $this->outboxConnection()->rollBack();

        self::assertSame(0, $this->outboxCount());
        self::assertFalse($signal->hasFailed());
    }

    /**
     * A capture whose transaction is on another connection is marked deferred
     * when its insert is queued, and inserted when that transaction commits.
     *
     * @return void
     */
    public function testACaptureOnAnotherConnectionIsDeferredAndMarked(): void
    {
        $this->begin(self::OTHER);

        $signal = $this->signal();

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        self::assertTrue($signal->isDeferred());
        self::assertSame(0, $this->outboxCount());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $this->outboxCount());
        self::assertFalse($signal->hasFailed());
    }

    /**
     * A deferred capture's failed insert reaches its signal at the commit, not
     * before, and the commit stands.
     *
     * @return void
     */
    public function testADeferredCapturesFailedInsertIsSignalledAtTheCommit(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $signal = $this->signal();

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        self::assertFalse($signal->hasFailed());

        DB::connection(self::OTHER)->commit();

        self::assertSame(0, DB::connection(self::OTHER)->transactionLevel());
        self::assertSame([QueryException::class], $this->signalled);
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A deferred capture whose transaction rolls back is never inserted and
     * signals nothing.
     *
     * @return void
     */
    public function testARolledBackCaptureSignalsNothing(): void
    {
        $this->pointOutboxAtProbeTable();
        $this->begin(self::OTHER);

        $signal = $this->signal();

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        DB::connection(self::OTHER)->rollBack();

        self::assertFalse($signal->hasFailed());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A failure outside the attempt in a deferred capture's commit callback is
     * reported once by class, signalled, and the commit succeeds.
     *
     * @return void
     */
    public function testADeferredCapturesInsertNeverThrowsFromTheCommit(): void
    {
        $other  = DB::connection(self::OTHER);
        $signal = $this->signal();

        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        $this->breakTheConnectionResolver();

        try {
            $other->commit();
        } finally {
            $this->app?->alias('db', ConnectionResolverInterface::class);
        }

        self::assertSame(0, $other->transactionLevel());
        self::assertCount(1, $this->reporter->reports());
        self::assertSame(\RuntimeException::class, $this->firstReport()->exceptionClass);
        self::assertSame('outbox', $this->firstReport()->operation);
        self::assertSame(Outbox::class, $this->firstReport()->store);
        self::assertSame([\RuntimeException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertSame(0, $this->outboxCount());
        self::assertHoldsNoSecret($this->reporter->reports(), 'the reports');
    }

    /**
     * The same failure in an ordinary record's deferred insert still reaches
     * the code that commits, as it always has: only a capture contains it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredOrdinaryInsertsEscapeStillReachesTheCommit(): void
    {
        $other = DB::connection(self::OTHER);

        $this->begin(self::OTHER);

        $this->write($this->record(), Timing::AFTER_COMMIT);

        $this->breakTheConnectionResolver();

        try {
            $other->commit();

            self::fail('Expected the failure to reach the commit.');
        } catch (\RuntimeException $thrown) {
            self::assertSame('The resolver is broken.', $thrown->getMessage());
        } finally {
            $this->app?->alias('db', ConnectionResolverInterface::class);
        }
    }

    /**
     * A synchronous capture's insert that deadlocks inside the host's
     * transaction is thrown sanitised and signalled as fatal.
     *
     * @return void
     */
    public function testACapturesFatalInsertInsideTheHostIsThrownAndSignalledFatal(): void
    {
        $this->breakTheInsert(self::DEADLOCK, '40001', 1213);
        $this->begin();

        $signal = $this->signal();

        $thrown = $this->thrownBy($this->record(), Timing::AFTER_COMMIT, null, FailureRule::REPORT, $signal);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame([DeadlockException::class], $this->signalled);
        self::assertTrue($signal->isFatal());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A deferred capture's insert that deadlocks at another connection's commit
     * is spilled at once, reported sanitised and signalled, never thrown.
     *
     * @return void
     */
    public function testADeferredCapturesFatalInsertIsReported(): void
    {
        $this->breakTheInsert(self::DEADLOCK, '40001', 1213);
        $this->begin(self::OTHER);

        $signal = $this->signal();

        $this->write($this->record(), Timing::AFTER_COMMIT, self::OTHER, FailureRule::REPORT, $signal);

        $this->outboxConnection()->beginTransaction();

        DB::connection(self::OTHER)->commit();

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(DeadlockException::class, $reports[0]);
        self::assertSame([DeadlockException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertCount(1, $this->spillLines());
        self::assertSame(1, $this->outboxConnection()->transactionLevel());
    }

    /**
     * A package write is handed the finalised record once its row is in the
     * outbox, and it is the envelope the row holds, the signature included.
     *
     * @return void
     */
    public function testAPackageWriteIsGivenItsFinalisedRecordOnceInserted(): void
    {
        $record = $this->record();

        $this->write($record, Timing::IMMEDIATE, null, FailureRule::SPILL_AND_THROW, null, $this->packageWrite());

        $enveloped = $this->enveloped($record);

        self::assertCount(1, $this->acknowledged);

        [$finalised, $rows] = $this->acknowledged[0];

        self::assertSame(1, $rows);
        self::assertSame($record, $finalised->record);
        self::assertSame($enveloped->hmac, $finalised->hmac);
        self::assertSame($enveloped->keyId, $finalised->keyId);
        self::assertSame($enveloped->recordedAt, $finalised->recordedAt);
    }

    /**
     * A failed insert is never acknowledged: it follows the record's rule, and
     * its spill is written.
     *
     * @return void
     */
    public function testAFailedInsertIsNeverAcknowledged(): void
    {
        $this->pointOutboxAtProbeTable();

        $thrown = $this->thrownBy($this->record(), Timing::IMMEDIATE, null, FailureRule::SPILL_AND_THROW, null, $this->packageWrite());

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame([], $this->acknowledged);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A package write whose finalising fails is never acknowledged either.
     *
     * @return void
     */
    public function testAFailedFinaliseIsNeverAcknowledged(): void
    {
        $writer = $this->writer();

        $this->breakTheClock();

        $thrown = null;

        try {
            $writer->write($this->record(), Timing::IMMEDIATE, null, FailureRule::SPILL_AND_THROW, null, $this->packageWrite());
        } catch (AuditWriteFailedException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(0, $this->outboxCount());
        self::assertSame([], $this->acknowledged);
    }

    /**
     * A write without a package write acknowledges nothing, and one under a
     * rule that returns on failure acknowledges nothing when its insert fails.
     *
     * @return void
     */
    public function testOnlyAnInsertedPackageWriteIsAcknowledged(): void
    {
        $this->write($this->record(), Timing::IMMEDIATE);

        $this->pointOutboxAtProbeTable();

        $this->write($this->record(), Timing::IMMEDIATE, null, FailureRule::REPORT, null, $this->packageWrite());

        self::assertSame([], $this->acknowledged);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Spill to a channel that writes nowhere, and register the second
     * transacting connection, with a table prefix of its own.
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
    }

    /**
     * The writer as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\OutboxWriter
     */
    private function writer(): OutboxWriter
    {
        return new OutboxWriter(app(), app(Outbox::class));
    }

    /**
     * A writer whose outbox connection is no database connection, so anything
     * that asks for it is refused.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\OutboxWriter
     */
    private function brokenWriter(): OutboxWriter
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);

        $resolver->shouldReceive('connection')->andReturn(\Mockery::mock(ConnectionInterface::class));

        return new OutboxWriter(app(), new Outbox($resolver, app(Clock::class), app(DeliverySettings::class)));
    }

    /**
     * Write the record through a new writer.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function write(
        AuditRecord $record,
        Timing $timing,
        ?string $transaction = null,
        FailureRule $rule = FailureRule::REPORT,
        ?CaptureSignal $capture = null,
        ?PackageWrite $package = null,
    ): void {
        $this->writer()->write($record, $timing, $transaction, $rule, $capture, $package);
    }

    /**
     * What writing the record throws; it must throw.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return \RuntimeException
     */
    private function thrownBy(
        AuditRecord $record,
        Timing $timing,
        ?string $transaction,
        FailureRule $rule,
        ?CaptureSignal $capture = null,
        ?PackageWrite $package = null,
    ): \RuntimeException {
        try {
            $this->write($record, $timing, $transaction, $rule, $capture, $package);
        } catch (\RuntimeException $thrown) {
            return $thrown;
        }

        self::fail('Expected the write to throw.');
    }

    /**
     * A package write that accepts every record, and keeps each finalised
     * record it is handed with the outbox's row count at that moment.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\PackageWrite
     */
    private function packageWrite(): PackageWrite
    {
        return new PackageWrite(
            static function (): void {},
            function (FinalisedRecord $finalised): void {
                $this->acknowledged[] = [$finalised, $this->outboxCount()];
            },
        );
    }

    /**
     * A capture's signal that keeps the class it passes on.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->signalled[] = $exceptionClass;
        });
    }

    /**
     * Make the connection resolver the insert reads the open transactions from
     * fail, outside the insert's attempt; the test puts it back.
     *
     * @return void
     */
    private function breakTheConnectionResolver(): void
    {
        $this->app?->bind(ConnectionResolverInterface::class, static function (): never {
            throw new \RuntimeException('The resolver is broken.');
        });
    }

    /**
     * A captured record whose properties hold the secret.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function record(): AuditRecord
    {
        return RecordFactory::captured(['note' => self::SECRET]);
    }

    /**
     * Open a transaction on the connection, the outbox's when none is named,
     * and return its record.
     *
     * @param  ?string  $name
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function begin(?string $name = null): DatabaseTransactionRecord
    {
        $connection = $name === null ? $this->outboxConnection() : DB::connection($name);

        $connection->beginTransaction();

        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $record = $manager->callbackApplicableTransactions()->last();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $record);

        return $record;
    }

    /**
     * The payload of the record's row, which must exist.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return string
     */
    private function payloadOf(AuditRecord $record): string
    {
        $payload = $this->outboxRow($record->id)['payload'] ?? null;

        self::assertIsString($payload);

        return $payload;
    }

    /**
     * The finalised record the record's row holds, decoded and held to its id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function enveloped(AuditRecord $record): FinalisedRecord
    {
        return app(EnvelopeCodec::class)->decode(app(StringEncrypter::class)->decryptString($this->payloadOf($record)), $record->id);
    }

    /**
     * Bind a clock read once, giving the stand-in instant; a writer made
     * earlier keeps the real clock for its outbox.
     *
     * @return void
     */
    private function stampingClockOnce(): void
    {
        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andReturn(new CarbonImmutable(self::STAMP, 'UTC'));

        $this->app?->instance(Clock::class, $clock);
    }

    /**
     * Bind a clock that fails, so finalising does. A writer made before this
     * keeps the real clock for its outbox.
     *
     * @return void
     */
    private function breakTheClock(): void
    {
        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->andThrow(new \RuntimeException('The clock failed: ' . self::SECRET));

        $this->app?->instance(Clock::class, $clock);
    }

    /**
     * Make an outbox insert throw a query failure holding the secret, with the
     * SQLSTATE and driver code; once when told to, else always.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @param  bool  $once
     * @return void
     */
    private function breakTheInsert(string $message, string $state, int $code, bool $once = false): void
    {
        $previous = new \PDOException($message . ' ' . self::SECRET);

        $previous->errorInfo = [$state, $code, $message . ' ' . self::SECRET];

        $failure = new QueryException(self::CONNECTION, 'insert into "audit_log_outbox" ("note") values (?)', [self::SECRET], $previous);
        $thrown  = false;

        $this->outboxConnection()->beforeExecuting(static function (string $query) use ($failure, $once, &$thrown): void {
            if (!str_starts_with($query, 'insert into') || ($once && $thrown)) {
                return;
            }

            $thrown = true;

            throw $failure;
        });
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
}
