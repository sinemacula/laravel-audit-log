<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for the outbox drain: it delivers each due row's record, byte
 * for byte as it was finalised, and deletes the row before saying so; retries a
 * failure after a doubling wait, and fails and keeps a row at its last attempt,
 * reporting it then and only then; fails and keeps a row it cannot decrypt or
 * verify, and one that killed its worker too often; never lets a first worker
 * that outlived its lease change what a new owner did; runs from a fixed due
 * instant, so it always ends; refuses to run inside a transaction; and says
 * every failure inside the write guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(DrainResult::class)]
final class OutboxDrainerTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string Past the default lease of a claim taken at the start. */
    private const string PAST_THE_LEASE = '2026-11-01T12:05:01.000000Z';

    /** @var string An application key other than the one the tests start with. */
    private const string OTHER_APP_KEY = 'base64:b3RoZXIgYXBwbGljYXRpb24ga2V5IGZvciB0ZXN0cyE=';

    /**
     * Stop the clock at the start of the day's tests.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);
    }

    /**
     * Roll back any transaction a test left open, put the clock and the outbox
     * back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ([self::CONNECTION, self::MOVED_OUTBOX_CONNECTION] as $name) {

            if (!app(ConfigRepository::class)->has('database.connections.' . $name)) {
                continue;
            }

            $connection = DB::connection($name);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A due row's record reaches the store and the row is deleted.
     *
     * @return void
     */
    public function testDrainingStoresTheRecordAndDeletesTheRow(): void
    {
        $id = $this->enqueue($this->finalisedRecord());

        $result = $this->drain();

        self::assertSame([1, 0, 0, 0, 0], self::tally($result));
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertSame($id, $this->storedRow($id)['id']);
    }

    /**
     * The store receives the record the outbox was given, byte for byte, and
     * the database keeps its signature and its times as they were, and they
     * verify.
     *
     * @return void
     */
    public function testTheStoredBytesEqualTheFinalisedBytes(): void
    {
        $record = $this->finalisedRecord(RecordFactory::captured(['amount' => '1200.00', 'lines' => ['0' => 'a', '1' => 'b'], 'empty' => []]));
        $plain  = new PlainStore;

        $this->bindStore(new StackAuditStore(['database' => app(DatabaseAuditStore::class), 'plain' => $plain]));

        $id = $this->enqueue($record);

        $this->drain();

        $codec  = app(EnvelopeCodec::class);
        $stored = $this->storedRow($id);

        self::assertSame($codec->encode($record), $codec->encode($plain->received()[0]));
        self::assertSame($record->hmac, $stored['hmac']);
        self::assertSame($record->recordedAt, $stored['recorded_at']);
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
    }

    /**
     * The drain never finalises a record again: one put in the outbox an hour
     * before it is drained keeps the time it was first recorded at.
     *
     * @return void
     */
    public function testRecordedAtIsTheFirstFinalisation(): void
    {
        $record = $this->finalisedRecord();
        $id     = $this->enqueue($record);

        $this->moveClockTo('2026-11-01T13:00:00.000000Z');

        $this->drain();

        self::assertSame($record->recordedAt, $this->storedRow($id)['recorded_at']);
        self::assertSame('2026-11-01T12:00:00.123456Z', $this->storedRow($id)['recorded_at']);
    }

    /**
     * `AuditRecorded` is dispatched once, after the row is deleted, carrying
     * the record's id, code and category.
     *
     * @return void
     */
    public function testAuditRecordedFollowsTheDelete(): void
    {
        $record = $this->finalisedRecord();
        $id     = $this->enqueue($record);
        $seen   = [];

        Event::listen(AuditRecorded::class, function (AuditRecorded $event) use (&$seen): void {
            $seen[] = [$event->id, $event->code, $event->category, $this->outboxRow($event->id)];
        });

        $this->drain();

        self::assertSame([[$id, 'invoice.approved', $record->record->category, null]], $seen);
    }

    /**
     * A row whose delivery failed says nothing of a write.
     *
     * @return void
     */
    public function testAuditRecordedIsNotDispatchedForAFailure(): void
    {
        Event::fake([AuditRecorded::class]);

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));
        $this->enqueue($this->finalisedRecord());

        $this->drain();

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * A listener of `AuditRecorded` that throws is reported, and the row stays
     * deleted and counted delivered.
     *
     * @return void
     */
    public function testAThrowingAuditRecordedListenerKeepsTheRowDeleted(): void
    {
        $handler   = $this->recordingHandler();
        $exception = new \RuntimeException('The listener failed.');

        Event::listen(AuditRecorded::class, static function () use ($exception): never {
            throw $exception;
        });

        $this->enqueue($this->finalisedRecord());

        $result = $this->drain();

        self::assertSame(1, $result->delivered());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame([$exception], $handler->reports());
    }

    /**
     * The store is the one bound when the drain runs, not when the record was
     * put in the outbox.
     *
     * @return void
     */
    public function testAStoreBoundLaterIsTheOneUsed(): void
    {
        $this->enqueue($this->finalisedRecord());

        $store = $this->bindStore(new PlainStore);

        $this->drain();

        self::assertSame(1, $store->calls());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A row whose destination failed is released, unclaimed and not failed, for
     * a retry after the first wait, its attempt counted.
     *
     * @return void
     */
    public function testAFailureRetriesWithBackoff(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord());

        $result = $this->drain();
        $row    = $this->outboxRow($id);

        self::assertSame([0, 1, 0, 0, 0], self::tally($result));
        self::assertFalse($result->hasFailures());
        self::assertIsArray($row);
        self::assertSame(1, $row['attempts']);
        self::assertSame('2026-11-01T12:01:00.000000Z', $row['available_at']);
        self::assertNull($row['claimed_by']);
        self::assertNull($row['claimed_until']);
        self::assertNull($row['failed_at']);
    }

    /**
     * Rows of `[attempt made, seconds waited after it]`: the first wait, then
     * double after each attempt, never more than an hour.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideBackoffs(): iterable
    {
        yield from [
            'the first attempt'   => [1, 60],
            'the second attempt'  => [2, 120],
            'the third attempt'   => [3, 240],
            'the sixth attempt'   => [6, 1920],
            'the seventh attempt' => [7, 3600],
            'the fortieth'        => [40, 3600],
        ];
    }

    /**
     * The wait doubles with each attempt and is capped at an hour.
     *
     * @param  int  $attempt
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideBackoffs')]
    public function testTheBackoffDoublesAndIsCapped(int $attempt, int $seconds): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1000);

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord(), ['attempts' => $attempt - 1]);

        $this->drain();

        self::assertSame($attempt, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame(CarbonImmutable::parse(self::NOW)->addSeconds($seconds)->format('Y-m-d\TH:i:s.u\Z'), $this->outboxRow($id)['available_at'] ?? null);
    }

    /**
     * The wait starts from the configured first wait.
     *
     * @return void
     */
    public function testTheBackoffStartsFromTheSetting(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.backoff_seconds', 5);

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord(), ['attempts' => 1]);

        $this->drain();

        self::assertSame('2026-11-01T12:00:10.000000Z', $this->outboxRow($id)['available_at'] ?? null);
    }

    /**
     * A retried row keeps the class of the failure, never its message.
     *
     * @return void
     */
    public function testAFailureKeepsTheErrorClass(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down, with a secret.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord());

        $this->drain();

        self::assertSame(\DomainException::class, $this->outboxRow($id)['last_error_class'] ?? null);
    }

    /**
     * A failure on the last attempt fails the row and keeps it, unclaimed, with
     * the failure's class, and the drain has failures.
     *
     * @return void
     */
    public function testTheFinalAttemptFailsTheRowAndKeepsIt(): void
    {
        $this->recordingHandler();
        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        $result = $this->drain();
        $row    = $this->outboxRow($id);

        self::assertSame([0, 0, 1, 0, 0], self::tally($result));
        self::assertTrue($result->hasFailures());
        self::assertIsArray($row);
        self::assertSame(10, $row['attempts']);
        self::assertSame(self::NOW, $row['failed_at']);
        self::assertSame(\DomainException::class, $row['last_error_class']);
        self::assertNull($row['claimed_by']);
    }

    /**
     * The final failure is reported once, payload-free, naming the record, its
     * code, the drain, the destination's class and the failure's class.
     *
     * @return void
     */
    public function testTheFinalFailureIsReported(): void
    {
        $handler = $this->recordingHandler();
        $record  = $this->finalisedRecord();

        $this->bindStore(new StackAuditStore(['remote' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: [])]));
        $this->enqueue($record, ['attempts' => 9]);

        $this->drain();

        $reports = $handler->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame($record->record->id, $reports[0]->recordId);
        self::assertSame('invoice.approved', $reports[0]->eventCode);
        self::assertSame('drain', $reports[0]->operation);
        self::assertSame(CallbackStore::class, $reports[0]->store);
        self::assertSame(\DomainException::class, $reports[0]->exceptionClass);
        self::assertSame('remote', $reports[0]->destination);
        self::assertNull($reports[0]->getPrevious());
    }

    /**
     * The final failure dispatches `AuditWriteFailed` once, with the record's
     * id and code, the destination's class and the failure's class.
     *
     * @return void
     */
    public function testTheFinalFailureDispatchesAuditWriteFailed(): void
    {
        $this->recordingHandler();

        Event::fake([AuditWriteFailed::class]);

        $record = $this->finalisedRecord();

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));
        $this->enqueue($record, ['attempts' => 9]);

        $this->drain();

        Event::assertDispatchedTimes(AuditWriteFailed::class, 1);
        Event::assertDispatched(AuditWriteFailed::class, static fn (AuditWriteFailed $event): bool => $event->id === $record->record->id
            && $event->code                                                                                      === 'invoice.approved'
            && $event->store                                                                                     === CallbackStore::class
            && $event->exception                                                                                 === \DomainException::class);
    }

    /**
     * A failure before the last attempt is neither reported nor said: it is
     * kept on the row and its receipt for the next attempt.
     *
     * @return void
     */
    public function testATransientFailureIsNotReported(): void
    {
        $handler = $this->recordingHandler();

        Event::fake([AuditWriteFailed::class]);

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));
        $this->enqueue($this->finalisedRecord(), ['attempts' => 8]);

        $this->drain();

        self::assertSame([], $handler->reports());
        Event::assertNotDispatched(AuditWriteFailed::class);
    }

    /**
     * A failed row is never claimed again: a later drain, after any wait, finds
     * nothing and calls nothing.
     *
     * @return void
     */
    public function testAFailedRowIsNotClaimedAgain(): void
    {
        $this->recordingHandler();

        $calls = 0;

        $this->bindStore(new CallbackStore(static function () use (&$calls): void {
            $calls++;

            throw new \DomainException('Down.');
        }, participatesOn: []));

        $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        $this->drain();

        $this->moveClockTo('2026-11-02T12:00:00.000000Z');

        self::assertSame([0, 0, 0, 0, 0], self::tally($this->drain()));
        self::assertSame(1, $calls);
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A row claimed with more attempts than it may have, which only a worker
     * killed on each of them leaves, is failed as abandoned without being
     * delivered, and reported by its id alone.
     *
     * @return void
     */
    public function testARowThatCrashedPastItsAttemptsIsAbandoned(): void
    {
        $handler = $this->recordingHandler();
        $store   = $this->bindStore(new PlainStore);

        Event::fake([AuditWriteFailed::class]);

        $id = $this->enqueue($this->finalisedRecord(), ['attempts' => 10]);

        $result = $this->drain();

        self::assertSame([0, 0, 1, 0, 0], self::tally($result));
        self::assertSame(0, $store->calls());
        self::assertSame('abandoned', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame(self::NOW, $this->outboxRow($id)['failed_at'] ?? null);
        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $handler->reports()[0]);
        self::assertSame($id, $handler->reports()[0]->recordId);
        self::assertNull($handler->reports()[0]->eventCode);
        self::assertSame('abandoned', $handler->reports()[0]->exceptionClass);
        Event::assertNotDispatched(AuditWriteFailed::class);
    }

    /**
     * A row on its last attempt is not abandoned: it is delivered.
     *
     * @return void
     */
    public function testARowOnItsLastAttemptIsStillDelivered(): void
    {
        $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        self::assertSame(1, $this->drain()->delivered());
    }

    /**
     * A payload that cannot be decrypted fails the row as undecryptable and
     * keeps it as it was.
     *
     * @return void
     */
    public function testAnUndecryptablePayloadIsFailedAndKept(): void
    {
        $this->recordingHandler();

        $id = RecordFactory::captured()->id;

        $this->seedOutboxRow($id, 'not-an-encrypted-payload');

        $result = $this->drain();

        self::assertSame(1, $result->failed());
        self::assertSame('undecryptable', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame('not-an-encrypted-payload', $this->outboxRow($id)['payload'] ?? null);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An undecryptable row is reported by its id, with no code, and says
     * nothing through `AuditWriteFailed`, which needs the code.
     *
     * @return void
     */
    public function testAnUndecryptableRowIsReportedById(): void
    {
        $handler = $this->recordingHandler();

        Event::fake([AuditWriteFailed::class]);

        $id = RecordFactory::captured()->id;

        $this->seedOutboxRow($id, 'not-an-encrypted-payload');

        $this->drain();

        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $handler->reports()[0]);
        self::assertSame($id, $handler->reports()[0]->recordId);
        self::assertNull($handler->reports()[0]->eventCode);
        self::assertSame(DecryptException::class, $handler->reports()[0]->exceptionClass);
        Event::assertNotDispatched(AuditWriteFailed::class);
    }

    /**
     * A row encrypted under an application key since retired, but still among
     * the previous keys, decrypts and verifies, and is delivered.
     *
     * @return void
     */
    public function testARetiredKeyStillInPreviousKeysDecrypts(): void
    {
        $config = app(ConfigRepository::class);
        $old    = $config->string('app.key');

        $this->enqueue($this->finalisedRecord());

        $this->rotateApplicationKey([$old]);

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A row encrypted under an application key no longer configured at all
     * cannot be decrypted, so it is failed as undecryptable and kept.
     *
     * @return void
     */
    public function testAPayloadUnderARemovedKeyIsUndecryptable(): void
    {
        $this->recordingHandler();

        $id = $this->enqueue($this->finalisedRecord());

        $this->rotateApplicationKey([]);

        self::assertSame(1, $this->drain()->failed());
        self::assertSame('undecryptable', $this->outboxRow($id)['last_error_class'] ?? null);
    }

    /**
     * An envelope altered after it was signed fails its row as a signature
     * mismatch, and the row is kept, altered as it was found.
     *
     * @return void
     */
    public function testATamperedEnvelopeIsFailedAndKept(): void
    {
        $this->recordingHandler();

        $record  = $this->finalisedRecord();
        $id      = $record->record->id;
        $payload = $this->encrypt(str_replace('inv_0042', 'inv_0043', app(EnvelopeCodec::class)->encode($record)));

        $this->seedOutboxRow($id, $payload);

        self::assertSame(1, $this->drain()->failed());
        self::assertSame('signature_mismatch', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame($payload, $this->outboxRow($id)['payload'] ?? null);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An envelope signed under an integrity key since removed from the ring
     * cannot be verified, so its row is failed as an unknown key and kept,
     * never signed again under the current key.
     *
     * @return void
     */
    public function testAnEnvelopeUnderARemovedSigningKeyIsFailedAndNeverResigned(): void
    {
        $this->recordingHandler();

        $config = app(ConfigRepository::class);

        $config->set(['audit-log.integrity.keys' => ['k1' => 'a-first-secret-of-32-bytes-long!'], 'audit-log.integrity.current' => 'k1']);

        $id      = $this->enqueue($this->finalisedRecord());
        $payload = $this->outboxRow($id)['payload'] ?? null;

        $config->set(['audit-log.integrity.keys' => ['k2' => 'a-second-secret-of-32-bytes-ok!!'], 'audit-log.integrity.current' => 'k2']);

        self::assertSame(1, $this->drain()->failed());
        self::assertSame('unknown_key', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame($payload, $this->outboxRow($id)['payload'] ?? null);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An envelope kept under an id other than its own fails its row as an id
     * mismatch, and the row is kept.
     *
     * @return void
     */
    public function testAnIdMismatchIsFailedAndKept(): void
    {
        $handler = $this->recordingHandler();
        $other   = RecordFactory::captured()->id;

        $this->seedOutboxRow($other, $this->encryptedEnvelope($this->finalisedRecord()));

        self::assertSame(1, $this->drain()->failed());
        self::assertSame('id_mismatch', $this->outboxRow($other)['last_error_class'] ?? null);
        self::assertSame(0, $this->entryCount());
        self::assertSame($other, self::onlyReport($handler)->recordId);
        self::assertSame(EnvelopeRejectedException::class, self::onlyReport($handler)->exceptionClass);
    }

    /**
     * A row that cannot be decrypted stops no other row.
     *
     * @return void
     */
    public function testOneBadRowStopsNoOther(): void
    {
        $this->recordingHandler();

        $this->seedOutboxRow(RecordFactory::captured()->id, 'not-an-encrypted-payload');
        $this->enqueue($this->finalisedRecord());

        $result = $this->drain();

        self::assertSame([1, 0, 1, 0, 0], self::tally($result));
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A row whose receipts cannot be read is a failed delivery like any other:
     * it retries after its backoff, keeps the failure's class, is not reported
     * and stops no other row.
     *
     * @return void
     */
    public function testARowWhoseReceiptsCannotBeReadRetriesAfterItsBackoff(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord());
        $good    = $this->enqueue($this->finalisedRecord());

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings) use ($bad): void {
            if (str_starts_with($query, 'select ') && str_contains($query, DeliveryTables::deliveriesTable()) && in_array($bad, $bindings, true)) {
                throw new \DomainException('The receipts cannot be read.');
            }
        });

        $result = $this->drain();

        self::assertSame([1, 1, 0, 0, 0], self::tally($result));
        self::assertNull($this->outboxRow($good));

        $row = $this->outboxRow($bad);

        self::assertNotNull($row);
        self::assertNull($row['claimed_by']);
        self::assertSame(\DomainException::class, $row['last_error_class']);
        self::assertSame('2026-11-01T12:01:00.000000Z', $row['available_at']);
        self::assertSame([], $handler->reports());
    }

    /**
     * Rows of `[which receipt statement fails]`: each statement of the
     * deliveries table a delivery runs for the first time.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReceiptStatements(): iterable
    {
        yield from [
            'reading the receipts' => ['select '],
            'counting the attempt' => ['insert '],
        ];
    }

    /**
     * Whichever statement of the deliveries table fails, an outage of the
     * storage connection is retried with a backoff that doubles, keeps the
     * failure's class, is reported once at the last attempt, and never reads as
     * `abandoned`, which means only that a worker died.
     *
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideReceiptStatements')]
    public function testAStorageOutageBacksOffAndIsReportedOnceAtTheLastAttempt(string $statement): void
    {
        $handler = $this->recordingHandler();
        $id      = $this->enqueue($this->finalisedRecord());

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 3);

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query) use ($statement): void {
            if (str_starts_with($query, $statement) && str_contains($query, DeliveryTables::deliveriesTable())) {
                throw new \DomainException('The storage connection is down.');
            }
        });

        foreach ([['2026-11-01T12:01:00.000000Z', '2026-11-01T13:00:00.000000Z'], ['2026-11-01T15:02:00.000000Z', '2026-11-01T15:00:00.000000Z']] as $wave => [$next, $then]) {
            $this->drain();

            self::assertSame($wave + 1, $this->outboxRow($id)['attempts'] ?? null);
            self::assertSame([], $handler->reports());
            self::assertSame(\DomainException::class, $this->outboxRow($id)['last_error_class'] ?? null);
            self::assertSame($next, $this->outboxRow($id)['available_at'] ?? null);

            $this->moveClockTo($then === '2026-11-01T15:00:00.000000Z' ? '2026-11-01T16:00:00.000000Z' : '2026-11-01T15:00:00.000000Z');
        }

        $this->drain();

        $row = $this->outboxRow($id);

        self::assertNotNull($row);
        self::assertNotNull($row['failed_at']);
        self::assertSame(\DomainException::class, $row['last_error_class']);
        self::assertSame(\DomainException::class, self::onlyReport($handler)->exceptionClass);
    }

    /**
     * A failed delivery whose receipt cannot be written either still ends in a
     * retry naming what the destination failed with.
     *
     * @return void
     */
    public function testAFailedReceiptKeepsTheDestinationsFailure(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \LogicException('The destination is down.'), participatesOn: []));

        $id = $this->enqueue($this->finalisedRecord());

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'update ') && str_contains($query, DeliveryTables::deliveriesTable())) {
                throw new \DomainException('The deliveries table is down.');
            }
        });

        self::assertSame([0, 1, 0, 0, 0], self::tally($this->drain()));
        self::assertSame(\LogicException::class, $this->outboxRow($id)['last_error_class'] ?? null);
    }

    /**
     * A row whose work stops for a reason a delivery does not expect, here a
     * renewal that fails, is reported payload-free, retried after its backoff
     * rather than left on its lease, and stops no other row.
     *
     * @return void
     */
    public function testARowThatCannotBeWorkedIsReportedAndRetriedAndStopsNoOther(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord());
        $good    = $this->enqueue($this->finalisedRecord());

        $this->failTheRenewalOf($bad, 1);

        self::assertSame([1, 1, 0, 0, 0], self::tally($this->drain()));
        self::assertNull($this->outboxRow($good));

        $row = $this->outboxRow($bad);

        self::assertNotNull($row);
        self::assertNull($row['claimed_by']);
        self::assertSame(\DomainException::class, $row['last_error_class']);
        self::assertSame($bad, self::onlyReport($handler)->recordId);
        self::assertSame(\DomainException::class, self::onlyReport($handler)->exceptionClass);
    }

    /**
     * When the retry cannot be written either, the row keeps its claim until
     * the lease passes, reported once and counted failed.
     *
     * @return void
     */
    public function testARowWhoseRetryCannotBeWrittenKeepsItsClaim(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord());

        $this->failTheRenewalOf($bad, PHP_INT_MAX);

        self::assertSame([0, 0, 1, 0, 0], self::tally($this->drain()));
        self::assertNotNull($this->outboxRow($bad)['claimed_by'] ?? null);
        self::assertSame($bad, self::onlyReport($handler)->recordId);
    }

    /**
     * The same failure at the last attempt fails the row, reported once and not
     * twice, and never as abandoned.
     *
     * @return void
     */
    public function testAnUnexpectedFailureAtTheLastAttemptFailsTheRow(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        $this->failTheRenewalOf($bad, 1);

        self::assertSame([0, 0, 1, 0, 0], self::tally($this->drain()));

        $row = $this->outboxRow($bad);

        self::assertNotNull($row);
        self::assertNotNull($row['failed_at']);
        self::assertSame(\DomainException::class, $row['last_error_class']);
        self::assertSame(\DomainException::class, self::onlyReport($handler)->exceptionClass);
    }

    /**
     * At the last attempt with the outbox out of reach too, the failure is
     * still reported once, and the row keeps its claim.
     *
     * @return void
     */
    public function testAnUnexpectedFailureAtTheLastAttemptWithNoOutboxIsStillReported(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        $this->failTheRenewalOf($bad, PHP_INT_MAX);

        self::assertSame([0, 0, 1, 0, 0], self::tally($this->drain()));
        self::assertNull($this->outboxRow($bad)['failed_at'] ?? null);
        self::assertSame($bad, self::onlyReport($handler)->recordId);
    }

    /**
     * A claim that fails is reported and counted missed, and the rest of the
     * batch is still worked.
     *
     * @return void
     */
    public function testAFailedClaimIsReportedAndStopsNoOther(): void
    {
        $handler = $this->recordingHandler();
        $bad     = $this->enqueue($this->finalisedRecord());
        $good    = $this->enqueue($this->finalisedRecord());

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings) use ($bad): void {
            if (str_starts_with($query, 'update ') && str_contains($query, DeliveryTables::outboxTable()) && in_array($bad, $bindings, true)) {
                throw new \DomainException('The claim failed.');
            }
        });

        self::assertSame([1, 0, 0, 0, 1], self::tally($this->drain()));
        self::assertNull($this->outboxRow($good));
        self::assertNull($this->outboxRow($bad)['claimed_by'] ?? null);
        self::assertSame($bad, self::onlyReport($handler)->recordId);
    }

    /**
     * A tally passed in holds the rows already worked when reading the next
     * batch stops the run.
     *
     * @return void
     */
    public function testATallyPassedInSurvivesAFailureReadingTheRows(): void
    {
        $this->enqueue($this->finalisedRecord());

        $reads = 0;

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query) use (&$reads): void {
            if (str_starts_with($query, 'select ') && str_contains($query, DeliveryTables::outboxTable()) && str_contains($query, 'available_at') && ++$reads === 2) {
                throw new \DomainException('The outbox cannot be read.');
            }
        });

        $result = new DrainResult;

        try {
            app(OutboxDrainer::class)->drain(1, true, $result);

            self::fail('Expected the failure to stop the run.');
        } catch (\DomainException) {
            self::assertSame([1, 0, 0, 0, 0], self::tally($result));
        }
    }

    /**
     * A row another worker claims between this drain reading it and claiming it
     * is counted missed and left to that worker, whose claim is the only one
     * taken, and the drain goes on to the next row.
     *
     * @return void
     */
    public function testARowAnotherWorkerClaimedFirstIsMissedAndStopsNoOther(): void
    {
        $taken = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T11:00:00.000000Z']);
        $free  = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T11:00:01.000000Z']);

        $outbox  = app(Outbox::class);
        $claimed = false;

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings) use ($taken, $outbox, &$claimed): void {
            if ($claimed || !str_starts_with($query, 'update ') || !in_array($taken, $bindings, true)) {
                return;
            }

            $claimed = true;

            $outbox->claim($taken, CarbonImmutable::now());
        });

        $result = $this->drain();

        self::assertSame([1, 0, 0, 0, 1], self::tally($result));
        self::assertNull($this->outboxRow($free));
        self::assertSame(1, (int) ($this->outboxRow($taken)['attempts'] ?? 0));
    }

    /**
     * A first worker still inside its destination when its lease passes and a
     * new owner delivers and deletes the row cannot delete it: it is stale, and
     * only the new owner counts the delivery.
     *
     * @return void
     */
    public function testALiveFirstWorkerPastItsLeaseCannotDelete(): void
    {
        $nested = $this->takeOverInsideTheDestination(static function (): void {});

        $result = $this->drain();

        self::assertSame([0, 0, 0, 1, 0], self::tally($result));
        self::assertInstanceOf(DrainResult::class, $nested[0] ?? null);
        self::assertSame([1, 0, 0, 0, 0], self::tally($nested[0]));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A first worker whose destination fails after a new owner has retried the
     * row cannot retry it again: the row keeps the new owner's wait.
     *
     * @return void
     */
    public function testALiveFirstWorkerPastItsLeaseCannotRetry(): void
    {
        $nested = $this->takeOverInsideTheDestination(static function (): never {
            throw new \DomainException('Down.');
        }, firstFails: true);

        $id = $this->enqueuedId();

        $result = $this->drain();

        self::assertSame([0, 0, 0, 1, 0], self::tally($result));
        self::assertSame([0, 1, 0, 0, 0], self::tally($nested[0]));
        self::assertSame(2, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame('2026-11-01T12:07:01.000000Z', $this->outboxRow($id)['available_at'] ?? null);
    }

    /**
     * A first worker on its last attempt whose destination fails after a new
     * owner has failed the row cannot fail it again or report it: only the new
     * owner's abandonment is said.
     *
     * @return void
     */
    public function testALiveFirstWorkerPastItsLeaseCannotFail(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $handler = $this->recordingHandler();

        Event::fake([AuditWriteFailed::class]);

        $nested = $this->takeOverInsideTheDestination(static function (): void {}, firstFails: true);

        $id = $this->enqueuedId();

        $result = $this->drain();

        self::assertSame([0, 0, 0, 1, 0], self::tally($result));
        self::assertSame([0, 0, 1, 0, 0], self::tally($nested[0]));
        self::assertSame('abandoned', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame('abandoned', self::onlyReport($handler)->exceptionClass);
        Event::assertNotDispatched(AuditWriteFailed::class);
    }

    /**
     * A first worker whose destination succeeds after its lease passed writes
     * no receipt of it: the receipt shows the new owner's failure, still
     * undelivered.
     *
     * @return void
     */
    public function testALiveFirstWorkerPastItsLeaseWritesNoReceipt(): void
    {
        $this->takeOverInsideTheDestination(static function (): never {
            throw new \DomainException('Down.');
        });

        $id = $this->enqueuedId();

        $this->drain();

        $receipt = $this->receipt($id, 'store');

        self::assertIsArray($receipt);
        self::assertSame(2, $receipt['attempts']);
        self::assertNull($receipt['delivered_at']);
        self::assertSame(\DomainException::class, $receipt['last_error_class']);
    }

    /**
     * The new owner finishes the work: the row is delivered, its receipt marked
     * at the new owner's time, and deleted.
     *
     * @return void
     */
    public function testANewOwnerFinishesTheWork(): void
    {
        $this->takeOverInsideTheDestination(static function (): void {});

        $id = $this->enqueuedId();

        $this->drain();

        self::assertNull($this->outboxRow($id));
        self::assertSame(self::PAST_THE_LEASE, $this->receipt($id, 'store')['delivered_at'] ?? null);
    }

    /**
     * Both owners call the database, which keeps the record once.
     *
     * @return void
     */
    public function testTheRecordIsStoredOnce(): void
    {
        $this->takeOverInsideTheDestination(static function (FinalisedRecord $record): void {
            app(DatabaseAuditStore::class)->store($record);
        }, firstStores: true);

        $this->drain();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A stale owner says nothing: `AuditRecorded` is dispatched once, by the
     * new owner, and `AuditWriteFailed` never.
     *
     * @return void
     */
    public function testAStaleOwnerDispatchesNoEvent(): void
    {
        $recorded = 0;
        $failed   = 0;

        Event::listen(AuditRecorded::class, static function () use (&$recorded): void {
            $recorded++;
        });

        Event::listen(AuditWriteFailed::class, static function () use (&$failed): void {
            $failed++;
        });

        $this->takeOverInsideTheDestination(static function (): void {});

        $this->drain();

        self::assertSame(1, $recorded);
        self::assertSame(0, $failed);
    }

    /**
     * A run drains at most the limit of rows, oldest first.
     *
     * @return void
     */
    public function testTheLimitHolds(): void
    {
        $first  = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T11:00:00.000000Z']);
        $second = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T11:00:01.000000Z']);
        $third  = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T11:00:02.000000Z']);

        $result = $this->drain(2);

        self::assertSame(2, $result->delivered());
        self::assertNull($this->outboxRow($first));
        self::assertNull($this->outboxRow($second));
        self::assertNotNull($this->outboxRow($third));
    }

    /**
     * Until empty, a run drains batch after batch until no due row is left.
     *
     * @return void
     */
    public function testUntilEmptyDrainsEveryDueRow(): void
    {
        foreach (range(1, 5) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $result = $this->drain(2, true);

        self::assertSame(5, $result->delivered());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Until empty, a run takes only the rows due when it began, so it ends even
     * while every delivery puts another row in the outbox.
     *
     * @return void
     */
    public function testUntilEmptyEndsWhileRowsArrive(): void
    {
        $this->bindStore(new CallbackStore(function (): void {
            $this->moveClockTo(CarbonImmutable::now()->addSecond()->format('Y-m-d\TH:i:s.u\Z'));
            $this->enqueue($this->finalisedRecord());
        }, participatesOn: []));

        $this->enqueue($this->finalisedRecord());
        $this->enqueue($this->finalisedRecord());

        $result = $this->drain(1, true);

        self::assertSame(2, $result->delivered());
        self::assertSame(2, $this->outboxCount());
    }

    /**
     * Until empty, a run in which every row fails ends: a retried row waits
     * past the instant the run began.
     *
     * @return void
     */
    public function testUntilEmptyEndsWhenEveryRowFails(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));

        $this->enqueue($this->finalisedRecord());
        $this->enqueue($this->finalisedRecord());

        self::assertSame([0, 2, 0, 0, 0], self::tally($this->drain(1, true)));
    }

    /**
     * A drain of an empty outbox counts nothing and has no failures.
     *
     * @return void
     */
    public function testADrainOfNothingIsNothing(): void
    {
        $result = $this->drain(100, true);

        self::assertSame([0, 0, 0, 0, 0], self::tally($result));
        self::assertFalse($result->hasFailures());
    }

    /**
     * A row not yet due is left for a later run.
     *
     * @return void
     */
    public function testARowNotYetDueIsLeft(): void
    {
        $id = $this->enqueue($this->finalisedRecord(), ['available_at' => '2026-11-01T12:00:00.000001Z']);

        self::assertSame([0, 0, 0, 0, 0], self::tally($this->drain()));
        self::assertSame(0, $this->outboxRow($id)['attempts'] ?? null);
    }

    /**
     * Rows of `[whether the outbox has a connection of its own]`: a transaction
     * on the storage connection, and one on a dedicated outbox connection.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideTransactionConnections(): iterable
    {
        yield from [
            'the storage connection'        => [false],
            'a dedicated outbox connection' => [true],
        ];
    }

    /**
     * A drain inside a transaction on either connection is refused before any
     * row is claimed.
     *
     * @param  bool  $moved
     * @return void
     */
    #[DataProvider('provideTransactionConnections')]
    public function testRefusesToRunInsideATransaction(bool $moved): void
    {
        if ($moved) {
            $this->moveOutboxToItsOwnConnection();
        }

        $id = $this->enqueue($this->finalisedRecord());

        DB::connection($moved ? self::MOVED_OUTBOX_CONNECTION : self::CONNECTION)->beginTransaction();

        try {
            $this->drain();

            self::fail('Expected the drain to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The outbox is drained outside any transaction, so a receipt and its delete are never held by a commit that may not come.', $exception->getMessage());
        }

        self::assertSame(0, $this->outboxRow($id)['attempts'] ?? null);
        self::assertNull($this->outboxRow($id)['claimed_by'] ?? null);
    }

    /**
     * A missing application key is an exception out of the drain that claims no
     * row, never a row failed as undecryptable.
     *
     * @return void
     */
    public function testAMissingKeyTouchesNoRow(): void
    {
        $id = $this->enqueue($this->finalisedRecord());

        app(ConfigRepository::class)->set('app.key', '');
        app()->forgetInstance('encrypter');

        try {
            $this->drain();

            self::fail('Expected the drain to fail without an application key.');
        } catch (\RuntimeException) {
            self::assertSame(0, $this->outboxRow($id)['attempts'] ?? null);
            self::assertNull($this->outboxRow($id)['failed_at'] ?? null);
        }
    }

    /**
     * The final failure is reported and said inside the write guard, so a
     * record made by the reporter or a listener is refused.
     *
     * @return void
     */
    public function testTheGuardIsActiveWhileTheFinalFailureIsSaid(): void
    {
        $active  = [];
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->andReturnUsing(static function () use (&$active): void {
            $active['report'] = app(WriteGuard::class)->isActive();
        });

        app()->instance(ExceptionHandler::class, $handler);

        Event::listen(AuditWriteFailed::class, static function () use (&$active): void {
            $active['event'] = app(WriteGuard::class)->isActive();
        });

        $this->bindStore(CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []));
        $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);

        $this->drain();

        self::assertSame(['report' => true, 'event' => true], $active);
        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * A broken reporter and a throwing listener of the final failure stop
     * nothing: the row is still failed and the next row still drained.
     *
     * @return void
     */
    public function testABrokenReporterAndListenerStopNothing(): void
    {
        $this->recordingHandler(throwsOnReport: true);

        Event::listen(AuditWriteFailed::class, static function (): never {
            throw new \RuntimeException('The listener failed.');
        });

        $failing = true;

        $this->bindStore(new CallbackStore(static function () use (&$failing): void {
            if ($failing) {
                $failing = false;

                throw new \DomainException('Down.');
            }
        }, participatesOn: []));

        $this->enqueue($this->finalisedRecord(), ['attempts' => 9, 'available_at' => '2026-11-01T11:00:00.000000Z']);
        $this->enqueue($this->finalisedRecord());

        self::assertSame([1, 0, 1, 0, 0], self::tally($this->drain()));
    }

    /**
     * Fail the given number of updates of the row after its claim, the first of
     * them its renewal, as a connection that drops would.
     *
     * @param  string  $id
     * @param  int  $times
     * @return void
     */
    private function failTheRenewalOf(string $id, int $times): void
    {
        $claimed = false;

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings) use ($id, &$claimed, &$times): void {
            if (!str_starts_with($query, 'update ') || !str_contains($query, DeliveryTables::outboxTable()) || !in_array($id, $bindings, true)) {
                return;
            }

            if (!$claimed) {
                $claimed = true;

                return;
            }

            if ($times-- > 0) {
                throw new \DomainException('The outbox cannot be written.');
            }
        });
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @param  int  $limit
     * @param  bool  $untilEmpty
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     *
     * @throws \LogicException
     */
    private function drain(int $limit = 100, bool $untilEmpty = false): DrainResult
    {
        return app(OutboxDrainer::class)->drain($limit, $untilEmpty);
    }

    /**
     * The tally's counts: delivered, retried, failed, stale and missed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return list<int>
     */
    private static function tally(DrainResult $result): array
    {
        return [$result->delivered(), $result->retried(), $result->failed(), $result->stale(), $result->missed()];
    }

    /**
     * Bind the store and return it.
     *
     * @template TStore of \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     *
     * @param  TStore  $store
     * @return TStore
     */
    private function bindStore(AuditStore $store): AuditStore
    {
        app()->instance(AuditStore::class, $store);

        return $store;
    }

    /**
     * Bind a handler that keeps what it is asked to report and return it.
     *
     * @param  bool  $throwsOnReport
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function recordingHandler(bool $throwsOnReport = false): RecordingExceptionHandler
    {
        $handler = new RecordingExceptionHandler($throwsOnReport);

        app()->instance(ExceptionHandler::class, $handler);

        return $handler;
    }

    /**
     * The one report the handler was asked to make, which must be a failed
     * write.
     *
     * @param  \Tests\Fixtures\Privacy\RecordingExceptionHandler  $handler
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private static function onlyReport(RecordingExceptionHandler $handler): AuditWriteFailedException
    {
        $reports = $handler->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);

        return $reports[0];
    }

    /**
     * The payload encrypted as a string by the application's encrypter.
     *
     * @param  string  $payload
     * @return string
     */
    private function encrypt(string $payload): string
    {
        return app(StringEncrypter::class)->encryptString($payload);
    }

    /**
     * Replace the application key with another, keeping the previous keys
     * given, and rebuild the encrypter.
     *
     * @param  list<string>  $previous
     * @return void
     */
    private function rotateApplicationKey(array $previous): void
    {
        app(ConfigRepository::class)->set(['app.key' => self::OTHER_APP_KEY, 'app.previous_keys' => $previous]);
        app()->forgetInstance('encrypter');
    }

    /**
     * The id of the one row in the outbox.
     *
     * @return string
     */
    private function enqueuedId(): string
    {
        $id = $this->outboxConnection()->table(DeliveryTables::outboxTable())->value('id');

        self::assertIsString($id);

        return $id;
    }

    /**
     * Put a record in the outbox and bind a non-participating destination whose
     * first call, the first worker's, moves the clock past its lease and runs a
     * second drain, the new owner, inside it. The new owner's call runs the
     * work given; the first worker's call then returns, or throws when told to,
     * having run the work first when told to. Returns the list the new owner's
     * tally is put in.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\FinalisedRecord): void  $work
     * @param  bool  $firstFails
     * @param  bool  $firstStores
     * @return \ArrayObject<int, \SineMacula\Laravel\AuditLog\Delivery\DrainResult>
     */
    private function takeOverInsideTheDestination(\Closure $work, bool $firstFails = false, bool $firstStores = false): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Delivery\DrainResult> $nested */
        $nested = new \ArrayObject;
        $calls  = 0;

        $this->bindStore(new CallbackStore(function (FinalisedRecord $record) use ($work, $firstFails, $firstStores, $nested, &$calls): void {
            if (++$calls > 1) {
                $work($record);

                return;
            }

            $this->moveClockTo(self::PAST_THE_LEASE);

            $nested[] = $this->drain();

            if ($firstStores) {
                $work($record);
            }

            if ($firstFails) {
                throw new \DomainException('Down.');
            }
        }, participatesOn: []));

        $this->enqueue($this->finalisedRecord());

        return $nested;
    }
}
