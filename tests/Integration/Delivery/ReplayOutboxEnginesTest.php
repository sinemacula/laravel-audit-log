<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Events\QueryExecuted;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for replaying the outbox on the engine the suite runs
 * against: a row that really failed reaches the store once it can, as it was
 * signed; a destination that has the record keeps its receipt and is not called
 * again; and a row whose application key was removed stays failed and is saved
 * by putting the key back in the previous keys; on SQLite, MySQL and PostgreSQL
 * alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Replayer::class)]
#[CoversClass(ReplayResult::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(Receipts::class)]
final class ReplayOutboxEnginesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string When a test's replay runs, once it moves the clock on. */
    private const string LATER = '2026-11-01T13:00:00.000000Z';

    /** @var string An application key the row was not encrypted under. */
    private const string OTHER_APP_KEY = 'base64:b3RoZXIgYXBwbGljYXRpb24ga2V5IGZvciB0ZXN0cyE=';

    /** @var string The destination of a store that is not a stack. */
    private const string STORE_DESTINATION = 'store';

    /** @var string The stack's database destination. */
    private const string DATABASE_DESTINATION = 'database';

    /** @var string The stack's other destination. */
    private const string SIEM_DESTINATION = 'siem.primary';

    /** @var bool Whether the stack's other destination fails. */
    private bool $siemIsDown = true;

    /** @var int The calls the stack's other destination has had. */
    private int $siemCalls = 0;

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
     * Undo what the test changed and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeProbeTable();
        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A record captured in outbox mode, whose row fails for good because the
     * engine refuses its write, replays to one entry once the table is back: as
     * it was signed, its receipt delivered and its row gone.
     *
     * @return void
     */
    public function testAFailedRowReplaysToOneEntry(): void
    {
        $id     = $this->failARowInTheDrain();
        $signed = $this->signedColumnsOf($id);

        self::assertSame(self::NOW, $this->outboxRow($id)['failed_at'] ?? null);
        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);
        self::assertSame(0, $this->entryCount());

        $this->moveClockTo(self::LATER);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());

        $stored = $this->storedRow($id);

        self::assertSame($signed, CanonicalEncoder::encode($stored));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));

        $receipt = $this->receipt($id, self::STORE_DESTINATION);

        self::assertSame(1, $receipt['attempts'] ?? null);
        self::assertSame(self::LATER, $receipt['delivered_at'] ?? null);
        self::assertNull($receipt['last_error_class'] ?? null);
    }

    /**
     * A second replay finds nothing to do, and adds no entry.
     *
     * @return void
     */
    public function testReplayingAgainAddsNothing(): void
    {
        $id = $this->failARowInTheDrain();

        $this->replayOutbox();

        self::assertSame([0, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(1, $this->entryCount());
        self::assertSame($id, $this->storedRow($id)['id']);
    }

    /**
     * A row whose entry is already stored, as a crash between the store and the
     * row's delete leaves it, gives no second entry, through the engine's own
     * duplicate check.
     *
     * @return void
     */
    public function testARowWhoseEntryIsStoredAddsNothing(): void
    {
        $record = $this->finalisedRecord();

        $this->store()->store($record);

        $id = $this->enqueue($record, ['failed_at' => self::NOW, 'attempts' => 10, 'last_error_class' => \DomainException::class]);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame($record->hmac, $this->storedRow($id)['hmac']);
    }

    /**
     * A database destination that has the record keeps its receipt to the
     * microsecond and sees no second insert, while the destination that failed
     * starts again and delivers it.
     *
     * @return void
     */
    public function testAReplayKeepsDeliveredReceipts(): void
    {
        app()->instance(AuditStore::class, new StackAuditStore([
            self::DATABASE_DESTINATION => app(DatabaseAuditStore::class),
            self::SIEM_DESTINATION     => new CallbackStore(function (): void {
                $this->siemCalls++;

                if ($this->siemIsDown) {
                    throw new \DomainException('The SIEM is down.');
                }
            }),
        ]));

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $id = $this->enqueue($this->finalisedRecord());

        self::assertSame(1, $this->drain()->failed());

        $delivered = $this->receipt($id, self::DATABASE_DESTINATION);

        self::assertSame(self::NOW, $delivered['delivered_at'] ?? null);
        self::assertSame(\DomainException::class, $this->receipt($id, self::SIEM_DESTINATION)['last_error_class'] ?? null);
        self::assertSame(1, $this->entryCount());

        $this->siemIsDown = false;

        $this->moveClockTo(self::LATER);

        $inserts = $this->countEntryInserts();

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayOutbox()));

        self::assertSame(0, $inserts->count);
        self::assertSame(2, $this->siemCalls);
        self::assertSame($delivered, $this->receipt($id, self::DATABASE_DESTINATION));
        self::assertSame(1, $this->receipt($id, self::SIEM_DESTINATION)['attempts'] ?? null);
        self::assertSame(self::LATER, $this->receipt($id, self::SIEM_DESTINATION)['delivered_at'] ?? null);
        self::assertNull($this->receipt($id, self::SIEM_DESTINATION)['last_error_class'] ?? null);
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A row under an application key that was removed fails as undecryptable
     * and is kept, payload and all, and with the key restored among the
     * previous keys a replay delivers it.
     *
     * @return void
     */
    public function testARestoredPreviousKeyDecrypts(): void
    {
        $key    = app(ConfigRepository::class)->string('app.key');
        $id     = $this->enqueue($this->finalisedRecord());
        $before = $this->outboxRow($id)['payload'] ?? null;

        $this->rotateApplicationKey([]);

        self::assertSame(1, $this->drain()->failed());
        self::assertSame('undecryptable', $this->outboxRow($id)['last_error_class'] ?? null);
        self::assertSame($before, $this->outboxRow($id)['payload'] ?? null);
        self::assertSame(0, $this->entryCount());

        $this->rotateApplicationKey([$key]);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($id)));
    }

    /**
     * A replay while the key is still missing fails again and keeps the row and
     * its payload, so restoring the key later can still save it.
     *
     * @return void
     */
    public function testAReplayWithTheKeyStillMissingKeepsTheRow(): void
    {
        $id     = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10, 'last_error_class' => 'undecryptable']);
        $before = $this->outboxRow($id)['payload'] ?? null;

        $this->rotateApplicationKey([]);
        $this->moveClockTo(self::LATER);

        self::assertSame([0, 0, 1, 0, []], self::tally($this->replayOutbox()));

        $row = $this->outboxRow($id);

        self::assertSame($before, $row['payload'] ?? null);
        self::assertSame(self::LATER, $row['failed_at'] ?? null);
        self::assertSame('undecryptable', $row['last_error_class'] ?? null);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A row whose envelope was altered fails again and writes no entry: a
     * replay gives it no way past its signature.
     *
     * @return void
     */
    public function testATamperedRowStaysFailed(): void
    {
        $record   = $this->finalisedRecord();
        $envelope = str_replace('1200.00', '9999.00', app(EnvelopeCodec::class)->encode($record));
        $id       = $record->record->id;

        $this->seedOutboxRow($id, app(StringEncrypter::class)->encryptString($envelope), ['failed_at' => self::NOW, 'attempts' => 10]);

        self::assertSame([0, 0, 1, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(0, $this->entryCount());
        self::assertSame('signature_mismatch', $this->outboxRow($id)['last_error_class'] ?? null);
    }

    /**
     * A replay reaches every failed row and a row due, and leaves a row whose
     * retry is not yet due, comparing times as each engine stores them.
     *
     * @return void
     */
    public function testAReplayLeavesARowNotYetDue(): void
    {
        $failed = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);
        $due    = $this->enqueue($this->finalisedRecord());
        $later  = $this->enqueue($this->finalisedRecord(), ['attempts' => 1, 'available_at' => self::LATER]);

        self::assertSame([2, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame($failed, $this->storedRow($failed)['id']);
        self::assertSame($due, $this->storedRow($due)['id']);
        self::assertSame(1, $this->outboxCount());
        self::assertSame(self::LATER, $this->outboxRow($later)['available_at'] ?? null);
    }

    /**
     * A failed row on an outbox of its own connection replays to one entry on
     * the storage connection, its receipt there too.
     *
     * @return void
     */
    public function testAFailedRowOnItsOwnConnectionReplays(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayOutbox()));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame(self::NOW, $this->receipt($id, self::STORE_DESTINATION)['delivered_at'] ?? null);
    }

    /**
     * A dry run lists the failed row and changes nothing: not its row, its
     * receipt or the entries.
     *
     * @return void
     */
    public function testADryRunChangesNothing(): void
    {
        $id = $this->failARowInTheDrain();

        $row     = $this->outboxRow($id);
        $receipt = $this->receipt($id, self::STORE_DESTINATION);

        $this->moveClockTo(self::LATER);

        $result = app(Replayer::class)->outbox(true);

        self::assertSame([0, 1, 0, 0, []], self::tally($result));
        self::assertSame(['outbox: would_replay ' . $id], $result->events());
        self::assertSame($row, $this->outboxRow($id));
        self::assertSame($receipt, $this->receipt($id, self::STORE_DESTINATION));
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Capture a record in outbox mode and drain it with one attempt allowed
     * while the store's table refuses it, so its row is failed for good, then
     * put the table back, and give back its id.
     *
     * @return string
     */
    private function failARowInTheDrain(): string
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $id = AuditLog::event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', '42'))
            ->withProperties(['amount' => '1200.00', 'note' => '%datetime%'])
            ->immediately()
            ->record()
            ->id;

        $this->pointAtProbeTable();

        self::assertSame(1, $this->drain()->failed());

        $this->removeProbeTable();

        return $id;
    }

    /**
     * Drain until nothing is left to claim.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, true);
    }

    /**
     * Replay the outbox.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     */
    private function replayOutbox(): ReplayResult
    {
        return app(Replayer::class)->outbox(false);
    }

    /**
     * The canonical encoding of what the outbox row under the id holds, read
     * back through its encryption, before a replay.
     *
     * @param  string  $id
     * @return string
     */
    private function signedColumnsOf(string $id): string
    {
        $payload = $this->outboxRow($id)['payload'] ?? null;

        self::assertIsString($payload);

        return app(EnvelopeCodec::class)->encode(app(EnvelopeCodec::class)->decode(app(StringEncrypter::class)->decryptString($payload), $id));
    }

    /**
     * A counter of the inserts into the entries table from now on.
     *
     * @return object{count: int}
     */
    private function countEntryInserts(): object
    {
        $inserts = new class {
            /** @var int The inserts into the entries table so far. */
            public int $count = 0;
        };

        $table = EntrySettings::table();

        $this->storageConnection()->listen(static function (QueryExecuted $query) use ($inserts, $table): void {
            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, $table)) {
                return;
            }

            $inserts->count++;
        });

        return $inserts;
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
     * The tally's counts: replayed, would replay, failed, deferred and skipped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return array{0: int, 1: int, 2: int, 3: int, 4: array<string, int>}
     */
    private static function tally(ReplayResult $result): array
    {
        return [$result->replayed(), $result->wouldReplay(), $result->failed(), $result->deferred(), $result->skipped()];
    }
}
