<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Delivery\SpillLine;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsArtifacts;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for replaying records from a spill file or the outbox; a dry
 * run changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Replayer::class)]
#[CoversClass(ReplayResult::class)]
#[CoversClass(SpillReader::class)]
#[CoversClass(SpillLine::class)]
final class ReplayerTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsArtifacts, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string When a test's replay runs, once it moves the clock on. */
    private const string LATER = '2026-11-01T13:00:00.000000Z';

    /** @var string The import batch an imported record came in. */
    private const string IMPORT_BATCH_ID = '019a4b2e-7c10-7000-8000-00000000abcd';

    /** @var string One secret of the integrity key ring. */
    private const string FIRST_SECRET = 'a-first-secret-of-32-bytes-long!';

    /** @var string The other secret of the integrity key ring. */
    private const string SECOND_SECRET = 'a-second-secret-of-32-bytes-ok!!';

    /** @var list<string> The files each test wrote. */
    private array $files = [];

    /**
     * Stop the clock at the start of the day's tests, and keep what a report
     * would say out of the output.
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
     * Put the clock back and remove the files the test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The row a replay stores encodes to the bytes of the line's JSON, once its
     * escaped `%` decodes, a value that would otherwise be rewritten included.
     *
     * @return void
     */
    public function testSpillThenReplayGivesOneRowEqualToTheSpilledBytes(): void
    {
        $record = $this->finalisedRecord(RecordFactory::captured(['note' => '%datetime% and 100%', 'lines' => ['0' => 'a', '1' => 'b'], 'empty' => []]));
        $line   = self::lineOf($record);
        $result = $this->replaySpill($line);

        $expected = str_replace('\u0025', '%', substr($line, strlen(FailureSpill::MARKER)));

        self::assertStringContainsString('\u0025datetime\u0025', $line);
        self::assertSame(1, $result->replayed());
        self::assertSame(1, $this->entryCount());
        self::assertSame($expected, CanonicalEncoder::encode($this->storedRow($record->record->id)));
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($record->record->id)));
    }

    /**
     * A second replay of one file finds its record already stored, unchanged,
     * and adds nothing.
     *
     * @return void
     */
    public function testReplayingTwiceAddsNothing(): void
    {
        $record = $this->finalisedRecord();
        $path   = $this->file(self::lineOf($record) . "\n");

        $this->replayer()->spill($path, false);

        $row    = CanonicalEncoder::encode($this->storedRow($record->record->id));
        $second = $this->replayer()->spill($path, false);

        self::assertSame([1, 0, 0, 0, []], self::tally($second));
        self::assertSame(1, $this->entryCount());
        self::assertSame($row, CanonicalEncoder::encode($this->storedRow($record->record->id)));
    }

    /**
     * A line with a channel's prefix and suffix around it replays.
     *
     * @return void
     */
    public function testAChannelPrefixedLineParses(): void
    {
        $record = $this->finalisedRecord();
        $result = $this->replaySpill('[2026-11-01 12:00:00] production.CRITICAL: ' . self::lineOf($record) . ' [] []');

        self::assertSame(1, $result->replayed());
        self::assertSame($record->record->id, $this->storedRow($record->record->id)['id']);
    }

    /**
     * A replayed record keeps its id, its envelope and a captured provenance.
     *
     * @return void
     */
    public function testKeepsIdEnvelopeAndProvenance(): void
    {
        $record = $this->finalisedRecord();

        $this->replaySpill(self::lineOf($record));

        $stored = $this->storedRow($record->record->id);

        self::assertSame($record->record->id, $stored['id']);
        self::assertSame('captured', $stored['provenance']);
        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($stored));
    }

    /**
     * An imported record keeps its provenance, its source, its batch and its
     * source digest, so a replay never turns it into something captured here.
     *
     * @return void
     */
    public function testAnImportedShapeKeepsItsProvenance(): void
    {
        $record = $this->finalisedRecord(RecordFactory::withFields([
            'provenance'       => 'imported',
            'source_record_id' => 'legacy-0042',
            'import_batch_id'  => self::IMPORT_BATCH_ID,
            'source_digest'    => str_repeat('4a', 32),
            'origin'           => null,
        ]));

        $this->replaySpill(self::lineOf($record));

        $stored = $this->storedRow($record->record->id);

        self::assertSame('imported', $stored['provenance']);
        self::assertSame('legacy-0042', $stored['source_record_id']);
        self::assertSame(self::IMPORT_BATCH_ID, $stored['import_batch_id']);
        self::assertSame(str_repeat('4a', 32), $stored['source_digest']);
        self::assertNull($stored['origin']);
    }

    /**
     * A line whose value was altered is skipped as a signature mismatch, by its
     * id, and stored nowhere.
     *
     * @return void
     */
    public function testATamperedLineIsSkippedAndCounted(): void
    {
        $record = $this->finalisedRecord();
        $result = $this->replaySpill(str_replace('1200.00', '9999.00', self::lineOf($record)));

        self::assertSame([0, 0, 0, 0, ['signature_mismatch' => 1]], self::tally($result));
        self::assertSame(['line 1: signature_mismatch ' . $record->record->id], $result->events());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A line spilled before it was signed is counted and left: nothing here can
     * say where its bytes came from.
     *
     * @return void
     */
    public function testAnUnsignedLineIsSkippedAndCounted(): void
    {
        $record = RecordFactory::captured();
        $result = $this->replaySpill(FailureSpill::line(['unsigned' => true, ...$record->toArray()]));

        self::assertSame([0, 0, 0, 0, ['unsigned' => 1]], self::tally($result));
        self::assertSame(['line 1: unsigned ' . $record->id], $result->events());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[the line]`: lines with the marker that hold no well-formed
     * record, whether the reader or the codec is the one to say so.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedLines(): iterable
    {
        yield from [
            'an object that is not a record' => [FailureSpill::MARKER . '{"id":"x"}'],
            'an object that is not JSON'     => [FailureSpill::MARKER . '{"a":}'],
            'something other than an object' => [FailureSpill::MARKER . 'not json'],
        ];
    }

    /**
     * A malformed line is skipped and counted.
     *
     * @param  string  $line
     * @return void
     */
    #[DataProvider('provideMalformedLines')]
    public function testAMalformedLineIsSkippedAndCounted(string $line): void
    {
        $result = $this->replaySpill($line);

        self::assertSame([0, 0, 0, 0, ['malformed' => 1]], self::tally($result));
        self::assertSame(['line 1: malformed'], $result->events());
    }

    /**
     * A line under a key the ring no longer holds is quarantined, not called
     * altered, not signed again, and left in the file.
     *
     * @return void
     */
    public function testAnUnknownKeyIsSkippedAndCounted(): void
    {
        $this->useKeys(['k1' => self::FIRST_SECRET], 'k1');

        $record = $this->finalisedRecord();
        $line   = self::lineOf($record);
        $path   = $this->file($line . "\n");

        $this->useKeys(['k2' => self::SECOND_SECRET], 'k2');

        $result = $this->replayer()->spill($path, false);

        self::assertSame([0, 0, 0, 0, ['unknown_key' => 1]], self::tally($result));
        self::assertSame(0, $this->entryCount());
        self::assertSame($line . "\n", file_get_contents($path));
    }

    /**
     * A line in a version this release does not read is counted as that, and as
     * nothing else.
     *
     * @return void
     */
    public function testAnUnsupportedVersionIsSkippedAndCounted(): void
    {
        $result = $this->replaySpill(FailureSpill::MARKER . self::envelopeWith($this->finalisedRecord(), ['record_version' => 99]));

        self::assertSame([0, 0, 0, 0, ['unsupported_version' => 1]], self::tally($result));
    }

    /**
     * A line cut short is counted and never repaired.
     *
     * @return void
     */
    public function testATruncatedLineIsSkippedAndCounted(): void
    {
        $line   = self::lineOf($this->finalisedRecord());
        $result = $this->replaySpill(substr($line, 0, (int) (strlen($line) / 2)));

        self::assertSame([0, 0, 0, 0, ['truncated' => 1]], self::tally($result));
        self::assertSame(['line 1: truncated'], $result->events());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * One file of every outcome counts each apart, by its line, and replays
     * what verifies; the lines of another channel are not counted at all.
     *
     * @return void
     */
    public function testEachOutcomeIsCountedApart(): void
    {
        $this->useKeys(['k1' => self::FIRST_SECRET], 'k1');

        $unknown = self::lineOf($this->finalisedRecord());

        $this->useKeys(['k2' => self::SECOND_SECRET], 'k2');

        $good     = $this->finalisedRecord();
        $tampered = str_replace('1200.00', '9999.00', self::lineOf($this->finalisedRecord()));
        $version  = FailureSpill::MARKER . self::envelopeWith($this->finalisedRecord(), ['record_version' => 99]);
        $unsigned = FailureSpill::line(['unsigned' => true, ...RecordFactory::captured()->toArray()]);
        $cut      = substr(self::lineOf($this->finalisedRecord()), 0, 80);

        $result = $this->replaySpill('another channel', self::lineOf($good), $tampered, $unknown, $version, FailureSpill::MARKER . '{"id":"x"}', $unsigned, $cut);

        self::assertSame([1, 0, 0, 0, [
            'signature_mismatch'  => 1,
            'unknown_key'         => 1,
            'unsupported_version' => 1,
            'malformed'           => 1,
            'unsigned'            => 1,
            'truncated'           => 1,
        ]], self::tally($result));
        self::assertSame(1, $this->entryCount());
        self::assertSame('line 2: replayed ' . $good->record->id, $result->events()[0]);
        self::assertSame('line 8: truncated', $result->events()[6]);
    }

    /**
     * A store's failure is counted by record id and failure class, never its
     * message, and stops no other line.
     *
     * @return void
     */
    public function testAStoreFailureIsCountedByIdAndClass(): void
    {
        $bad   = $this->finalisedRecord();
        $good  = $this->finalisedRecord();
        $saved = new PlainStore;
        $said  = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$said): void {
            $said[] = $event->id;
        });

        $this->bindStore(new CallbackStore(static function (FinalisedRecord $record) use ($bad, $saved): void {
            if ($record->record->id === $bad->record->id) {
                throw new \DomainException('Down, holding the record.');
            }

            $saved->store($record);
        }));

        $result = $this->replaySpill(self::lineOf($bad), self::lineOf($good));

        self::assertSame([1, 0, 1, 0, []], self::tally($result));
        self::assertSame('line 1: failed ' . $bad->record->id . ' (DomainException)', $result->events()[0]);
        self::assertSame(1, $saved->calls());
        self::assertSame([$good->record->id], $said);
    }

    /**
     * A record signed under a key that is no longer current verifies and stays
     * signed under that key.
     *
     * @return void
     */
    public function testNeverResigns(): void
    {
        $this->useKeys(['k1' => self::FIRST_SECRET], 'k1');

        $record = $this->finalisedRecord();
        $line   = self::lineOf($record);

        $this->useKeys(['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET], 'k2');

        $result = $this->replaySpill($line);
        $stored = $this->storedRow($record->record->id);

        self::assertSame(1, $result->replayed());
        self::assertSame(['k1', $record->hmac], [$stored['key_id'], $stored['hmac']]);
    }

    /**
     * A record replayed an hour after it was finalised keeps the time it was
     * first recorded at.
     *
     * @return void
     */
    public function testNeverFinalisesAgain(): void
    {
        $record = $this->finalisedRecord();
        $line   = self::lineOf($record);

        $this->moveClockTo(self::LATER);

        $this->replaySpill($line);

        self::assertSame($record->recordedAt, $this->storedRow($record->record->id)['recorded_at']);
    }

    /**
     * `AuditRecorded` is dispatched once the store has the record, with its id,
     * code and category, outside the write guard.
     *
     * @return void
     */
    public function testAuditRecordedFollowsAReplay(): void
    {
        $record = $this->finalisedRecord();
        $seen   = [];

        Event::listen(AuditRecorded::class, function (AuditRecorded $event) use (&$seen): void {
            $seen[] = [$event->id, $event->code, $event->category, $this->entryCount(), app(WriteGuard::class)->isActive()];
        });

        $this->replaySpill(self::lineOf($record));

        self::assertSame([[$record->record->id, 'invoice.approved', $record->record->category, 1, false]], $seen);
    }

    /**
     * A record reaches the store inside the write guard, so a record made there
     * is refused rather than recursing.
     *
     * @return void
     */
    public function testTheStoreRunsInsideTheGuard(): void
    {
        $active = [];

        $this->bindStore(new CallbackStore(static function () use (&$active): void {
            $active[] = app(WriteGuard::class)->isActive();
        }));

        $this->replaySpill(self::lineOf($this->finalisedRecord()));

        self::assertSame([true], $active);
        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * A listener's failure is contained: the record is stored, so it is
     * replayed.
     *
     * @return void
     */
    public function testAThrowingListenerIsStillReplayed(): void
    {
        Event::listen(AuditRecorded::class, static function (): never {
            throw new \DomainException('A listener failed.');
        });

        $result = $this->replaySpill(self::lineOf($this->finalisedRecord()));

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
    }

    /**
     * A file that cannot be read is refused before anything happens.
     *
     * @return void
     */
    public function testAMissingFileIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->replayer()->spill(sys_get_temp_dir() . '/audit-log-no-such-spill-file.log', false);
    }

    /**
     * A failed row is requeued and drained: its record reaches the store and
     * the row goes.
     *
     * @return void
     */
    public function testRequeuesAndDrainsFailedRows(): void
    {
        $record = $this->finalisedRecord();

        $this->enqueue($record, ['failed_at' => self::NOW, 'attempts' => 10, 'last_error_class' => \DomainException::class]);

        $result = $this->replayer()->outbox(false);

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
        self::assertSame(0, $this->outboxCount());
        self::assertSame($record->hmac, $this->storedRow($record->record->id)['hmac']);
    }

    /**
     * The drain runs until the outbox is empty, past its first batch, so one
     * replay reaches every failed row.
     *
     * @return void
     */
    public function testDrainsPastTheFirstBatch(): void
    {
        $store = new PlainStore;

        $this->bindStore($store);

        foreach (range(1, 101) as $ignored) {
            $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);
        }

        self::assertSame(101, $this->replayer()->outbox(false)->replayed());
        self::assertSame(101, $store->calls());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A replay clears the failure and starts the attempts again, so a row that
     * fails again has this attempt alone against it, and waits for its retry.
     *
     * @return void
     */
    public function testClearsFailedAtAndAttempts(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \DomainException('Still down.'), false));

        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10, 'last_error_class' => \OverflowException::class]);

        $result = $this->replayer()->outbox(false);
        $row    = $this->outboxRow($id);

        self::assertSame([0, 0, 1, 0, []], self::tally($result));
        self::assertNull($row['failed_at'] ?? null);
        self::assertSame(1, $row['attempts'] ?? null);
        self::assertSame(\DomainException::class, $row['last_error_class'] ?? null);
        self::assertSame('2026-11-01T12:01:00.000000Z', $row['available_at'] ?? null);
    }

    /**
     * A destination that already has the record keeps its receipt as it was.
     *
     * @return void
     */
    public function testKeepsSuccessfulReceipts(): void
    {
        $id = $this->failedRowOfTwoDestinations();

        $this->seedReceipt($id, 'first', attempts: 2, delivered: true);
        $this->seedReceipt($id, 'second', attempts: 3, error: \DomainException::class);

        $before = $this->receipt($id, 'first');

        $this->moveClockTo(self::LATER);

        self::assertSame(1, $this->replayer()->outbox(false)->replayed());
        self::assertSame($before, $this->receipt($id, 'first'));
    }

    /**
     * The receipt of a destination that does not have the record starts again,
     * and only that one.
     *
     * @return void
     */
    public function testResetsOnlyFailedReceipts(): void
    {
        $this->bindStore(new StackAuditStore([
            'first'  => new PlainStore,
            'second' => CallbackStore::failingWith(new \DomainException('Still down.'), false),
        ]));

        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);

        $this->seedReceipt($id, 'first', attempts: 2, delivered: true);
        $this->seedReceipt($id, 'second', attempts: 9, error: \OverflowException::class);

        $this->replayer()->outbox(false);

        self::assertSame(2, $this->receipt($id, 'first')['attempts'] ?? null);
        self::assertSame(1, $this->receipt($id, 'second')['attempts'] ?? null);
        self::assertSame(\DomainException::class, $this->receipt($id, 'second')['last_error_class'] ?? null);
    }

    /**
     * A replay calls only the destination that does not have the record.
     *
     * @return void
     */
    public function testAReplayReachesOnlyTheFailedDestination(): void
    {
        $first  = new PlainStore;
        $second = new PlainStore;

        $this->bindStore(new StackAuditStore(['first' => $first, 'second' => $second]));

        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);

        $this->seedReceipt($id, 'first', attempts: 1, delivered: true);
        $this->seedReceipt($id, 'second', attempts: 10, error: \DomainException::class);

        $this->replayer()->outbox(false);

        self::assertSame([0, 1], [$first->calls(), $second->calls()]);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A row that still cannot be decrypted fails again and is kept as it was,
     * with the time of this failure, so restoring the key can still save it.
     *
     * @return void
     */
    public function testAnUndecryptableRowFailsAgainAndIsKept(): void
    {
        $id = RecordFactory::captured()->id;

        $this->seedOutboxRow($id, 'not-an-encrypted-payload', ['failed_at' => self::NOW, 'attempts' => 10]);
        $this->moveClockTo(self::LATER);

        $result = $this->replayer()->outbox(false);
        $row    = $this->outboxRow($id);

        self::assertSame([0, 0, 1, 0, []], self::tally($result));
        self::assertSame('not-an-encrypted-payload', $row['payload'] ?? null);
        self::assertSame(self::LATER, $row['failed_at'] ?? null);
        self::assertSame(1, $row['attempts'] ?? null);
        self::assertSame('undecryptable', $row['last_error_class'] ?? null);
    }

    /**
     * A row that is due and did not fail goes with the drain, since the drain
     * takes every row due, and counts as replayed.
     *
     * @return void
     */
    public function testARowDueGoesWithTheDrain(): void
    {
        $this->enqueue($this->finalisedRecord());

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replayer()->outbox(false)));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A spilled bundle is replayed whole, entry and artifact, and
     * `AuditRecorded` follows.
     *
     * @return void
     */
    public function testASpilledBundleIsReplayedWhole(): void
    {
        $record = $this->finalisedRecord(RecordFactory::bundled());
        $id     = $record->record->id;
        $said   = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$said): void {
            $said[] = $event->id;
        });

        $result = $this->replaySpill(self::bundleLineOf($record));

        $attachment = $record->record->attachment;
        $artifact   = $this->artifactOf($id);

        self::assertNotNull($attachment);
        self::assertIsArray($artifact);

        $expected = $attachment->envelopeFor($id);

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
        self::assertSame(1, $this->entryCount());
        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($this->storedRow($id)));
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($id)));
        self::assertSame($expected, array_replace($expected, array_intersect_key($artifact, $expected)));
        self::assertSame([$id], $said);
    }

    /**
     * A spilled bundle the store keeps no attachments of is counted failed and
     * left in the file; a plain line beside it is replayed.
     *
     * @return void
     */
    public function testABundleToAStoreKeepingNoAttachmentsIsCountedFailed(): void
    {
        $bundle = $this->finalisedRecord(RecordFactory::bundled());
        $plain  = $this->finalisedRecord();
        $store  = new PlainStore;
        $said   = 0;

        Event::listen(AuditRecorded::class, static function () use (&$said): void {
            $said++;
        });

        $this->bindStore($store);

        $contents = self::bundleLineOf($bundle) . "\n" . self::lineOf($plain) . "\n";
        $path     = $this->file($contents);
        $result   = $this->replayer()->spill($path, false);

        self::assertSame([1, 0, 1, 0, []], self::tally($result));
        self::assertSame('line 1: failed ' . $bundle->record->id . ' (LogicException)', $result->events()[0]);
        self::assertSame([$plain->record->id], array_map(static fn (FinalisedRecord $received): string => $received->record->id, $store->received()));
        self::assertSame(1, $said);
        self::assertSame($contents, file_get_contents($path));
    }

    /**
     * A stack with one destination keeping no attachments keeps none, so a
     * spilled bundle is refused before any destination.
     *
     * @return void
     */
    public function testABundleToAStackWithADestinationKeepingNoneIsCountedFailed(): void
    {
        $this->bindStore(new StackAuditStore(['database' => $this->store(), 'plain' => new PlainStore]));

        $record = $this->finalisedRecord(RecordFactory::bundled());
        $result = $this->replaySpill(self::bundleLineOf($record));

        self::assertSame([0, 0, 1, 0, []], self::tally($result));
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactsTable()->count());
    }

    /**
     * A spilled bundle the store already holds is a no-op, counted replayed.
     *
     * @return void
     */
    public function testAReplayedBundleThatIsStoredAlreadyIsANoOp(): void
    {
        $record = $this->finalisedRecord(RecordFactory::bundled());
        $id     = $record->record->id;

        $this->store()->store($record);

        $row      = CanonicalEncoder::encode($this->storedRow($id));
        $artifact = $this->artifactOf($id);
        $result   = $this->replaySpill(self::bundleLineOf($record));

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactsTable()->count());
        self::assertSame($row, CanonicalEncoder::encode($this->storedRow($id)));
        self::assertSame($artifact, $this->artifactOf($id));
    }

    /**
     * A failed outbox row holding a bundle is requeued and drained whole: the
     * entry and its artifact are stored and the row goes.
     *
     * @return void
     */
    public function testAFailedBundleRowIsReplayedWhole(): void
    {
        $record = $this->finalisedRecord(RecordFactory::bundled());
        $id     = $this->enqueue($record, ['failed_at' => self::NOW, 'attempts' => 10, 'last_error_class' => \LogicException::class]);

        $result = $this->replayer()->outbox(false);

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
        self::assertSame(0, $this->outboxCount());
        self::assertSame($record->hmac, $this->storedRow($id)['hmac']);
        self::assertNotNull($this->artifactOf($id));
    }

    /**
     * A failed outbox row holding a bundle that a destination still keeps no
     * attachments of is retried by the replay's drain and kept, never deleted.
     *
     * @return void
     */
    public function testAFailedBundleRowToAStoreKeepingNoAttachmentsIsKept(): void
    {
        $this->bindStore(new PlainStore);

        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled()), ['failed_at' => self::NOW, 'attempts' => 10]);

        $result = $this->replayer()->outbox(false);

        self::assertSame(0, $result->replayed());
        self::assertSame(1, $this->outboxCount());
        self::assertSame(\LogicException::class, $this->outboxRow($id)['last_error_class'] ?? null);
    }

    /**
     * A dry run counts a spilled bundle it would replay and changes nothing.
     *
     * @return void
     */
    public function testADryRunCountsASpilledBundle(): void
    {
        $record = $this->finalisedRecord(RecordFactory::bundled());
        $result = $this->replayer()->spill($this->file(self::bundleLineOf($record) . "\n"), true);

        self::assertSame([0, 1, 0, 0, []], self::tally($result));
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactsTable()->count());
    }

    /**
     * Rows of `[what is replayed]`.
     *
     * @return iterable<string, array{0: 'outbox'|'spill'}>
     */
    public static function provideSources(): iterable
    {
        yield from [
            'a spill file' => ['spill'],
            'the outbox'   => ['outbox'],
        ];
    }

    /**
     * A dry run changes no row, receipt, entry or file and dispatches no event,
     * with both kinds of work waiting.
     *
     * @param  'outbox'|'spill'  $source
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testADryRunChangesNothing(string $source): void
    {
        $id   = $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);
        $path = $this->file(self::lineOf($this->finalisedRecord()) . "\n");
        $said = 0;

        $this->seedReceipt($id, 'store', attempts: 10, error: \DomainException::class);

        foreach ([AuditRecorded::class, AuditWriteFailed::class] as $event) {
            Event::listen($event, static function () use (&$said): void {
                $said++;
            });
        }

        $before = $this->snapshot($path);

        $this->moveClockTo(self::LATER);

        $source === 'spill' ? $this->replayer()->spill($path, true) : $this->replayer()->outbox(true);

        self::assertSame($before, $this->snapshot($path));
        self::assertSame(0, $said);
    }

    /**
     * A dry run counts what would be replayed and lists each by its id.
     *
     * @param  'outbox'|'spill'  $source
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testADryRunCountsWhatItWouldDo(string $source): void
    {
        $first  = $this->finalisedRecord();
        $second = $this->finalisedRecord();
        $ids    = [$first->record->id, $second->record->id];
        $store  = new PlainStore;

        $this->bindStore($store);

        if ($source === 'spill') {
            $result = $this->replayer()->spill($this->file(self::lineOf($first) . "\n" . self::lineOf($second) . "\n"), true);
            $where  = ['line 1', 'line 2'];
        } else {
            sort($ids);

            $this->seedFailedPayloadRow($ids[0]);
            $this->seedFailedPayloadRow($ids[1]);

            $result = $this->replayer()->outbox(true);
            $where  = ['outbox', 'outbox'];
        }

        self::assertSame([0, 2, 0, 0, []], self::tally($result));
        self::assertSame([$where[0] . ': would_replay ' . $ids[0], $where[1] . ': would_replay ' . $ids[1]], $result->events());
        self::assertSame(0, $store->calls());
    }

    /**
     * A dry run still skips and counts each line that would not verify.
     *
     * @return void
     */
    public function testADryRunStillCountsTheSkipped(): void
    {
        $record = $this->finalisedRecord();
        $path   = $this->file(str_replace('1200.00', '9999.00', self::lineOf($record)) . "\n");
        $result = $this->replayer()->spill($path, true);

        self::assertSame([0, 0, 0, 0, ['signature_mismatch' => 1]], self::tally($result));
        self::assertTrue($result->hasSkippedOrFailed());
    }

    /**
     * The replayer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\Replayer
     */
    private function replayer(): Replayer
    {
        return app(Replayer::class);
    }

    /**
     * Replay a file of the lines given.
     *
     * @param  string  ...$lines
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     */
    private function replaySpill(string ...$lines): ReplayResult
    {
        return $this->replayer()->spill($this->file(implode("\n", $lines) . "\n"), false);
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

    /**
     * The spill line of the finalised record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    private static function lineOf(FinalisedRecord $record): string
    {
        return FailureSpill::line($record->toArray());
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
     * The record's envelope with the columns given in place of its own.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array<string, int|string|null>  $columns
     * @return string
     */
    private static function envelopeWith(FinalisedRecord $record, array $columns): string
    {
        return CanonicalEncoder::encode([...$record->toArray(), ...$columns]);
    }

    /**
     * Use the integrity key ring given.
     *
     * @param  array<string, string>  $keys
     * @param  string  $current
     * @return void
     */
    private function useKeys(array $keys, string $current): void
    {
        app(ConfigRepository::class)->set(['audit-log.integrity.keys' => $keys, 'audit-log.integrity.current' => $current]);
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
     * A file holding the contents, removed when the test ends.
     *
     * @param  string  $contents
     * @return string
     */
    private function file(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * Bind a stack of two stores that take anything and put a failed row in the
     * outbox, returning its id.
     *
     * @return string
     */
    private function failedRowOfTwoDestinations(): string
    {
        $this->bindStore(new StackAuditStore(['first' => new PlainStore, 'second' => new PlainStore]));

        return $this->enqueue($this->finalisedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);
    }

    /**
     * Seed a failed row holding a payload that is never read.
     *
     * @param  string  $id
     * @return void
     */
    private function seedFailedPayloadRow(string $id): void
    {
        $this->seedOutboxRow($id, 'never-read', ['failed_at' => self::NOW, 'attempts' => 10]);
    }

    /**
     * Seed a receipt of the destination for the entry, attempted now and, when
     * told, delivered now.
     *
     * @param  string  $id
     * @param  string  $destination
     * @param  int  $attempts
     * @param  bool  $delivered
     * @param  ?string  $error
     * @return void
     */
    private function seedReceipt(string $id, string $destination, int $attempts, bool $delivered = false, ?string $error = null): void
    {
        $now = StoredTime::toStorage(self::NOW);

        DB::connection(StorageConnection::name())->table(DeliveryTables::deliveriesTable())->insert([
            'entry_id'           => $id,
            'destination'        => $destination,
            'attempts'           => $attempts,
            'first_attempted_at' => $now,
            'delivered_at'       => $delivered ? $now : null,
            'last_error_class'   => $error,
        ]);
    }

    /**
     * Everything a replay could change: the outbox, the receipts, the entries
     * and the spill file.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @return array<string, mixed>
     */
    private function snapshot(string $path): array
    {
        $storage = DB::connection(StorageConnection::name());
        $rows    = static fn (Builder $table, string $column): array => array_map(static fn (object $row): array => (array) $row, $table->orderBy($column)->get()->all());

        return [
            'outbox'   => $rows($this->outboxConnection()->table(DeliveryTables::outboxTable()), 'id'),
            'receipts' => $rows($storage->table(DeliveryTables::deliveriesTable()), 'entry_id'),
            'entries'  => $rows($storage->table(EntrySettings::table()), 'id'),
            'file'     => file_get_contents($path),
        ];
    }
}
