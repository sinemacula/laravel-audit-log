<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the tombstones on the re-delivery paths, on whichever
 * engine the suite runs against: an entry retention pruned, a record's or a
 * bundle's, is never stored again by the drain of an outbox row or the replay
 * of a spill line holding it, while a record beside it, never pruned, is.
 *
 * A test prunes a record as retention does: it is stored and sealed, then its
 * artifact and its entry are deleted, and its seal and member are kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(Replayer::class)]
#[CoversClass(PruneTombstones::class)]
final class PrunedRedeliveryEnginesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, PrunesByHand, SealsEntries, SeedsTheOutbox;

    /** @var string When each test starts, and its records are finalised. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string When the records are sealed: after each was recorded. */
    private const string SEALED_AT = '2026-11-01 12:30:00';

    /** @var ?string The spill file the test wrote. */
    private ?string $file = null;

    /**
     * Stop the clock, freeze the sealer's, and keep what a report would say out
     * of the output.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);
        $this->sealAt(self::SEALED_AT);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Put the clock back and remove the spill file.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->file !== null && is_file($this->file)) {
            unlink($this->file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The drain completes the rows of a pruned record and a pruned bundle as
     * pruned and stores neither, nor the bundle's artifact, and delivers the
     * row of a record beside them.
     *
     * @return void
     */
    public function testAPrunedEntryIsNeverResurrectedByTheDrain(): void
    {
        $record = $this->pruned($this->finalisedRecord());
        $bundle = $this->pruned($this->finalisedRecord(RecordFactory::bundled()));
        $fresh  = $this->finalisedRecord();

        $this->enqueue($record);
        $this->enqueue($bundle);
        $this->enqueue($fresh);

        $result = app(OutboxDrainer::class)->drain(100, false);

        self::assertSame([1, 2, 0], [$result->delivered(), $result->pruned(), $result->failed()]);
        self::assertSame(0, $this->outboxCount());
        self::assertSame([0, 0, 1], [$this->entriesUnder($record->record->id), $this->entriesUnder($bundle->record->id), $this->entriesUnder($fresh->record->id)]);
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * The spill replay counts the lines of a pruned record and a pruned bundle
     * as pruned and stores neither, nor the bundle's artifact, and replays the
     * line of a record beside them.
     *
     * @return void
     */
    public function testAPrunedEntryIsNeverResurrectedBySpillReplay(): void
    {
        $record = $this->pruned($this->finalisedRecord());
        $bundle = $this->pruned($this->finalisedRecord(RecordFactory::bundled()));
        $fresh  = $this->finalisedRecord();

        $this->file = $this->spillFile([
            FailureSpill::line($record->toArray()),
            FailureSpill::line(EnvelopeCodec::envelopeOf($bundle)),
            FailureSpill::line($fresh->toArray()),
        ]);

        $result = app(Replayer::class)->spill($this->file, false);

        self::assertSame([1, 2, 0], [$result->replayed(), $result->pruned(), $result->failed()]);
        self::assertSame([0, 0, 1], [$this->entriesUnder($record->record->id), $this->entriesUnder($bundle->record->id), $this->entriesUnder($fresh->record->id)]);
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * Store the record, seal it and prune it as retention would: its artifact
     * and its entry deleted, its seal and member kept, and a signed record of
     * the prune bound.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function pruned(#[\SensitiveParameter] FinalisedRecord $record): FinalisedRecord
    {
        $id = $record->record->id;

        $this->store()->store($record);

        self::assertSame(1, $this->sealAll()->entries());

        DB::connection(StorageConnection::name())->table(EntrySettings::artifactsTable())->where('entry_id', $id)->delete();

        $this->pruneByHand($id);

        return $record;
    }

    /**
     * A spill file of the lines, in order.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function spillFile(array $lines): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($path);

        file_put_contents($path, implode("\n", $lines) . "\n");

        return $path;
    }

    /**
     * The number of entries under the id.
     *
     * @param  string  $id
     * @return int
     */
    private function entriesUnder(string $id): int
    {
        return $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->count();
    }

    /**
     * The number of rows in the artifacts table.
     *
     * @return int
     */
    private function artifactCount(): int
    {
        return $this->storageConnection()->table(EntrySettings::artifactsTable())->count();
    }
}
