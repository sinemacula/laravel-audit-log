<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\JournalVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\ConnectsSecondDatabases;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for importing another system's records into the audit log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditImporter::class)]
final class AuditImporterTest extends TestCase
{
    use ConnectsSecondDatabases, SealsEntries, WritesTheJournal;

    /** @var string When every import runs. */
    private const string NOW = '2026-11-02 09:00:00.000000';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every import is of, unless a test names another. */
    private const string SOURCE = 'crm-eu';

    /** @var string The refusal of a batch that cannot be closed. */
    private const string NOT_CLOSABLE = 'Only a running import batch, or a final one whose finish was never journalled, is closed.';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, name this installation's source and bind the retention
     * policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * Put the clock back and remove the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * A dry run reads and counts but writes nothing.
     *
     * @return void
     */
    public function testADryRunWritesNothing(): void
    {
        $path   = $this->file([self::line('rec-1'), self::line('rec-2'), self::line('rec-3', ['event' => 'audit_log.pruned']), '{']);
        $writes = [];

        DB::listen(static function (QueryExecuted $query) use (&$writes): void {
            if (str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
                return;
            }

            $writes[] = $query->sql;
        });

        $result = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), dryRun: true, hold: true);

        self::assertSame([], $writes);
        self::assertFalse($result->committed);
        self::assertTrue($result->dryRun);
        self::assertNull($result->batchId);
        self::assertNull($result->status);
        self::assertNull($result->hold);
        self::assertSame([4, 2, 0, 0, 2], [$result->linesRead, $result->imported, $result->duplicates, $result->conflicts, $result->rejected]);
        self::assertSame(['reserved_code' => 1, 'malformed_json' => 1], $result->rejections);
        self::assertSame(0, $this->rowsIn(EntrySettings::table()));
        self::assertSame(0, $this->rowsIn(LifecycleTables::importBatchesTable()));
        self::assertSame([], $this->journalRows());
    }

    /**
     * An imported row carries its source identity, batch and digest, signed and
     * sealed like any row.
     *
     * @return void
     */
    public function testEveryColumnOfAnImportedRow(): void
    {
        $line   = self::line('rec-1', ['origin' => null, 'occurred_at' => '2026-11-02T09:02:00.000000Z']);
        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-0'), $line]), self::SOURCE, 'eu-west-2'), self::authority());
        $rows   = $this->rows();

        self::assertCount(2, $rows);

        [$first, $future] = $rows;

        $source = [$first['provenance'], $first['source_id'], $first['source_region'], $first['source_record_id'], $first['import_batch_id']];

        self::assertSame(['imported', self::SOURCE, 'eu-west-2', 'rec-0', $result->batchId], $source);
        self::assertSame('http', $first['origin']);
        self::assertNull($future['origin']);
        self::assertSame('2026-10-01T09:00:00.000001Z', $first['occurred_at']);
        self::assertSame('2026-11-02T09:00:00.000000Z', $first['recorded_at']);
        self::assertSame('2026-11-02T09:02:00.000000Z', $future['occurred_at']);
        self::assertSame('2026-11-02T09:02:00.000000Z', $future['recorded_at']);

        $digest = app(SourceDigest::class)->of(self::assertionOf(self::fields('rec-0')), app(SourceDigest::class)->signingKeyId());

        self::assertSame($digest, $first['source_digest']);
        self::assertTrue(app(RecordSigner::class)->verifies($first));
        self::assertTrue(app(RecordSigner::class)->verifies($future));

        $this->sealAt('2026-11-02 10:00:00.000000');
        $this->sealAll();

        $members = $this->membersOf((string) $this->seals()[0]['id']);

        self::assertContains($first['id'], $members);
        self::assertContains($future['id'], $members);
    }

    /**
     * The batch records its importer, source, file digest, counts and times,
     * and ends `complete`.
     *
     * @return void
     */
    public function testTheBatchRecordsImporterSourceDigestCountsAndTimes(): void
    {
        $path   = $this->file([self::line('rec-1'), self::line('rec-2'), self::line('rec-2')]);
        $result = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE, 'eu-west-2'), self::authority());
        $batch  = $this->batch((string) $result->batchId);

        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame([self::SOURCE, 'eu-west-2', 'audit-log-import/v1', 'App\Models\User', '7', 'case.review', 'app:ticket-123', hash_file('sha256', $path)], [
            $batch['source_id'], $batch['source_region'], $batch['input_format'], $batch['importer_type'],
            $batch['importer_id'], $batch['reason'], $batch['external_reference'], $batch['file_sha256'],
        ]);
        self::assertSame('complete', $batch['status']);
        self::assertSame([3, 2, 1, 0, 0], array_map(intval(...), [$batch['lines_read'], $batch['imported'], $batch['duplicates'], $batch['conflicts'], $batch['rejected']]));
        self::assertNull($batch['conflict_ids']);
        self::assertNull($batch['hold_id']);
        self::assertSame(self::NOW, self::time($batch['started_at']));
        self::assertSame(self::NOW, self::time($batch['finished_at']));
        self::assertSame([3, 2, 1, 0, 0], [$result->linesRead, $result->imported, $result->duplicates, $result->conflicts, $result->rejected]);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
    }

    /**
     * The batch is never externally verified.
     *
     * @return void
     */
    public function testTheBatchIsNotExternallyVerified(): void
    {
        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());

        self::assertFalse((bool) $this->batch((string) $result->batchId)['externally_verified']);
        $payload = $this->journalRows()[0]['payload'] ?? '{}';

        self::assertIsString($payload);

        $decoded = json_decode($payload, true);

        self::assertIsArray($decoded);
        self::assertFalse($decoded['externally_verified'] ?? true);
    }

    /**
     * Importing the same file twice stores each record once.
     *
     * @return void
     */
    public function testARepeatedImportStoresOnce(): void
    {
        $path   = $this->file([self::line('rec-1'), self::line('rec-2')]);
        $first  = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());
        $second = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

        self::assertSame([2, 0], [$first->imported, $first->duplicates]);
        self::assertSame([0, 2, 0], [$second->imported, $second->duplicates, $second->conflicts]);
        self::assertSame(ImportStatus::COMPLETE, $second->status);
        self::assertSame(2, $this->rowsIn(EntrySettings::table()));
    }

    /**
     * A conflicting line marks the batch `partial` and lists its record id.
     *
     * @return void
     */
    public function testAConflictingImportIsReportedAndThePartialBatchListsIt(): void
    {
        $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());

        $path   = $this->file([self::line('rec-1', ['outcome' => 'denied']), self::line('rec-2')]);
        $result = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());
        $batch  = $this->batch((string) $result->batchId);

        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertSame([1, 0, 1], [$result->imported, $result->duplicates, $result->conflicts]);
        self::assertSame(['rec-1'], $result->conflictIds);
        self::assertSame('partial', $batch['status']);
        self::assertSame('["rec-1"]', $batch['conflict_ids']);
    }

    /**
     * A rejected line makes the batch `partial`, counted under its reason.
     *
     * @return void
     */
    public function testARejectedLineMakesTheBatchPartial(): void
    {
        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1'), 'not json']), self::SOURCE), self::authority());

        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertSame(['malformed_json' => 1], $result->rejections);
        self::assertSame('1', (string) $this->batch((string) $result->batchId)['rejected']);
    }

    /**
     * Imported rows are never dispatched or delivered.
     *
     * @return void
     */
    public function testImportedRowsAreNotDispatchedOrDelivered(): void
    {
        Event::fake([AuditRecorded::class]);

        $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1'), self::line('rec-2')]), self::SOURCE), self::authority());

        Event::assertNotDispatched(AuditRecorded::class);

        self::assertSame(2, $this->rowsIn(EntrySettings::table()));
        self::assertSame(0, DB::connection(DeliveryTables::outboxConnection())->table(DeliveryTables::outboxTable())->count());
        self::assertSame(0, $this->rowsIn(DeliveryTables::deliveriesTable()));
    }

    /**
     * The start and its hold commit before the first entry, and the hold keeps
     * exactly the batch.
     *
     * @return void
     */
    public function testTheHoldIsPlacedBeforeTheFirstEntry(): void
    {
        $order = [];

        DB::listen(static function (QueryExecuted $query) use (&$order): void {
            $sql = strtolower($query->sql);

            foreach (['journal' => LifecycleTables::journalTable(), 'holds' => LifecycleTables::holdsTable(), 'entries' => EntrySettings::table()] as $label => $table) {
                if (!str_starts_with($sql, 'insert') || preg_match('/\b' . $table . '\b/', $sql) !== 1) {
                    continue;
                }

                $order[] = $label;
            }
        });

        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true, basis: HoldBasis::LEGAL_CLAIM);

        self::assertSame(['journal', 'journal', 'holds', 'entries', 'journal'], $order);
        self::assertNotNull($result->hold);
        self::assertSame($result->hold->id, $result->holdId);
        self::assertSame(HoldBasis::LEGAL_CLAIM, $result->hold->basis);
        self::assertSame(HoldScope::all()->importBatch((string) $result->batchId)->toArray(), $result->hold->scope->toArray());
        self::assertSame($result->hold->id, $this->batch((string) $result->batchId)['hold_id']);
        self::assertSame([$result->hold->id], DB::connection(StorageConnection::forMaintenance())->table(LifecycleTables::holdsTable())->pluck('hold_id')->all());
    }

    /**
     * A failure after the hold's row rolls back the start and fails the batch.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStartAndTheHoldCommitTogether(): void
    {
        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with(strtolower($query->sql), 'insert') && str_contains($query->sql, LifecycleTables::holdsTable())) {
                throw new \RuntimeException('The hold\'s projection row could not be written.');
            }
        });

        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true);
            self::fail('Expected the start to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The hold\'s projection row could not be written.', $exception->getMessage());
        }

        $batches = $this->allBatches();

        self::assertCount(1, $batches);
        self::assertSame('failed', $batches[0]['status']);
        self::assertSame([], $this->journalRows());
        self::assertSame(0, $this->rowsIn(LifecycleTables::holdsTable()));
        self::assertSame(0, $this->rowsIn(EntrySettings::table()));
    }

    /**
     * A broken journal refuses the start and the batch is `failed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJournalFailureAtStartFailsTheBatchAndWritesNoEntry(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'edited']);

        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());
            self::fail('Expected a broken journal to refuse the import.');
        } catch (JournalBrokenException) {
            // The start was refused
        }

        self::assertSame('failed', $this->allBatches()[0]['status'] ?? null);
        self::assertCount(1, $this->journalRows());
        self::assertSame(0, $this->rowsIn(EntrySettings::table()));
    }

    /**
     * A failure after the start fails the batch, journals its finish and leaves
     * the hold.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnFailureTheHoldStays(): void
    {
        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with(strtolower($query->sql), 'insert') && str_contains($query->sql, EntrySettings::table())) {
                throw new \RuntimeException('The entries could not be written.');
            }
        });

        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true);
            self::fail('Expected the import to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The entries could not be written.', $exception->getMessage());
        }

        $batch = $this->allBatches()[0];

        self::assertSame('failed', $batch['status']);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::HOLD, JournalKind::IMPORT_FINISHED], $this->journalKinds());
        self::assertSame('failed', json_decode((string) $this->journalRows()[2]['payload'], true)['status'] ?? null);
        self::assertSame([$batch['hold_id']], array_map(static fn (Hold $hold): string => $hold->id, $this->replayed()->holds()));
        self::assertSame(1, $this->rowsIn(LifecycleTables::holdsTable()));
    }

    /**
     * A file that changed between its two reads fails the batch.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFileChangedDuringTheImportFailsTheBatch(): void
    {
        $path = $this->file([self::line('rec-1')]);

        try {
            $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), started: static function () use ($path): void {
                file_put_contents($path, self::line('rec-2') . "\n");
            });
            self::fail('Expected the changed file to fail the batch.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The import file changed while it was read (`source_changed`), so the batch failed.', $exception->getMessage());
        }

        self::assertSame('failed', $this->allBatches()[0]['status']);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $this->journalKinds());
    }

    /**
     * The started closure is told once the start commits, before any entry is
     * written.
     *
     * @return void
     */
    public function testTheStartedClosureIsToldOfTheStart(): void
    {
        $told = [];

        $tell = function (ImportResult $started) use (&$told): void {
            $told[] = [$started->status, $started->batchId, $started->holdId, $this->rowsIn(EntrySettings::table()), count($this->journalRows())];
        };

        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true, started: $tell);

        self::assertSame([[ImportStatus::RUNNING, $result->batchId, $result->holdId, 0, 2]], $told);
    }

    /**
     * An import whose source is this installation is refused before its file is
     * read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItRefusesItsOwnSource(): void
    {
        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::OWN), self::authority());
            self::fail('Expected the own source to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An import\'s source is never this installation\'s own `source.id`; its own records come back through `audit-log:replay`.', $exception->getMessage());
        }

        self::assertSame(0, $this->rowsIn(LifecycleTables::importBatchesTable()));
    }

    /**
     * An import inside a host transaction on the storage connection is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItRefusesInsideAHostTransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());
            self::fail('Expected the import to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('An import runs outside any transaction on the storage and the maintenance connections, and refuses to run inside one.', $exception->getMessage());
        } finally {
            $connection->rollBack();
        }

        self::assertSame(0, $this->rowsIn(LifecycleTables::importBatchesTable()));
    }

    /**
     * A malformed import setting refuses the import before anything is read.
     *
     * @return void
     */
    public function testAMalformedSettingRefusesTheImport(): void
    {
        app(ConfigRepository::class)->set('audit-log.import.chunk', 50);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.import.chunk` must be an integer from 100 to 5000.');

        $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());
    }

    /**
     * Another installation's export imports under its upstream identities,
     * without envelopes or metadata.
     *
     * @return void
     */
    public function testAnotherInstallationsExportImports(): void
    {
        $exported = [
            ...array_fill_keys(array_keys(RowCodec::COLUMNS), null),
            'id'                => '01a196fb-1600-7328-bff7-a78c4cedcf62',
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'finance',
            'outcome'           => 'success',
            'origin'            => 'http',
            'provenance'        => 'captured',
            'source_id'         => 'app-us-1',
            'properties'        => ['amount' => '1200.00', '_audit' => ['omitted' => ['iban']], 'iban' => ['v' => 1, 'k' => 'x', 'c' => 'y']],
            'occurred_at'       => '2026-11-01T12:00:00.000001Z',
            'recorded_at'       => '2026-11-01T12:00:00.000001Z',
            'integrity_version' => 1,
            'key_id'            => 'd03d4735ce37bd961',
            'hmac'              => str_repeat('c', 64),
        ];

        $upstream = [...$exported, 'id' => '01a196fb-1600-7328-bff7-a78c4cedcf63', 'provenance' => 'imported', 'source_id' => 'crm-eu', 'source_record_id' => 'rec-9'];
        $upstream = [...$upstream, 'properties' => null];
        $path     = $this->file([CanonicalEncoder::encode($exported), CanonicalEncoder::encode($upstream)]);
        $result   = $this->importer()->import(ImportSource::fromExport($path, 'app-us-1'), self::authority());
        $rows     = $this->rows();

        self::assertSame([2, 2], [$result->imported, $result->dropped]);
        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame(['app-us-1', '01a196fb-1600-7328-bff7-a78c4cedcf62'], [$rows[0]['source_id'], $rows[0]['source_record_id']]);
        self::assertSame(['crm-eu', 'rec-9'], [$rows[1]['source_id'], $rows[1]['source_record_id']]);
        self::assertSame(['amount' => '1200.00'], (array) $rows[0]['properties']);
        self::assertNotSame($exported['id'], $rows[0]['id']);
        self::assertSame('audit-log-export/v1', $this->batch((string) $result->batchId)['input_format']);
    }

    /**
     * Importing a line again after its row was pruned creates a new row.
     *
     * @return void
     */
    public function testAReimportAfterAPruneCreatesNewRows(): void
    {
        $path = $this->file([self::line('rec-1')]);

        $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

        $first = $this->rows()[0]['id'];

        DB::connection(StorageConnection::forMaintenance())->table(EntrySettings::table())->delete();

        $again = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

        self::assertSame([1, 0], [$again->imported, $again->duplicates]);
        self::assertNotSame($first, $this->rows()[0]['id']);
    }

    /**
     * Lines already past their retention on arrival are counted.
     *
     * @return void
     */
    public function testThePastRetentionCountIsReported(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', ['finance' => 7]);

        $path    = $this->file([self::line('rec-1'), self::line('rec-2', ['occurred_at' => '2026-11-01T09:00:00.000000Z'])]);
        $planned = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), dryRun: true);
        $result  = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

        self::assertSame(1, $planned->pastRetention);
        self::assertSame(1, $result->pastRetention);
    }

    /**
     * Rows of `[how the retention policy fails to answer]`.
     *
     * @return iterable<string, array{0: \Closure(): void}>
     */
    public static function provideFailingRetention(): iterable
    {
        yield from [
            'a malformed schedule' => [static function (): void {
                app(ConfigRepository::class)->set('audit-log.retention.schedule', 'every night');
            }],
            'a throwing policy' => [static function (): void {
                app()->instance(RetentionPolicy::class, new class implements RetentionPolicy {
                    /**
                     * The policy's version.
                     *
                     * @return string
                     */
                    #[\Override]
                    public function version(): string
                    {
                        return 'custom:1';
                    }

                    /**
                     * Throw, naming a tenant a report must never show.
                     *
                     * @param  string  $category
                     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
                     * @return ?int
                     *
                     * @throws \RuntimeException
                     */
                    #[\Override]
                    public function retainFor(string $category, ?Reference $tenant): ?int
                    {
                        throw new \RuntimeException('org_01 is under review');
                    }

                    /**
                     * Nothing obliges the package to keep anything.
                     *
                     * @param  string  $category
                     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
                     * @return ?int
                     */
                    #[\Override]
                    public function preserveFor(string $category, ?Reference $tenant): ?int
                    {
                        return null;
                    }
                });
            }],
        ];
    }

    /**
     * A failing retention policy leaves the past-retention count `null` and is
     * reported once by class.
     *
     * @param  \Closure(): void  $fail
     * @return void
     */
    #[DataProvider('provideFailingRetention')]
    public function testAFailingRetentionPolicyNeverFailsTheImport(\Closure $fail): void
    {
        $fail();

        $reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $reporter);

        $path    = $this->file([self::line('rec-1'), self::line('rec-2'), self::line('rec-3')]);
        $planned = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), dryRun: true);
        $result  = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

        self::assertSame([3, null], [$planned->imported, $planned->pastRetention]);
        self::assertSame([ImportStatus::COMPLETE, 3, null], [$result->status, $result->imported, $result->pastRetention]);
        self::assertSame('complete', $this->batch((string) $result->batchId)['status']);
        self::assertCount(2, $reporter->reports());

        foreach ($reporter->reports() as $report) {
            self::assertStringStartsWith('Counting an import\'s lines past retention did not complete: ', $report->getMessage());
            self::assertStringNotContainsString('org_01', $report->getMessage());
        }
    }

    /**
     * The journal opens the batch with `import_started` and closes it with
     * `import_finished`.
     *
     * @return void
     */
    public function testTheJournalRowsOpenAndCloseTheBatch(): void
    {
        $path   = $this->file([self::line('rec-1'), self::line('rec-1'), 'x']);
        $result = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE, 'eu-west-2'), self::authority(), hold: true);
        $rows   = array_map(static fn (array $row): JournalRow => JournalRow::fromRow($row, true), $this->journalRows());

        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::HOLD, JournalKind::IMPORT_FINISHED], array_map(static fn (JournalRow $row): JournalKind => $row->kind, $rows));
        self::assertSame(CanonicalEncoder::encode([
            'batch_id'            => $result->batchId,
            'source_id'           => self::SOURCE,
            'source_region'       => 'eu-west-2',
            'format'              => 'audit-log-import/v1',
            'file_sha256'         => hash_file('sha256', $path),
            'externally_verified' => false,
            'hold_id'             => $result->holdId,
        ]), $rows[0]->payload);
        self::assertSame($result->holdId, $rows[0]->holdId);
        self::assertSame(CanonicalEncoder::encode([
            'batch_id'    => $result->batchId,
            'status'      => 'partial',
            'lines_read'  => 3,
            'imported'    => 1,
            'duplicates'  => 1,
            'conflicts'   => 0,
            'rejected'    => 1,
            'file_sha256' => hash_file('sha256', $path),
        ]), $rows[2]->payload);

        foreach ($rows as $row) {
            self::assertSame($result->operationId, $row->operationId);
            self::assertSame('case.review', $row->reason);
        }

        self::assertSame([$result->holdId], array_map(static fn (Hold $hold): string => $hold->id, $this->replayed()->holds()));
    }

    /**
     * Close marks a running batch `interrupted` and journals its finish.
     *
     * @return void
     */
    public function testCloseMarksARunningBatchInterruptedAndJournalsIt(): void
    {
        $batchId = $this->runningBatch();
        $result  = $this->importer()->close($batchId, new Authority(Reference::of('App\Models\User', '9'), 'stale.import'));

        self::assertSame(ImportStatus::INTERRUPTED, $result->status);
        self::assertTrue($result->committed);
        self::assertSame($batchId, $result->batchId);
        self::assertSame('interrupted', $this->batch($batchId)['status']);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $this->journalKinds());

        $finish = JournalRow::fromRow($this->journalRows()[1], true);

        self::assertSame('stale.import', $finish->reason);
        self::assertSame($result->operationId, $finish->operationId);
        self::assertSame('interrupted', json_decode($finish->payload ?? '{}', true)['status'] ?? null);
    }

    /**
     * Close refuses a finished, closed, missing or malformed batch and journals
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCloseRefusesAFinishedBatch(): void
    {
        $finished = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());
        $running  = $this->runningBatch();

        $this->importer()->close($running, self::authority());

        $journalled = count($this->journalRows());

        foreach ([(string) $finished->batchId, $running, '01932b4e-a000-7000-8000-00000000ffff', 'not-a-batch'] as $batchId) {
            try {
                $this->importer()->close($batchId, self::authority());
                self::fail('Expected the close to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::NOT_CLOSABLE, $exception->getMessage());
            }
        }

        self::assertCount($journalled, $this->journalRows());
    }

    /**
     * A chunk's data failure is rethrown masked, keeping its class and
     * SQLSTATE.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChunksDataFailureIsRethrownMasked(): void
    {
        $reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $reporter);

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $sql, array $bindings, Connection $connection): void {
            if (str_starts_with(strtolower($sql), 'insert') && str_contains($sql, EntrySettings::table())) {
                $driver            = new \PDOException('SQLSTATE[22001]: String data, right truncated: 1406 Data too long, value \'secret-amount-4711\'');
                $driver->errorInfo = ['22001', 1406, 'Data too long'];
                $name              = $connection->getName();

                self::assertNotNull($name);

                throw new QueryException($name, $sql, $bindings, $driver);
            }
        });

        try {
            $path = $this->file([self::line('rec-secret-1', ['properties' => ['amount' => 'secret-amount-4711']])]);

            $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());
            self::fail('Expected the chunk to fail.');
        } catch (QueryException $exception) {
            self::assertSame('22001', $exception->errorInfo[0] ?? null);
            self::assertStringNotContainsString('rec-secret-1', $exception->getMessage());
            self::assertStringNotContainsString('secret-amount-4711', $exception->getMessage());
            self::assertStringNotContainsString('secret-amount-4711', (string) $exception->getPrevious()?->getMessage());
            self::assertSame([], $exception->getBindings());
        }

        foreach ($reporter->reports() as $report) {
            self::assertStringNotContainsString('secret-amount-4711', $report->getMessage());
            self::assertStringNotContainsString('rec-secret-1', $report->getMessage());
        }

        self::assertSame('failed', $this->allBatches()[0]['status'] ?? null);
    }

    /**
     * A malformed batch id is refused before any statement runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedBatchIdIsRefusedBeforeAnyQuery(): void
    {
        $statements = 0;

        DB::listen(static function () use (&$statements): void {
            $statements++;
        });

        try {
            $this->importer()->close('abc', self::authority());
            self::fail('Expected the malformed id to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::NOT_CLOSABLE, $exception->getMessage());
        }

        self::assertSame(0, $statements);
    }

    /**
     * Closing a batch whose start never committed journals nothing.
     *
     * @return void
     */
    public function testCloseOfABatchNeverStartedJournalsNothing(): void
    {
        $batchId = $this->runningBatch(false);
        $result  = $this->importer()->close($batchId, self::authority());

        self::assertSame([ImportStatus::INTERRUPTED, true], [$result->status, $result->committed]);
        self::assertSame('interrupted', $this->batch($batchId)['status']);
        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->journalFindings());
    }

    /**
     * A close whose journal fails leaves the batch running for a retry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACloseWhoseJournalFailsCanBeRetried(): void
    {
        $batchId = $this->runningBatch();
        $fail    = true;

        DB::listen(static function (QueryExecuted $query) use (&$fail): void {
            if ($fail && str_starts_with(strtolower($query->sql), 'insert') && in_array(JournalKind::IMPORT_FINISHED->value, $query->bindings, true)) {
                $fail = false;

                throw new \RuntimeException('The journal could not be written.');
            }
        });

        try {
            $this->importer()->close($batchId, self::authority());
            self::fail('Expected the close to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The journal could not be written.', $exception->getMessage());
        }

        self::assertSame('running', $this->batch($batchId)['status']);

        $result = $this->importer()->close($batchId, self::authority());

        self::assertSame([ImportStatus::INTERRUPTED, true], [$result->status, $result->committed]);
        self::assertSame('interrupted', $this->batch($batchId)['status']);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $this->journalKinds());
        self::assertSame([], $this->journalFindings());
    }

    /**
     * A finish journalled before its batch was made final is completed by
     * close.
     *
     * @return void
     */
    public function testAFinishJournalledBeforeItsBatchIsRecoveredByClose(): void
    {
        $fail = true;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $sql) use (&$fail): void {
            if ($fail && str_starts_with(strtolower($sql), 'update') && str_contains($sql, LifecycleTables::importBatchesTable()) && str_contains($sql, 'finished_at')) {
                $fail = false;

                throw new \RuntimeException('The batch could not be written.');
            }
        });

        $result = $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());

        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame('running', $this->batch((string) $result->batchId)['status']);

        $closed = $this->importer()->close((string) $result->batchId, self::authority());

        self::assertSame([ImportStatus::COMPLETE, false, $result->operationId], [$closed->status, $closed->committed, $closed->operationId]);
        self::assertSame('complete', $this->batch((string) $result->batchId)['status']);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $this->journalKinds());
        self::assertSame([], $this->journalFindings());
    }

    /**
     * A finish that cannot be journalled leaves the batch running for close.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFinishThatCannotBeJournalledLeavesTheBatchForClose(): void
    {
        DB::listen(static function (QueryExecuted $query): void {
            $finish = in_array(JournalKind::IMPORT_FINISHED->value, $query->bindings, true) && in_array('case.review', $query->bindings, true);

            if ($finish && str_starts_with(strtolower($query->sql), 'insert')) {
                throw new \RuntimeException('The journal could not be written.');
            }
        });

        try {
            $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority());
            self::fail('Expected the import to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The journal could not be written.', $exception->getMessage());
        }

        $batchId = (string) ($this->allBatches()[0]['id'] ?? '');

        self::assertSame('running', $this->batch($batchId)['status']);
        self::assertSame([JournalKind::IMPORT_STARTED], $this->journalKinds());

        $closed = $this->importer()->close($batchId, new Authority(Reference::of('App\Models\User', '9'), 'stale.import'));

        self::assertSame([ImportStatus::INTERRUPTED, true], [$closed->status, $closed->committed]);
        self::assertSame([JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $this->journalKinds());
        self::assertSame([], $this->journalFindings());
    }

    /**
     * A final batch whose start has no finish has that finish journalled with
     * its status kept.
     *
     * @return void
     */
    public function testAFinalBatchWithAnOpenStartHasItsFinishJournalled(): void
    {
        $batchId = $this->runningBatch();

        app(ImportBatches::class)->settles($batchId, ImportStatus::FAILED);

        $result = $this->importer()->close($batchId, self::authority());

        self::assertSame([ImportStatus::FAILED, true], [$result->status, $result->committed]);
        self::assertSame('failed', $this->batch($batchId)['status']);
        self::assertSame('failed', json_decode((string) $this->journalRows()[1]['payload'], true)['status'] ?? null);
        self::assertSame([], $this->journalFindings());
    }

    /**
     * Entries and the batch go through the storage connection; the journal and
     * hold through maintenance.
     *
     * @return void
     */
    public function testEntriesAndTheBatchAreOnTheStorageWriterAndTheJournalOnTheMaintenanceConnection(): void
    {
        $this->sameDatabase();

        $writes = [];

        $tables = [
            'entries' => EntrySettings::table(),
            'batches' => LifecycleTables::importBatchesTable(),
            'journal' => LifecycleTables::journalTable(),
            'holds'   => LifecycleTables::holdsTable(),
        ];

        DB::listen(static function (QueryExecuted $query) use (&$writes, $tables): void {
            $verb = strtolower((string) strtok($query->sql, ' '));

            foreach ($tables as $label => $table) {
                if (!in_array($verb, ['insert', 'update'], true) || preg_match('/\b' . $table . '\b/', $query->sql) !== 1) {
                    continue;
                }

                $writes[$label][$query->connectionName] = true;
            }
        });

        $this->importer()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true);

        $storage = StorageConnection::resolvedName();

        self::assertSame([$storage], array_keys($writes['entries'] ?? []));
        self::assertSame([$storage], array_keys($writes['batches'] ?? []));
        self::assertSame([self::MAINTENANCE], array_keys($writes['journal'] ?? []));
        self::assertSame([self::MAINTENANCE], array_keys($writes['holds'] ?? []));
    }

    /**
     * Leave a batch as a killed import does: `running`, with its start
     * journalled unless killed before.
     *
     * @param  bool  $started
     * @return string
     */
    private function runningBatch(bool $started = true): string
    {
        $batchId = '01932b4e-a000-7000-8000-0000000000e1';

        app(ImportBatches::class)->start([
            'id'                  => $batchId,
            'source_id'           => 'crm-killed',
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);

        if (!$started) {
            return $batchId;
        }

        $this->journalRow(JournalKind::IMPORT_STARTED, [
            'batch_id'            => $batchId,
            'source_id'           => 'crm-killed',
            'source_region'       => null,
            'format'              => 'audit-log-import/v1',
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);

        return $batchId;
    }

    /**
     * The journal findings `audit-log:verify` gives.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding>
     */
    private function journalFindings(): array
    {
        $tally = new VerificationTally;

        app(JournalVerifier::class)->verify($tally);

        return $tally->findings();
    }

    /**
     * A replay of the whole journal, verified.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function replayed(): JournalReplay
    {
        return JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId())->verify(DB::connection(StorageConnection::forMaintenance()));
    }

    /**
     * The kinds of the stored journal rows, in sequence.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind>
     */
    private function journalKinds(): array
    {
        return array_map(static fn (array $row): JournalKind => JournalKind::from((string) $row['kind']), $this->journalRows());
    }

    /**
     * Every stored entry decoded, by its source record id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return list<array<string, mixed>>
     */
    private function rows(): array
    {
        $rows = DB::connection(StorageConnection::name())->table(EntrySettings::table())->orderBy('source_record_id')->get()->all();

        return array_values(array_map(static fn (object $row): array => app(RowCodec::class)->decode((array) $row), $rows));
    }

    /**
     * The batch's row.
     *
     * @param  string  $batchId
     * @return array<string, scalar|null>
     */
    private function batch(string $batchId): array
    {
        $row = DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->where('id', $batchId)->first();

        self::assertNotNull($row);

        /** @var array<string, scalar|null> */
        return (array) $row;
    }

    /**
     * Every batch's row, by when each started.
     *
     * @return list<array<string, scalar|null>>
     */
    private function allBatches(): array
    {
        $rows = DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->orderBy('started_at')->get()->all();

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (object $row): array => (array) $row, $rows));
    }

    /**
     * The count of the table's rows on the storage connection.
     *
     * @param  string  $table
     * @return int
     */
    private function rowsIn(string $table): int
    {
        return DB::connection(StorageConnection::name())->table($table)->count();
    }

    /**
     * A line of the import format, with the fields given over its own.
     *
     * @param  string  $recordId
     * @param  array<string, array<string, string>|string|null>  $fields
     * @return string
     */
    private static function line(string $recordId, array $fields = []): string
    {
        return (string) json_encode([...self::fields($recordId), ...$fields]);
    }

    /**
     * The fields of a line of the import format, of the record id given.
     *
     * @param  string  $recordId
     * @return array<string, array<string, string>|string>
     */
    private static function fields(string $recordId): array
    {
        return [
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-10-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
            'properties'       => ['amount' => '1200.00'],
            'origin'           => 'http',
        ];
    }

    /**
     * The source assertion an import line gives for the fields of a line.
     *
     * @param  array<string, array<string, string>|string>  $line
     * @return array<string, array<int|string, string>|int|string|null>
     */
    private static function assertionOf(array $line): array
    {
        $pair = static fn (array|string|null $reference): ?array => is_array($reference) ? [$reference['type'], $reference['id']] : null;

        return [
            'v'              => 1,
            'event'          => $line['event'],
            'occurred_at'    => $line['occurred_at'],
            'outcome'        => $line['outcome'],
            'actor'          => $pair($line['actor'] ?? null),
            'subject'        => null,
            'principal'      => null,
            'tenant'         => $pair($line['tenant'] ?? null),
            'reason'         => null,
            'correlation_id' => null,
            'properties'     => $line['properties'],
            'context'        => null,
            'origin'         => $line['origin'],
            'ip'             => null,
        ];
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'import-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * A stored time as `Y-m-d H:i:s.u`, whatever fractional digits the engine
     * returns.
     *
     * @param  bool|float|int|string|null  $stored
     * @return ?string
     */
    private static function time(bool|float|int|string|null $stored): ?string
    {
        return is_string($stored) ? (new CarbonImmutable($stored, 'UTC'))->format('Y-m-d H:i:s.u') : null;
    }

    /**
     * The authority every import is made on, unless a test gives another.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * The importer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter
     */
    private function importer(): AuditImporter
    {
        return app(AuditImporter::class);
    }
}
