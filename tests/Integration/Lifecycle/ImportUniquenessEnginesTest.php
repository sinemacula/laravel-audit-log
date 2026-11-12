<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for import uniqueness on every engine, SQLite on a WAL
 * file, where two imports take turns rather than meet the unique index.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditImporter::class)]
#[CoversClass(ImportWriter::class)]
#[CoversClass(ImportClassifier::class)]
#[CoversClass(ImportBatches::class)]
final class ImportUniquenessEnginesTest extends TestCase
{
    use RunsKilledChildren;

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string A second connection to the test's database, a writer whose rows commit on their own. */
    private const string COMPETING_WRITER = 'competing_writer';

    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var int The lines of the file the racing imports share: three chunks. */
    private const int LINES = 300;

    /** @var string The gate that releases the racing children together. */
    private const string START = 'start';

    /** @var string The file each racing child writes its result to. */
    private const string RESULTS = 'results';

    /**
     * Freeze the clock, name the installation, bind retention, chunk by 100.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        $config = app(ConfigRepository::class);

        $config->set('audit-log.source.id', self::OWN);
        $config->set('audit-log.import.chunk', 100);

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * Put the clock back and remove the children's files after the rollback.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Two concurrent imports store each record once; whether they overlap is
     * timing, so this is a smoke test.
     *
     * @return void
     */
    public function testTwoConcurrentImportsStoreEachRecordOnce(): void
    {
        $path = $this->importFile(self::LINES);

        app(MaintenanceTransaction::class)->confirm();

        $children = [];

        for ($child = 0; $child < 2; $child++) {
            $children[] = $this->startChild(function () use ($path, $child): void {
                // Each fork needs its own clock, or both draw the same ids
                CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:0' . ($child + 1), 'UTC'));

                $this->awaitGate(self::START);

                $result = $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());

                $this->appendToChildFile(self::RESULTS, (string) json_encode([$result->status?->value, $result->imported, $result->duplicates, $result->conflicts]));
            });
        }

        $this->openGate(self::START);

        foreach ($children as $child) {
            $this->assertKilled($this->waitForChild($child));
        }

        /** @var list<array{0: ?string, 1: int, 2: int, 3: int}> $results */
        $results = array_map(static fn (string $line): mixed => json_decode($line, true), $this->childFileLines(self::RESULTS));

        self::assertCount(2, $results);
        self::assertSame(self::LINES, array_sum(array_column($results, 1)));

        foreach ($results as [$status, $imported, $duplicates, $conflicts]) {
            self::assertSame('complete', $status);
            self::assertSame(self::LINES, $imported + $duplicates);
            self::assertSame(0, $conflicts);
        }

        self::assertSame(self::LINES, $this->entries());
        self::assertSame(self::LINES, DB::connection(StorageConnection::name())->table(EntrySettings::table())->distinct()->count('source_record_id'));
    }

    /**
     * A unique violation rolls the chunk back, and the chunk is classified
     * again.
     *
     * @return void
     */
    public function testAUniqueViolationRollsTheChunkBackAndReclassifies(): void
    {
        $classified = $this->interfere(1);
        $result     = $this->importer()->import(ImportSource::fromFile($this->importFile(3), self::SOURCE), self::authority());

        self::assertCount(2, $classified);
        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame([3, 0, 0], [$result->imported, $result->duplicates, $result->conflicts]);
        self::assertSame(3, $this->entries());
    }

    /**
     * On MySQL and PostgreSQL a row committed between classify and insert
     * becomes a conflict; SQLite locks before it classifies.
     *
     * @return void
     */
    public function testARowCommittedBetweenClassifyAndInsertIsReclassifiedAConflict(): void
    {
        $storage = StorageConnection::resolvedName();

        if (DB::connection($storage)->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite takes its write lock before a chunk classifies, so no other writer commits between the two.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::COMPETING_WRITER, $config->get('database.connections.' . $storage));

        /** @var \ArrayObject<int, string> $classified */
        $classified = new \ArrayObject;

        DB::listen(function (QueryExecuted $query) use ($classified): void {
            $classifies = str_starts_with(strtolower($query->sql), 'select') && str_contains($query->sql, EntrySettings::table()) && str_contains($query->sql, 'source_record_id');

            if ($query->connectionName === self::COMPETING_WRITER || !$classifies) {
                return;
            }

            $classified->append($query->sql);

            if ($classified->count() > 1) {
                return;
            }

            DB::connection(self::COMPETING_WRITER)->table(EntrySettings::table())->insert($this->interferingRow());
        });

        try {
            $result = $this->importer()->import(ImportSource::fromFile($this->importFile(3), self::SOURCE), self::authority());
        } finally {
            DB::purge(self::COMPETING_WRITER);
        }

        self::assertCount(2, $classified);
        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertSame([2, 0, 1], [$result->imported, $result->duplicates, $result->conflicts]);
        self::assertSame(['rec-1'], $result->conflictIds);
        self::assertSame(3, $this->entries());
        self::assertSame(3, DB::connection($storage)->table(EntrySettings::table())->distinct()->count('source_record_id'));
        self::assertSame('01932b4e-ffff-7000-8000-000000000001', DB::connection($storage)->table(EntrySettings::table())->where('source_record_id', 'rec-1')->value('id'));
    }

    /**
     * A second violation makes the chunk's lines conflicts, the batch partial.
     *
     * @return void
     */
    public function testASecondViolationMakesTheBatchPartial(): void
    {
        $classified = $this->interfere(2);
        $result     = $this->importer()->import(ImportSource::fromFile($this->importFile(3), self::SOURCE), self::authority());
        $batch      = app(ImportBatches::class)->find((string) $result->batchId);

        self::assertCount(2, $classified);
        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertSame([0, 3], [$result->imported, $result->conflicts]);
        self::assertSame(['rec-1', 'rec-2', 'rec-3'], $result->conflictIds);
        self::assertSame('partial', $batch['status'] ?? null);
        self::assertSame('["rec-1","rec-2","rec-3"]', $batch['conflict_ids'] ?? null);
        self::assertSame(0, $this->entries());
    }

    /**
     * A killed import's batch stays running, then closes `interrupted`.
     *
     * @return void
     */
    public function testAnInterruptedImportIsReportedAndClosed(): void
    {
        $path = $this->importFile(self::LINES);

        $this->assertKilled($this->runChild(function () use ($path): void {
            $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority());
        }, killAfter: '/insert into [`"]?' . EntrySettings::table() . '/i'));

        $batches = DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->get()->all();

        self::assertCount(1, $batches);

        $batchId = (string) $batches[0]->id;

        self::assertSame('running', $batches[0]->status);
        self::assertSame(0, $this->entries());
        self::assertSame([], $this->staleIds());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 10:00:01', 'UTC'));

        self::assertSame([$batchId], $this->staleIds());

        $result = $this->importer()->close($batchId, self::authority());

        self::assertSame(ImportStatus::INTERRUPTED, $result->status);
        self::assertSame('interrupted', app(ImportBatches::class)->find($batchId)['status'] ?? null);

        $kinds = DB::connection(StorageConnection::forMaintenance())->table(LifecycleTables::journalTable())->orderBy('sequence')->pluck('kind')->all();

        self::assertSame([JournalKind::IMPORT_STARTED->value, JournalKind::IMPORT_FINISHED->value], $kinds);
        self::assertSame([], $this->staleIds());
    }

    /**
     * Every imported column reads back as written, and the row verifies.
     *
     * @return void
     */
    public function testEveryImportedColumnRoundTripsOnEachEngine(): void
    {
        $line = [
            'format'           => 'audit-log-import/v1',
            'source_record_id' => 'rec-é-1',
            'occurred_at'      => '2026-10-01T09:00:00.123456Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'denied',
            'reason'           => 'over_limit',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'subject'          => ['type' => 'invoice', 'id' => 'inv_0042'],
            'principal'        => ['type' => 'user', 'id' => '7'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
            'correlation_id'   => 'app:ticket-123',
            'properties'       => ['zeta' => 'last', 'amount' => '1200.00', 'nested' => ['b' => 2, 'a' => [1, 2]], 'empty' => []],
            'context'          => ['route' => 'invoices.approve'],
            'origin'           => 'queue',
            'ip'               => '203.0.113.7',
        ];

        $result = $this->importer()->import(ImportSource::fromFile($this->file([(string) json_encode($line)]), self::SOURCE, 'eu-west-2'), self::authority());
        $stored = DB::connection(StorageConnection::name())->table(EntrySettings::table())->first();

        self::assertNotNull($stored);

        $row = app(RowCodec::class)->decode((array) $stored);

        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame([
            'event'            => 'invoice.approved',
            'outcome'          => 'denied',
            'reason'           => 'over_limit',
            'actor'            => ['user', '42'],
            'subject'          => ['invoice', 'inv_0042'],
            'principal'        => ['user', '7'],
            'tenant'           => ['organisation', 'org_01'],
            'category'         => 'finance',
            'correlation_id'   => 'app:ticket-123',
            'origin'           => 'queue',
            'provenance'       => 'imported',
            'source_id'        => self::SOURCE,
            'source_region'    => 'eu-west-2',
            'source_record_id' => 'rec-é-1',
            'import_batch_id'  => $result->batchId,
            'ip'               => '203.0.113.7',
            'occurred_at'      => '2026-10-01T09:00:00.123456Z',
            'recorded_at'      => '2026-11-02T09:00:00.000000Z',
            'credential_id'    => null,
            'guard'            => null,
            'user_agent'       => null,
        ], [
            'event'            => $row['event'],
            'outcome'          => $row['outcome'],
            'reason'           => $row['reason'],
            'actor'            => [$row['actor_type'], $row['actor_id']],
            'subject'          => [$row['subject_type'], $row['subject_id']],
            'principal'        => [$row['principal_type'], $row['principal_id']],
            'tenant'           => [$row['tenant_type'], $row['tenant_id']],
            'category'         => $row['category'],
            'correlation_id'   => $row['correlation_id'],
            'origin'           => $row['origin'],
            'provenance'       => $row['provenance'],
            'source_id'        => $row['source_id'],
            'source_region'    => $row['source_region'],
            'source_record_id' => $row['source_record_id'],
            'import_batch_id'  => $row['import_batch_id'],
            'ip'               => $row['ip'],
            'occurred_at'      => $row['occurred_at'],
            'recorded_at'      => $row['recorded_at'],
            'credential_id'    => $row['credential_id'],
            'guard'            => $row['guard'],
            'user_agent'       => $row['user_agent'],
        ]);
        self::assertIsString($row['source_digest']);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $row['source_digest']);

        $properties = json_decode((string) json_encode($row['properties']), true);

        self::assertIsArray($properties);

        ksort($properties);

        self::assertSame(['amount' => '1200.00', 'empty' => [], 'nested' => ['a' => [1, 2], 'b' => 2], 'zeta' => 'last'], self::sorted($properties));
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $config->set($key . '.journal_mode', 'wal');
    }

    /**
     * Insert a clashing row after each of the first classifications.
     *
     * @param  int  $times
     * @return \ArrayObject<int, string>
     */
    private function interfere(int $times): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $classified */
        $classified = new \ArrayObject;
        $row        = null;

        DB::listen(function (QueryExecuted $query) use ($classified, $times, &$row): void {
            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, EntrySettings::table()) || !str_contains($query->sql, 'source_record_id')) {
                return;
            }

            $classified->append($query->sql);

            if ($classified->count() > $times) {
                return;
            }

            $row ??= $this->interferingRow();

            DB::connection($query->connectionName)->table(EntrySettings::table())->insert($row);
        });

        return $classified;
    }

    /**
     * A row of `rec-1` of the source, as another import of it would store it.
     *
     * @return array<string, int|string|null>
     */
    private function interferingRow(): array
    {
        return [
            ...array_fill_keys(array_keys(RowCodec::COLUMNS), null),
            'id'                => '01932b4e-ffff-7000-8000-000000000001',
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'finance',
            'outcome'           => 'success',
            'provenance'        => 'imported',
            'source_id'         => self::SOURCE,
            'source_record_id'  => 'rec-1',
            'import_batch_id'   => '01932b4e-a000-7000-8000-0000000000ff',
            'source_digest'     => str_repeat('0', 64),
            'occurred_at'       => '2026-10-01 09:00:00.000001',
            'recorded_at'       => '2026-11-02 09:00:00.000000',
            'integrity_version' => 1,
            'key_id'            => 'k',
            'hmac'              => str_repeat('0', 64),
        ];
    }

    /**
     * The map with its keys sorted, at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $map
     * @return array<array-key, mixed>
     */
    private static function sorted(array $map): array
    {
        ksort($map);

        return array_map(static fn (mixed $value): mixed => is_array($value) && !array_is_list($value) ? self::sorted($value) : $value, $map);
    }

    /**
     * The ids of the stale batches, read afresh on every call.
     *
     * @return list<bool|float|int|string|null>
     *
     * @phpstan-impure
     */
    private function staleIds(): array
    {
        return array_column(app(ImportBatches::class)->stale(), 'id');
    }

    /**
     * The count of stored entries.
     *
     * @return int
     */
    private function entries(): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->count();
    }

    /**
     * Write a file of the given number of lines, `rec-1` onwards.
     *
     * @param  int  $count
     * @return string
     */
    private function importFile(int $count): string
    {
        return $this->file(array_map(static fn (int $number): string => (string) json_encode(self::line($number)), range(1, $count)));
    }

    /**
     * Write the lines to a file the children share.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = $this->childFile('import-' . count(glob($this->childFile('import-*')) ?: []) . '.ndjson');

        file_put_contents($path, implode("\n", $lines) . "\n");

        return $path;
    }

    /**
     * A line of the import format, `rec-<number>`.
     *
     * @param  int  $number
     * @return array<string, array<string, string>|string>
     */
    private static function line(int $number): array
    {
        return [
            'format'           => 'audit-log-import/v1',
            'source_record_id' => 'rec-' . $number,
            'occurred_at'      => '2026-10-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'category'         => 'finance',
            'properties'       => ['amount' => '1200.00'],
        ];
    }

    /**
     * The authority every import is made on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
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
