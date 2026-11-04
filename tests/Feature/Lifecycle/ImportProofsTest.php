<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests that prove an import end to end through `audit-log:import` and
 * the commands around it, as the package ships them bound and registered: a dry
 * run writes nothing at all; an imported row holds, column by column, what its
 * line asserted, as this installation's acceptance of it, signed here; the
 * batch, its journal rows, its hold and its records say who imported what, from
 * which file, and how it ended; a repeated import finds duplicates and a line
 * asserting something else under a record id already imported a conflict;
 * another installation's export imports as foreign evidence that seals and
 * verifies here; and a spilled record replayed is the record itself, never an
 * import.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
#[CoversClass(AuditLifecycle::class)]
#[CoversClass(AuditImporter::class)]
final class ImportProofsTest extends TestCase
{
    use ReadsTheTrail, WritesTheJournal;

    /** @var string When every import runs, unless a test moves the clock. */
    private const string NOW = '2026-11-02 09:00:00';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every import file is of. */
    private const string SOURCE = 'crm-eu';

    /** @var string The installation whose export is imported. */
    private const string EXPORTER = 'app-us-1';

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var array<string, string> The operator every import is made by. */
    private const array OPERATOR = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'migration.crm', '--reference' => 'app:ticket-123'];

    /** @var list<string> The keys of a line a source assertion holds, in its order after its version. */
    private const array ASSERTED = [
        'event', 'occurred_at', 'outcome', 'actor', 'subject', 'principal', 'tenant', 'reason', 'correlation_id', 'properties', 'context', 'origin', 'ip',
    ];

    /** @var list<string> The keys of a line that hold a reference, which a source assertion holds as `[type, id]`. */
    private const array REFERENCES = ['actor', 'subject', 'principal', 'tenant'];

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, name this installation's source and report to a
     * recording handler. Nothing is bound or registered by hand.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
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
     * A dry run, even one asking for a hold, reads the file, classifies and
     * counts its lines and issues no statement but reads: no entry, no batch,
     * no journal row, no hold, no change to the installation id and no record.
     *
     * @return void
     */
    public function testADryRunMakesNoWrite(): void
    {
        $file   = $this->file([self::line('rec-1'), self::line('rec-2'), self::line('rec-3', ['event' => 'audit_log.pruned'])]);
        $state  = $this->storage()->table(IntegrityTables::stateTable())->get()->all();
        $writes = [];

        DB::listen(static function (QueryExecuted $query) use (&$writes): void {
            if (str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
                return;
            }

            $writes[] = $query->sql;
        });

        $result = $this->import(['file' => $file, '--source' => self::SOURCE, '--dry-run' => true, '--hold' => true, '--hold-basis' => 'legal_claim']);

        self::assertSame([], $writes);
        self::assertSame([true, false, false], [$result['dry_run'], $result['committed'], $result['recorded']]);
        self::assertSame([null, null, null], [$result['batch_id'], $result['status'], $result['hold_id']]);
        self::assertSame([3, 2, 0, 0, 1], [$result['lines_read'], $result['imported'], $result['duplicates'], $result['conflicts'], $result['rejected']]);
        self::assertSame(['reserved_code' => 1], $result['rejections']);

        $tables = [EntrySettings::table(), LifecycleTables::importBatchesTable(), LifecycleTables::journalTable(), LifecycleTables::holdsTable()];

        foreach ($tables as $table) {
            self::assertSame(0, $this->storage()->table($table)->count(), $table);
        }

        self::assertEquals($state, $this->storage()->table(IntegrityTables::stateTable())->get()->all());
    }

    /**
     * An imported row holds what its line asserted, column by column: a fresh
     * id of the import's time, its code in the category given, its outcome and
     * reason, its references, correlation id, origin, address, context and
     * properties; it is `imported`, of its source and region, under its record
     * id there, in its batch, with the keyed digest of the assertion; it
     * happened when the line says and was recorded at the import; nothing the
     * line could not assert is set; and this installation's ring signs it.
     *
     * @return void
     */
    public function testEveryColumnOfAnImportedRow(): void
    {
        $line = [
            'format'           => 'audit-log-import/v1',
            'source_record_id' => 'rec-1',
            'occurred_at'      => '2026-11-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'denied',
            'reason'           => 'over_limit',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'subject'          => ['type' => 'invoice', 'id' => 'inv_0042'],
            'principal'        => ['type' => 'membership', 'id' => 'mem_7'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
            'correlation_id'   => 'app:ticket-123',
            'properties'       => ['amount' => '1200.00'],
            'context'          => ['method' => 'POST', 'route' => 'invoices.approve'],
            'origin'           => 'http',
            'ip'               => '203.0.113.7',
        ];

        $result = $this->import(['file' => $this->file([(string) json_encode($line)]), '--source' => self::SOURCE, '--region' => 'eu-west-1']);
        $rows   = $this->entries();

        self::assertSame(['complete', 1], [$result['status'], $result['imported']]);
        self::assertCount(1, $rows);

        $row = $rows[0];

        self::assertIsString($row['id']);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $row['id']);
        self::assertSame(CarbonImmutable::now()->getTimestampMs(), hexdec(substr(str_replace('-', '', $row['id']), 0, 12)));

        $digest = app(SourceDigest::class);

        self::assertSame([
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'finance',
            'outcome'           => 'denied',
            'reason'            => 'over_limit',
            'actor_type'        => 'user',
            'actor_id'          => '42',
            'subject_type'      => 'invoice',
            'subject_id'        => 'inv_0042',
            'principal_type'    => 'membership',
            'principal_id'      => 'mem_7',
            'tenant_type'       => 'organisation',
            'tenant_id'         => 'org_01',
            'credential_id'     => null,
            'guard'             => null,
            'session_id'        => null,
            'request_id'        => null,
            'trace_id'          => null,
            'correlation_id'    => 'app:ticket-123',
            'origin'            => 'http',
            'provenance'        => 'imported',
            'source_id'         => self::SOURCE,
            'source_region'     => 'eu-west-1',
            'source_record_id'  => 'rec-1',
            'import_batch_id'   => $result['batch_id'],
            'source_digest'     => $digest->of(self::assertionOf($line), $digest->signingKeyId()),
            'ip'                => '203.0.113.7',
            'user_agent'        => null,
            'occurred_at'       => '2026-11-01T09:00:00.000001Z',
            'recorded_at'       => '2026-11-02T09:00:00.000000Z',
            'integrity_version' => 1,
            'key_id'            => $digest->signingKeyId(),
        ], array_diff_key($row, array_flip(['id', 'context', 'properties', 'hmac'])));

        self::assertSameProperties(['method' => 'POST', 'route' => 'invoices.approve'], self::arrayOf($row['context']));
        self::assertSameProperties(['amount' => '1200.00'], self::propertiesOf($row));
        self::assertSame(array_keys(RowCodec::COLUMNS), array_keys($row));
        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame([], $this->readRecords('audit_log.held'));
    }

    /**
     * The batch records who imported, why and under which reference, from which
     * source, region, format and file, that nothing outside verified it, its
     * hold, its counts and times, and how it ended; the journal holds its
     * start, its hold and its finish; the hold keeps its entries and is listed;
     * and the hold and the import are each recorded once, by the importer.
     *
     * @return void
     */
    public function testTheBatchRecord(): void
    {
        $file   = $this->file([self::line('rec-1'), self::line('rec-2'), self::line('rec-2'), '{']);
        $result = $this->import(['file' => $file, '--source' => self::SOURCE, '--region' => 'eu-west-1', '--hold' => true, '--hold-basis' => 'legal_claim']);

        self::assertIsString($result['batch_id']);
        self::assertIsString($result['hold_id']);
        self::assertSame([true, true, 'partial'], [$result['committed'], $result['recorded'], $result['status']]);

        $batch    = (array) $this->storage()->table(LifecycleTables::importBatchesTable())->where('id', $result['batch_id'])->first();
        $expected = [
            'id'                 => $result['batch_id'],
            'source_id'          => self::SOURCE,
            'source_region'      => 'eu-west-1',
            'input_format'       => 'audit-log-import/v1',
            'importer_type'      => 'App\Models\User',
            'importer_id'        => '7',
            'reason'             => 'migration.crm',
            'external_reference' => 'app:ticket-123',
            'file_sha256'        => hash_file('sha256', $file),
            'hold_id'            => $result['hold_id'],
            'status'             => 'partial',
            'conflict_ids'       => null,
        ];

        self::assertSame($expected, array_intersect_key($batch, $expected));
        self::assertFalse((bool) $batch['externally_verified']);
        self::assertSame([4, 2, 1, 0, 1], array_map(intval(...), [$batch['lines_read'], $batch['imported'], $batch['duplicates'], $batch['conflicts'], $batch['rejected']]));
        self::assertSame([self::NOW, self::NOW, self::NOW], array_map(self::time(...), [$batch['started_at'], $batch['updated_at'], $batch['finished_at']]));

        $journal = $this->journalRows();

        self::assertSame([JournalKind::IMPORT_STARTED->value, JournalKind::HOLD->value, JournalKind::IMPORT_FINISHED->value], array_column($journal, 'kind'));
        self::assertSame([$result['hold_id'], $result['hold_id'], null], array_column($journal, 'hold_id'));

        $holds = $this->jsonOf('audit-log:holds')['holds'] ?? null;

        self::assertIsArray($holds);
        self::assertSame([$result['hold_id']], array_column($holds, 'id'));
        self::assertSame($result['batch_id'], $this->storage()->table(LifecycleTables::holdsTable())->value('import_batch_id'));

        $held     = $this->readRecords('audit_log.held');
        $imported = $this->readRecords('audit_log.imported');

        self::assertCount(1, $held);
        self::assertCount(1, $imported);
        self::assertSame(['App\Models\User', '7', 'success'], [$imported[0]['actor_type'], $imported[0]['actor_id'], $imported[0]['outcome']]);
        $properties = self::propertiesOf($imported[0]);
        $recorded   = [$properties['batch_id'], $properties['source_id'], $properties['status'], $properties['hold_id']];

        self::assertSame([$result['batch_id'], self::SOURCE, 'partial', $result['hold_id']], $recorded);
        self::assertSame($result['hold_id'], self::propertiesOf($held[0])['hold_id'] ?? null);
    }

    /**
     * Importing a file again stores nothing twice: every line is a duplicate
     * and the batch is complete. A file asserting something else under a record
     * id imported already is a conflict, kept out and listed, beside the new
     * line it imports, and the batch is partial.
     *
     * @return void
     */
    public function testRepeatedAndConflictingImports(): void
    {
        $file = $this->file([self::line('rec-1'), self::line('rec-2')]);

        $first  = $this->import(['file' => $file, '--source' => self::SOURCE]);
        $second = $this->import(['file' => $file, '--source' => self::SOURCE]);

        self::assertSame(['complete', 2, 0, 0], [$first['status'], $first['imported'], $first['duplicates'], $first['conflicts']]);
        self::assertSame(['complete', 0, 2, 0], [$second['status'], $second['imported'], $second['duplicates'], $second['conflicts']]);
        self::assertCount(2, $this->entries());

        $changed = $this->file([self::line('rec-2', ['outcome' => 'failure', 'reason' => 'reversed']), self::line('rec-3')]);
        $third   = $this->import(['file' => $changed, '--source' => self::SOURCE]);

        self::assertSame(['partial', 1, 0, 1, ['rec-2']], [$third['status'], $third['imported'], $third['duplicates'], $third['conflicts'], $third['conflict_ids']]);
        self::assertSame(['rec-1', 'rec-2', 'rec-3'], array_column($this->entries(), 'source_record_id'));
        self::assertSame(['success', 'success', 'success'], array_column($this->entries(), 'outcome'));

        $conflicts = $this->storage()->table(LifecycleTables::importBatchesTable())->where('id', $third['batch_id'])->value('conflict_ids');

        self::assertIsString($conflicts);
        self::assertSame(['rec-2'], json_decode($conflicts, true));

        $other = $this->import(['file' => $file, '--source' => 'billing-eu']);

        self::assertSame(['complete', 2, 0], [$other['status'], $other['imported'], $other['duplicates']]);
    }

    /**
     * Another installation's export imports here: its lines become rows of this
     * installation, `imported` from that installation under the ids it gave
     * them, never the same rows, and they seal and verify in this
     * installation's chain like any entry.
     *
     * @return void
     */
    public function testAnotherInstallationsExportImports(): void
    {
        $this->allowEverything();

        app(ConfigRepository::class)->set('audit-log.source.id', self::EXPORTER);

        $exported = [
            $this->seedEntry(['source_id' => self::EXPORTER, 'source_region' => 'us-west-2'], '2026-11-01T09:00:00.000001Z'),
            $this->seedEntry(['source_id' => self::EXPORTER, 'source_region' => 'us-west-2', 'outcome' => 'denied', 'reason' => 'over_limit'], '2026-11-01T09:00:00.000002Z'),
        ];

        $file = $this->file([]);

        self::assertSame(0, Artisan::call('audit-log:export', ['file' => $file, '--force' => true, '--viewer-type' => 'App\Models\User', '--viewer-id' => '7']), Artisan::output());

        $this->files[] = $file . '.manifest.json';

        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($file)), static fn (string $line): bool => $line !== ''));

        self::assertCount(2, $lines);

        // The exporting installation's database is not this one's
        foreach ([EntrySettings::table(), EntrySettings::artifactsTable(), IntegrityTables::stateTable()] as $table) {
            $this->storage()->table($table)->delete();
        }

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);

        $result = $this->import(['file' => $file, '--from-export' => true, '--source' => self::EXPORTER, '--region' => 'us-west-2']);
        $rows   = $this->entries('audit_log.');

        self::assertSame(['complete', 2, 0], [$result['status'], $result['imported'], $result['rejected']]);
        self::assertSame($this->sorted($exported), $this->sorted(array_column($rows, 'source_record_id')));
        self::assertSame([], array_values(array_intersect($exported, array_column($rows, 'id'))));
        self::assertSame(['imported', 'imported'], array_column($rows, 'provenance'));
        self::assertSame([self::EXPORTER, self::EXPORTER], array_column($rows, 'source_id'));
        self::assertSame([$result['batch_id'], $result['batch_id']], array_column($rows, 'import_batch_id'));
        self::assertSame(['success', 'denied'], array_column($rows, 'outcome'));
        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]));
        self::assertSame(0, Artisan::call('audit-log:verify'), Artisan::output());
    }

    /**
     * A record spilled by a failed write and replayed with `audit-log:replay`
     * is the record itself: it keeps its id and its `captured` provenance, is
     * of this installation, belongs to no batch and carries no source record id
     * or digest, and replaying it writes no batch and no journal row.
     *
     * @return void
     */
    public function testReplayIsNotImport(): void
    {
        $spill = $this->file([]);

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($spill),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);

        $record = (new RecordFinaliser(FrozenClock::at(self::NOW), app(RecordSigner::class)))->finalise(RecordFactory::captured());

        app(FailureSpill::class)->spillFinalised($record);

        self::assertSame(0, Artisan::call('audit-log:replay', ['--spill' => $spill]), Artisan::output());

        $rows = $this->entries();

        self::assertCount(1, $rows);
        self::assertSame([$record->record->id, 'captured', self::OWN, null, null, null], [
            $rows[0]['id'], $rows[0]['provenance'], $rows[0]['source_id'], $rows[0]['import_batch_id'], $rows[0]['source_record_id'], $rows[0]['source_digest'],
        ]);
        self::assertSame(0, $this->storage()->table(LifecycleTables::importBatchesTable())->count());
        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->readRecords('audit_log.imported'));
    }

    /**
     * Run `audit-log:import --json` with the parameters given as the operator,
     * assert it succeeds, and return the result it wrote.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, bool|string>  $parameters
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     *
     * @phpstan-impure
     */
    private function import(array $parameters): array
    {
        return $this->jsonOf('audit-log:import', [...$parameters, ...self::OPERATOR]);
    }

    /**
     * Run the command with `--json` and the parameters given, assert it
     * succeeds, and return the object it wrote.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $command
     * @param  array<string, bool|string>  $parameters
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     *
     * @phpstan-impure
     */
    private function jsonOf(string $command, array $parameters = []): array
    {
        $exit    = Artisan::call($command, [...$parameters, '--json' => true]);
        $printed = Artisan::output();

        self::assertSame(0, $exit, $printed);

        $decoded = json_decode(trim($printed), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * Every stored entry but the package's own records, or but those of the
     * prefix given, decoded through the row codec, by source record id and id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $except
     * @return list<array<string, mixed>>
     */
    private function entries(string $except = 'audit_log.'): array
    {
        $rows = $this->storage()->table(EntrySettings::table())->where('event', 'not like', $except . '%')->orderBy('source_record_id')->orderBy('id')->get()->all();

        return array_values(array_map(static fn (object $row): array => app(RowCodec::class)->decode((array) $row), $rows));
    }

    /**
     * A line of the import format, of the record id given and with the fields
     * given over its own.
     *
     * @param  string  $recordId
     * @param  array<string, string>  $fields
     * @return string
     */
    private static function line(string $recordId, array $fields = []): string
    {
        return (string) json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-10-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
            'properties'       => ['amount' => '1200.00'],
            ...$fields,
        ]);
    }

    /**
     * The source assertion of a decoded line of the import format, as the
     * digest is computed over it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $line
     * @return array<string, mixed>
     */
    private static function assertionOf(array $line): array
    {
        $assertion = ['v' => 1];

        foreach (self::ASSERTED as $key) {
            $value = $line[$key] ?? null;

            $assertion[$key] = in_array($key, self::REFERENCES, true) && is_array($value) ? [$value['type'] ?? null, $value['id'] ?? null] : $value;
        }

        return $assertion;
    }

    /**
     * A decoded JSON value as an array of arrays.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function arrayOf(mixed $value): array
    {
        $array = json_decode(json_encode($value, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($array);

        return $array;
    }

    /**
     * A stored time as `Y-m-d H:i:s`, whatever fractional digits the engine
     * returns, or `null`.
     *
     * @param  bool|float|int|string|null  $stored
     * @return ?string
     */
    private static function time(bool|float|int|string|null $stored): ?string
    {
        return is_string($stored) ? (new CarbonImmutable($stored, 'UTC'))->format('Y-m-d H:i:s') : null;
    }

    /**
     * The strings given, sorted bytewise.
     *
     * @param  list<string>  $strings
     * @return list<string>
     */
    private function sorted(array $strings): array
    {
        sort($strings, SORT_STRING);

        return $strings;
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'import-proofs-');

        file_put_contents($path, $lines === [] ? '' : implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function storage(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
