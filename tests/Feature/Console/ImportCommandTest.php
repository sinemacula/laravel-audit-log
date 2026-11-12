<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\ImportCommand;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use Tests\Concerns\CountsStatements;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:import`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportCommand::class)]
final class ImportCommandTest extends TestCase
{
    use CountsStatements, ReadsTheTrail, WritesTheJournal;

    /** @var array<string, string> The options of the authority every import is made on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.review'];

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every import is of, unless a test names another. */
    private const string SOURCE = 'crm-eu';

    /** @var string A running batch's id. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000e1';

    /** @var string A value of a line no output may hold. */
    private const string SECRET = 'SECRET-VALUE-4242';

    /** @var string What the command printed last. */
    private string $printed = '';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, name the source, bind services, register the command.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new ImportCommand);
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
     * An import prints its batch, status, counts and rejections, and exits 0.
     *
     * @return void
     */
    public function testAnImportPrintsItsBatchAndCounts(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1'), self::line('rec-2'), '{'])));

        $batch = $this->batch();

        self::assertSame(implode("\n", [
            sprintf('Batch %s: partial.', $batch['id']),
            'Read 3 lines: imported 2, duplicates 0, conflicts 0, rejected 1.',
            'Rejected as malformed_json: 1.',
            '',
        ]), $this->printed);
        self::assertSame([self::SOURCE, null, 'audit-log-import/v1'], [$batch['source_id'], $batch['source_region'], $batch['input_format']]);
        self::assertCount(1, $this->readRecords('audit_log.imported'));
    }

    /**
     * A dry run prints its plan and writes nothing.
     *
     * @return void
     */
    public function testADryRunWritesNothing(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1')]), ['--dry-run' => true, '--hold' => true]));
        self::assertSame("Dry run: nothing was written.\nRead 1 lines: would import 1, duplicates 0, conflicts 0, rejected 0.\n", $this->printed);
        self::assertSame(0, DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->table(EntrySettings::table())->count());
        self::assertSame([], $this->journalRows());
    }

    /**
     * `--region` names the source's region on the batch.
     *
     * @return void
     */
    public function testTheRegionIsKept(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1')]), ['--region' => 'eu-west-1']));
        self::assertSame('eu-west-1', $this->batch()['source_region']);
    }

    /**
     * `--from-export` reads the file as this package's export lines.
     *
     * @return void
     */
    public function testFromExportReadsExportLines(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1')]), ['--from-export' => true]));
        self::assertSame('audit-log-export/v1', $this->batch()['input_format']);
        self::assertStringContainsString('imported 0, duplicates 0, conflicts 0, rejected 1.', $this->printed);
    }

    /**
     * `--hold` places a hold of the `--hold-basis` basis on the batch.
     *
     * @return void
     */
    public function testHoldPlacesAHoldOfTheBasisNamed(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1')]), ['--hold' => true, '--hold-basis' => 'legal_claim']));

        $holds = app(AuditLifecycle::class)->holds();

        self::assertCount(1, $holds);
        self::assertSame(HoldBasis::LEGAL_CLAIM, $holds[0]->basis);
        self::assertSame($this->batch()['hold_id'], $holds[0]->id);
        self::assertStringContainsString(sprintf('Hold %s keeps the batch.', $holds[0]->id), $this->printed);
        self::assertCount(1, $this->readRecords('audit_log.held'));
    }

    /**
     * A hold asked for with no basis is placed on the basis `other`.
     *
     * @return void
     */
    public function testAHoldWithNoBasisIsOther(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1')]), ['--hold' => true]));
        self::assertSame(HoldBasis::OTHER, app(AuditLifecycle::class)->holds()[0]->basis);
    }

    /**
     * Lines already past their retention when they arrive are warned of.
     *
     * @return void
     */
    public function testLinesPastRetentionAreWarnedOf(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', ['finance' => 7]);

        self::assertSame(0, $this->import($this->file([self::line('rec-1', ['occurred_at' => '2026-10-01T09:00:00.000000Z']), self::line('rec-2')])));
        self::assertStringContainsString('1 lines were past their retention on arrival; the next prune deletes them unless a hold keeps them.', $this->printed);
    }

    /**
     * Conflicting source record ids are printed and dropped envelopes counted.
     *
     * @return void
     */
    public function testConflictsAndDroppedValuesArePrinted(): void
    {
        $this->import($this->file([self::line('rec-1')]));

        $envelope = ['amount' => '1300.00', 'token' => ['v' => 1, 'k' => 'key-1', 'c' => 'Y2lwaGVy']];

        self::assertSame(0, $this->import($this->file([self::line('rec-1', ['properties' => $envelope])])));
        self::assertStringContainsString('conflicts 1', $this->printed);
        self::assertStringContainsString('Conflicting source record ids: rec-1.', $this->printed);
        self::assertStringContainsString('Dropped 1 values shaped as an encrypted envelope.', $this->printed);
    }

    /**
     * `--json` writes the result as one JSON object, and nothing else.
     *
     * @return void
     */
    public function testJsonWritesTheResultAsOneObject(): void
    {
        self::assertSame(0, $this->import($this->file([self::line('rec-1'), '{']), ['--json' => true]));

        $lines = array_values(array_filter(explode("\n", $this->printed), static fn (string $line): bool => $line !== ''));

        self::assertCount(1, $lines);

        $result = json_decode($lines[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($result);
        self::assertSame(['partial', 2, 1, 1, ['malformed_json' => 1], true], [
            $result['status']     ?? null,
            $result['lines_read'] ?? null,
            $result['imported']   ?? null,
            $result['rejected']   ?? null,
            $result['rejections'] ?? null,
            $result['recorded']   ?? null,
        ]);
    }

    /**
     * `--close` marks a running batch `interrupted` and journals its finish.
     *
     * @return void
     */
    public function testCloseMarksARunningBatchInterrupted(): void
    {
        $this->runningBatch();

        self::assertSame(0, $this->import(null, ['--close' => self::BATCH, '--source' => null]));
        self::assertStringStartsWith(sprintf('Batch %s: interrupted.', self::BATCH), $this->printed);
        self::assertSame('interrupted', $this->batch()['status']);
        self::assertSame([JournalKind::IMPORT_STARTED->value, JournalKind::IMPORT_FINISHED->value], array_column($this->journalRows(), 'kind'));

        $records = $this->readRecords('audit_log.imported');

        self::assertCount(1, $records);
        self::assertSame(['failure', 'interrupted'], [$records[0]['outcome'], $records[0]['reason']]);
    }

    /**
     * Closing a batch that is not running exits 1, named by its class.
     *
     * @return void
     */
    public function testClosingABatchThatIsNotRunningExitsOne(): void
    {
        $this->import($this->file([self::line('rec-1')]));

        $batchId = (string) $this->batch()['id'];

        self::assertSame(1, $this->import(null, ['--close' => $batchId, '--source' => null]));
        self::assertSame("The import stopped with InvalidArgumentException.\n", $this->printed);
    }

    /**
     * An import that fails once started exits 1, named by its class alone.
     *
     * @return void
     */
    public function testAFailedImportExitsOne(): void
    {
        DB::listen(static function (QueryExecuted $query): void {
            $imported = in_array('invoice.approved', $query->bindings, true);

            if ($imported && str_starts_with(strtolower($query->sql), 'insert') && str_contains($query->sql, EntrySettings::table())) {
                throw new \RuntimeException('The entries could not be written: ' . self::SECRET);
            }
        });

        self::assertSame(1, $this->import($this->file([self::line('rec-1')])));
        self::assertSame("The import stopped with RuntimeException.\n", $this->printed);
        self::assertSame('failed', $this->batch()['status']);
    }

    /**
     * An import whose record could not be written still imports and warns.
     *
     * @return void
     */
    public function testAnUnrecordedImportWarns(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['duplicates']);

        self::assertSame(0, $this->import($this->file([self::line('rec-1')])));
        self::assertStringContainsString('The import\'s activity records could not all be written; audit-log:reconcile writes them from the journal.', $this->printed);
    }

    /**
     * Rows of `[whether a file is given, options, message]`.
     *
     * @return iterable<string, array{0: bool, 1: array<string, bool|string|null>, 2: string}>
     */
    public static function provideRefusals(): iterable
    {
        $nothing = 'Name the file to import and its --source, or a batch to --close.';
        $close   = 'The --close option takes no file and no other option of an import.';
        $basis   = 'The --hold-basis option must be legal_claim, regulatory, investigation or other.';

        yield from [
            'no file'                  => [false, ['--source' => self::SOURCE], $nothing],
            'no source'                => [true, ['--source' => null], $nothing],
            'a close with a file'      => [true, ['--close' => self::BATCH, '--source' => null], $close],
            'a close with a source'    => [false, ['--close' => self::BATCH, '--source' => self::SOURCE], $close],
            'a close with a dry run'   => [false, ['--close' => self::BATCH, '--source' => null, '--dry-run' => true], $close],
            'a close that is no batch' => [false, ['--close' => 'batch-1', '--source' => null], 'The --close option must name a batch by its id, a lower-case UUID.'],
            'a basis with no hold'     => [true, ['--hold-basis' => 'legal_claim'], 'The --hold-basis option goes only with --hold.'],
            'an unknown basis'         => [true, ['--hold' => true, '--hold-basis' => 'litigation'], $basis],
            'this installation'        => [true, ['--source' => self::OWN], 'The --source option is never this installation\'s own source'],
            'a source with a newline'  => [true, ['--source' => "crm\neu"], 'An import\'s source id must be from 1 to 64 characters, with no control characters.'],
            'a region too long'        => [true, ['--region' => str_repeat('r', 33)], 'An import\'s region must be from 1 to 32 characters, with no control characters.'],
            'no operator'              => [true, ['--by-type' => ''], 'The --by-type option is required.'],
        ];
    }

    /**
     * Each refusal exits 2, printing why, before any statement runs.
     *
     * @param  bool  $withFile
     * @param  array<string, bool|string|null>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalExitsTwoBeforeAnyStatement(bool $withFile, array $options, string $message): void
    {
        $file       = $withFile ? $this->file([self::line('rec-1')]) : null;
        $statements = $this->countStatements();

        self::assertSame(2, $this->import($file, $options));
        self::assertStringContainsString($message, $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * A missing file is refused with exit 2, its path printed unstyled.
     *
     * @return void
     */
    public function testAMissingFileIsRefused(): void
    {
        self::assertSame(2, $this->import(sys_get_temp_dir() . '/<error>missing</error>.ndjson'));
        self::assertStringContainsString('<error>missing</error>.ndjson` does not exist.', $this->printed);
    }

    /**
     * Nothing printed holds a line's properties, actor or subject.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $line = self::line('rec-1', [
            'properties' => ['card' => self::SECRET],
            'actor'      => ['type' => 'user', 'id' => 'actor-secret'],
            'subject'    => ['type' => 'invoice', 'id' => 'inv_secret'],
        ]);

        $this->import($this->file([$line, '{"format": "audit-log-import/v1", "card": "' . self::SECRET . '"}']));

        $printed = $this->printed;

        $this->import($this->file([$line]), ['--json' => true, '--source' => 'crm-us']);

        $printed .= $this->printed;

        foreach ([self::SECRET, 'actor-secret', 'inv_secret'] as $value) {
            self::assertStringNotContainsString($value, $printed, $value);
        }
    }

    /**
     * Leave a batch as a killed import would: `running`, with only its start.
     *
     * @return void
     */
    private function runningBatch(): void
    {
        DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->insert([
            'id'                  => self::BATCH,
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
            'status'              => 'running',
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'conflict_ids'        => null,
            'started_at'          => '2026-11-02 08:00:00.000000',
            'updated_at'          => '2026-11-02 08:00:00.000000',
            'finished_at'         => null,
        ]);

        $this->journalRow(JournalKind::IMPORT_STARTED, [
            'batch_id'            => self::BATCH,
            'source_id'           => 'crm-killed',
            'source_region'       => null,
            'format'              => 'audit-log-import/v1',
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);
    }

    /**
     * The latest batch's row.
     *
     * @return array<string, scalar|null>
     */
    private function batch(): array
    {
        $row = DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->orderByDesc('started_at')->orderByDesc('id')->first();

        self::assertNotNull($row);

        /** @var array<string, scalar|null> */
        return (array) $row;
    }

    /**
     * A line of the import format, with the fields given over its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $recordId
     * @param  array<string, mixed>  $fields
     * @return string
     */
    private static function line(string $recordId, array $fields = []): string
    {
        return (string) json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-11-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'category'         => 'finance',
            'properties'       => ['amount' => '1200.00'],
            ...$fields,
        ]);
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'import-command-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * Run the command on the file and return its exit code; `null` is omitted.
     *
     * @param  ?string  $file
     * @param  array<string, bool|string|null>  $options
     * @return int
     */
    private function import(?string $file, array $options = []): int
    {
        $kernel     = $this->app?->make(Kernel::class);
        $parameters = array_filter($options + ['--source' => self::SOURCE] + self::AUTHORITY, static fn (bool|string|null $value): bool => $value !== null);

        assert($kernel instanceof Kernel);

        if ($file !== null) {
            $parameters['file'] = $file;
        }

        $exit          = $kernel->call('audit-log:import', $parameters);
        $this->printed = $kernel->output();

        return $exit;
    }
}
