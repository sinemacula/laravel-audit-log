<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Statement budgets of an import: ten thousand rows open no savepoint and one
 * transaction per chunk; a chunk's statements are fixed, apart from its
 * inserts, which scale with the rows each insert carries on its engine and
 * never with the rows themselves; and a dry run writes nothing. Every budget is
 * a count of statements and transactions, never a time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportWriter::class)]
#[CoversClass(AuditImporter::class)]
final class ImportStatementBudgetTest extends PerformanceContractTestCase
{
    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var string The batch the writer's chunks are of. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Name this installation and bind the configured retention policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        app(ConfigRepository::class)->set('audit-log.source.id', 'app-eu-1');
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * Remove the files this test wrote.
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

        parent::tearDown();
    }

    /**
     * Ten thousand rows in chunks of 500 open no savepoint: one transaction per
     * chunk and one for each of the journal's start and finish, none nested,
     * counted by the transaction events, since a savepoint never reaches the
     * statement log, and nothing rolled back.
     *
     * @return void
     */
    public function testTenThousandRowsOpenNoSavepoint(): void
    {
        $path   = $this->file(10000);
        $result = $this->assertTransactionBudget(22, 22, fn () => $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority()));

        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame(10000, $result->imported);
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
        self::assertSame(10000, DB::connection()->table(EntrySettings::table())->count());
    }

    /**
     * A chunk's statements are fixed but for its inserts: a chunk of 500 new
     * lines and one of 100 differ only by the inserts, which are as many as the
     * engine's rows per insert need, and each chunk is one transaction with no
     * savepoint.
     *
     * @return void
     */
    public function testTheStatementsAreFixedPerChunk(): void
    {
        $this->startBatch();

        $perInsert = DB::connection()->getDriverName() === 'sqlite' ? ImportWriter::SQLITE_ROWS_PER_INSERT : ImportWriter::ROWS_PER_INSERT;
        $budgets   = [];

        foreach ([[1, 500], [501, 100]] as [$first, $count]) {
            $this->assertStatementBudget(...$this->chunkBudget($first, $count, $perInsert));

            $statements = $this->capturedStatements();
            $inserts    = count(array_filter($statements, static fn (string $statement): bool => str_starts_with(strtolower($statement), 'insert')));

            self::assertSame((int) ceil($count / $perInsert), $inserts);

            $budgets[] = count($statements) - $inserts;
        }

        self::assertSame($budgets[0], $budgets[1]);
    }

    /**
     * A dry run of a thousand lines writes nothing and opens no transaction:
     * every statement it issues is a read.
     *
     * @return void
     */
    public function testADryRunIssuesNoWrite(): void
    {
        $path   = $this->file(1000);
        $result = $this->assertTransactionBudget(0, 0, fn () => $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), dryRun: true));

        self::assertSame(1000, $result->imported);
        $writes = array_filter($this->capturedStatements(), static fn (string $statement): bool => !str_starts_with(strtolower(ltrim($statement)), 'select'));

        self::assertSame([], array_values($writes));
        self::assertNotSame([], $this->capturedStatements());
    }

    /**
     * The budget of a chunk of new lines from the first given: one read to
     * classify, and the claim, the inserts and the counts as writes, with no
     * savepoint and no rollback.
     *
     * @param  int  $first
     * @param  int  $count
     * @param  int  $perInsert
     * @return array{0: int, 1: int, 2: int, 3: int, 4: callable(): void}
     */
    private function chunkBudget(int $first, int $count, int $perInsert): array
    {
        $lines = array_map(static fn (int $number): ImportLine => self::line($number), range($first, $first + $count - 1));
        $tally = new ImportTally;

        foreach ($lines as $line) {
            $tally->countRead();
        }

        return [1, 2 + (int) ceil($count / $perInsert), 0, 0, fn () => app(ImportWriter::class)->write(self::BATCH, $lines, $tally, CarbonImmutable::now())];
    }

    /**
     * Start the batch the writer's chunks are of.
     *
     * @return void
     */
    private function startBatch(): void
    {
        app(ImportBatches::class)->start([
            'id'                  => self::BATCH,
            'source_id'           => self::SOURCE,
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
    }

    /**
     * Write a file of the number of lines given, and return its path.
     *
     * @param  int  $count
     * @return string
     */
    private function file(int $count): string
    {
        $path   = (string) tempnam(sys_get_temp_dir(), 'import-budget-');
        $handle = fopen($path, 'wb');

        assert($handle !== false);

        for ($number = 1; $number <= $count; $number++) {
            $line = ['format' => 'audit-log-import/v1', 'source_record_id' => 'rec-' . $number, 'occurred_at' => '2026-10-01T09:00:00.000001Z', 'event' => 'invoice.approved'];

            fwrite($handle, json_encode([...$line, 'outcome' => 'success', 'category' => 'finance', 'properties' => ['amount' => '1200.00']]) . "\n");
        }

        fclose($handle);

        $this->files[] = $path;

        return $path;
    }

    /**
     * A line of the number given.
     *
     * @param  int  $number
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(int $number): ImportLine
    {
        return new ImportLine(
            $number,
            self::SOURCE,
            null,
            'rec-' . $number,
            'invoice.approved',
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            'finance',
            null,
            ['amount' => '1200.00'],
            null,
            null,
            null,
        );
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
