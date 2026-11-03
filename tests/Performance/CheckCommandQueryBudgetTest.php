<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\DeliveryChecks;
use SineMacula\Laravel\AuditLog\Console\EngineChecks;
use SineMacula\Laravel\AuditLog\Console\IntegrityChecks;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\Concerns\SealsEntries;

/**
 * Statement-budget contract for `audit-log:check`: a run makes a few reads of
 * the schema and, on MySQL, of the session and the table's engine, whatever the
 * tables hold, and never writes, begins a savepoint or rolls back. In sync mode
 * the delivery checks read configuration alone, so a run reads what the engine
 * and schema checks of the entries table, the schema checks of the artifacts
 * table and the integrity checks of the checkpoints, checkpoint members and
 * integrity state tables read; in outbox mode they read the outbox and
 * deliveries tables' schema too, and still write nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
#[CoversClass(DeliveryChecks::class)]
#[CoversClass(IntegrityChecks::class)]
final class CheckCommandQueryBudgetTest extends PerformanceContractTestCase
{
    use SealsEntries;

    /** @var int The most statements a run makes on any engine, as counted on SQLite: four schema reads for the entries table, for the artifacts table and for each integrity table. */
    private const int MAX_STATEMENTS = 20;

    /** @var int How many times a sync run's statements an outbox run may make. */
    private const int OUTBOX_FACTOR = 2;

    /**
     * Register the command with the console kernel, which keeps the test
     * independent of the provider, whose registration
     * `AuditLogServiceProviderTest::testTheCheckCommandIsRegistered` pins.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new CheckCommand);
    }

    /**
     * A passing run makes at most twenty statements, none of them a write, and
     * begins no savepoint and makes no rollback, on every engine.
     *
     * @return void
     */
    public function testTheCheckMakesBoundedReadsAndNoWrites(): void
    {
        $code = $this->capture(fn (): int => $this->check());

        $statements = implode(' | ', $this->capturedStatements());

        self::assertSame(0, $code);
        self::assertNotSame([], $this->capturedStatements());
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()), "Statements: {$statements}");
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
    }

    /**
     * A run reads no more with 200 entries in the table, every one of them
     * sealed, than with none.
     *
     * @return void
     */
    public function testTheCheckReadsNoMoreWithMoreEntries(): void
    {
        $this->capture(fn (): int => $this->check());

        $empty = $this->capturedStatements();

        DB::table('audit_log_entries')->insert(array_map(self::row(...), range(1, 200)));

        $this->sealAt('2026-11-02 00:00:00');
        $this->sealAll();

        $this->capture(fn (): int => $this->check());

        $full = $this->capturedStatements();

        self::assertSame(200, DB::table('audit_log_entries')->count());
        self::assertSame(200, DB::table(IntegrityTables::membersTable())->count());
        self::assertNotSame([], $this->seals());
        self::assertSame($empty, $full);
    }

    /**
     * The integrity checks write nothing, begin no savepoint and make no
     * rollback, whatever the integrity tables hold, and leave every seal,
     * member and progress row as it was.
     *
     * @return void
     */
    public function testTheIntegrityChecksWriteNothing(): void
    {
        DB::table('audit_log_entries')->insert(array_map(self::row(...), range(1, 20)));

        $this->sealAt('2026-11-02 00:00:00');
        $this->sealAll();

        $before = $this->integrityRows();
        $checks = app(IntegrityChecks::class);

        $this->capture(static fn (): array => $checks->problems());

        $statements = implode(' | ', $this->capturedStatements());

        self::assertNotSame([], $this->capturedStatements());
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());

        self::assertSame(0, $this->capture(fn (): int => $this->check()));
        self::assertSame([], $this->capturedWrites());
        self::assertSame($before, $this->integrityRows());
    }

    /**
     * A sync run reads exactly what the engine and schema checks of the entries
     * table, the schema checks of the artifacts table and the integrity checks
     * read on their own, so the delivery checks add no statement, and the bound
     * of twenty still holds: the four statements the artifacts table's schema
     * check reads on SQLite raised it from sixteen.
     *
     * @return void
     */
    public function testASyncRunReadsNoMoreThanItDid(): void
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        $integrity = app(IntegrityChecks::class);

        $this->capture(static function () use ($database, $integrity): void {
            (new EngineChecks($database))->problems(self::CONNECTION, 'audit_log_entries');
            (new SchemaChecks($database))->problems(self::CONNECTION, 'audit_log_entries');
            (new SchemaChecks($database))->problems(self::CONNECTION, 'audit_log_artifacts', TableShape::artifacts());
            $integrity->problems();
        });

        $baseline = $this->capturedStatements();

        self::assertSame(0, $this->capture(fn (): int => $this->check()));
        self::assertSame($baseline, $this->capturedStatements());
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()));
    }

    /**
     * An outbox run reads the outbox and deliveries tables' schema as well, so
     * more than a sync run, but at most twice as much.
     *
     * @return void
     */
    public function testAnOutboxRunReadsAtMostTwiceASyncRun(): void
    {
        $this->capture(fn (): int => $this->check());

        $sync = count($this->capturedStatements());

        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        self::assertSame(0, $this->capture(fn (): int => $this->check()));

        $outbox     = count($this->capturedStatements());
        $statements = implode(' | ', $this->capturedStatements());

        self::assertGreaterThan($sync, $outbox, "Statements: {$statements}");
        self::assertLessThanOrEqual(self::OUTBOX_FACTOR * $sync, $outbox, "Statements: {$statements}");
    }

    /**
     * An outbox run writes nothing, begins no savepoint and makes no rollback,
     * on every engine, whatever the outbox and deliveries tables hold.
     *
     * @return void
     */
    public function testAnOutboxRunWritesNothing(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        DB::table('audit_log_outbox')->insert([
            'id'           => '0195f4a2-7b1c-7000-8000-000000000001',
            'payload'      => 'payload',
            'attempts'     => 0,
            'available_at' => self::NOW,
            'created_at'   => self::NOW,
        ]);

        $code       = $this->capture(fn (): int => $this->check());
        $statements = implode(' | ', $this->capturedStatements());

        self::assertSame(0, $code);
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
        self::assertSame(1, DB::table('audit_log_outbox')->count());
    }

    /**
     * Run the command and return its exit code.
     *
     * @return int
     */
    private function check(): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:check');
    }

    /**
     * Every row of the integrity tables, by table, in key order.
     *
     * @return array<string, list<array<string, scalar|null>>>
     */
    private function integrityRows(): array
    {
        $rows = [];

        foreach ([IntegrityTables::checkpointsTable() => 'id', IntegrityTables::membersTable() => 'entry_id', IntegrityTables::stateTable() => 'name'] as $table => $key) {

            /** @var list<array<string, scalar|null>> $read */
            $read = array_map(static fn (object $row): array => (array) $row, DB::table($table)->orderBy($key)->get()->all());

            $rows[$table] = $read;
        }

        return $rows;
    }

    /**
     * An entries row with every column a row must have, numbered so each row's
     * id is its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function row(int $number): array
    {
        return [
            'id'                => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'billing',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => self::NOW,
            'recorded_at'       => self::NOW,
            'integrity_version' => 1,
            'key_id'            => 'test-key',
            'hmac'              => str_repeat('a', 64),
        ];
    }
}
