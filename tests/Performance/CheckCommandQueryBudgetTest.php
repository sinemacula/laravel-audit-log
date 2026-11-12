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
use SineMacula\Laravel\AuditLog\Console\LifecycleChecks;
use SineMacula\Laravel\AuditLog\Console\PrivacyChecks;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\SealsEntries;

/**
 * Statement budget for `audit-log:check`: a run makes a bounded number of reads
 * whatever the tables hold, and writes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
#[CoversClass(DeliveryChecks::class)]
#[CoversClass(IntegrityChecks::class)]
#[CoversClass(LifecycleChecks::class)]
#[CoversClass(PrivacyChecks::class)]
final class CheckCommandQueryBudgetTest extends PerformanceContractTestCase
{
    use MakesSubjectKeys, SealsEntries;

    /** @var int Most statements a run makes on any engine, as counted on SQLite. */
    private const int MAX_STATEMENTS = 60;

    /** @var string The data key of every key a test stores by hand: thirty-two bytes. */
    private const string DATA_KEY = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';

    /** @var string The table the installation id is kept in. */
    private const string STATE = 'audit_log_integrity_state';

    /** @var int How many times a sync run's statements an outbox run may make. */
    private const int OUTBOX_FACTOR = 2;

    /**
     * Register the command directly, keeping the test independent of the
     * provider.
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

        // The package's default bindings, in case the provider has not bound
        // them yet
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bindIf(KeyWrapper::class, LocalKeyWrapper::class);
    }

    /**
     * A passing run reads within the bound and writes nothing, on every engine.
     *
     * @return void
     */
    public function testTheCheckWritesNothing(): void
    {
        $before     = DB::table(self::STATE)->get()->all();
        $code       = $this->capture(fn (): int => $this->check());
        $statements = implode(' | ', $this->capturedStatements());

        self::assertSame(0, $code);
        self::assertNotSame([], $this->capturedStatements());
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()), "Statements: {$statements}");
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
        self::assertSame([InstallationIdentity::NAME], array_column($before, 'name'));
        self::assertEquals($before, DB::table(self::STATE)->get()->all());
    }

    /**
     * A run that finds no installation id fails and still writes nothing.
     *
     * @return void
     */
    public function testTheCheckWritesNothingWhenTheInstallationIdIsMissing(): void
    {
        DB::table(self::STATE)->delete();

        $code       = $this->capture(fn (): int => $this->check());
        $statements = implode(' | ', $this->capturedStatements());

        self::assertSame(1, $code);
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()), "Statements: {$statements}");
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
        self::assertSame(0, DB::table(self::STATE)->count());
    }

    /**
     * A run reads no more with 200 sealed entries than with none.
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
     * The lifecycle statements are fixed whatever the journal holds: it is read
     * a page of rows at a time.
     *
     * @return void
     */
    public function testTheLifecycleStatementsAreFixedWhateverTheJournalHolds(): void
    {
        $lifecycle = app(LifecycleChecks::class);
        $authority = new Authority(Reference::of('App\Models\User', '7'), 'case.review');

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000a1', HoldScope::all(), $authority, HoldBasis::LEGAL_CLAIM, null);

        self::assertSame([], $this->capture(static fn (): array => [...$lifecycle->problems(), ...$lifecycle->notes()]));

        $few = $this->capturedStatements();

        foreach (range(1, 300) as $run) {
            $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => sprintf('01932b4e-a000-7000-8000-%012d', $run), 'phase' => 'start']);
        }

        self::assertSame(301, DB::table('audit_log_lifecycle')->count());
        self::assertSame([], $this->capture(static fn (): array => [...$lifecycle->problems(), ...$lifecycle->notes()]));
        self::assertSame($few, $this->capturedStatements());
        self::assertSame([], $this->capturedWrites());
    }

    /**
     * The privacy statements read the key store a page at a time and write
     * nothing.
     *
     * @return void
     */
    public function testThePrivacyStatementsReadTheKeyStoreInPages(): void
    {
        $privacy = app(PrivacyChecks::class);

        $this->makeSubjectKey(Reference::of('App\Models\User', '0'));
        $this->eraseByHand(Reference::of('App\Models\User', '0'));
        $this->storeKeys(1, 1);

        self::assertSame([], $this->capture(static fn (): array => [...$privacy->problems(), ...$privacy->notes()]));

        $one = $this->capturedStatements();

        $this->storeKeys(2, 298);

        self::assertSame(300, DB::table(KeyTables::subjectKeysTable())->count());
        self::assertSame([], $this->capture(static fn (): array => [...$privacy->problems(), ...$privacy->notes()]));
        self::assertSame($one, $this->capturedStatements());

        $this->storeKeys(300, KeyStoreVerifier::PAGE + 1 - 300);

        self::assertSame(KeyStoreVerifier::PAGE + 1, DB::table(KeyTables::subjectKeysTable())->count());
        self::assertSame([], $this->capture(static fn (): array => [...$privacy->problems(), ...$privacy->notes()]));
        self::assertCount(count($one) + 1, $this->capturedStatements());
        self::assertSame([], $this->capturedWrites());
    }

    /**
     * The integrity checks write nothing and leave every integrity row as it
     * was.
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
     * A sync run reads no more than its engine, schema, integrity, lifecycle
     * and privacy checks do alone, so the delivery checks add no statement.
     *
     * @return void
     */
    public function testASyncRunReadsNoMoreThanItDid(): void
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        $integrity = app(IntegrityChecks::class);
        $lifecycle = app(LifecycleChecks::class);
        $privacy   = app(PrivacyChecks::class);

        $this->capture(static function () use ($database, $integrity, $lifecycle, $privacy): void {
            (new EngineChecks($database))->problems(self::CONNECTION, 'audit_log_entries');
            (new SchemaChecks($database))->problems(self::CONNECTION, 'audit_log_entries');
            (new SchemaChecks($database))->problems(self::CONNECTION, 'audit_log_artifacts', TableShape::artifacts());
            $integrity->problems();
            $lifecycle->problems();
            $privacy->problems();
            $lifecycle->notes();
            $privacy->notes();
        });

        $baseline = $this->capturedStatements();

        self::assertSame(0, $this->capture(fn (): int => $this->check()));
        self::assertSame($baseline, $this->capturedStatements());
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()));
    }

    /**
     * An outbox run reads at most twice what a sync run does.
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
     * An outbox run writes nothing, whatever the outbox and deliveries tables
     * hold.
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
     * Store live keys of consecutive owners from the first given, fifty rows to
     * a statement.
     *
     * @param  int  $first
     * @param  int  $count
     * @return void
     */
    private function storeKeys(int $first, int $count): void
    {
        $rows = [];

        foreach (range($first, $first + $count - 1) as $owner) {
            $rows[] = $this->signedSubjectKey(new KeyUnit(Reference::of('App\Models\User', (string) $owner), null, self::KEY_CATEGORY), 1, self::DATA_KEY)->toRow();
        }

        foreach (array_chunk($rows, 50) as $chunk) {
            DB::table(KeyTables::subjectKeysTable())->insert($chunk);
        }
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
     * An entries row with every required column, numbered so each id is unique.
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
