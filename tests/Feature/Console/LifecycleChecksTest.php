<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\LifecycleChecks;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for the lifecycle checks of `audit-log:check`: a reader for
 * every lifecycle, retention and import setting; the four tables' shapes, the
 * lock's row, the bound policy's version, the installation's identity through
 * both connections, the journal's verification and the projection's drift as
 * problems, each named and never a value; holds past their review date and
 * import batches that stopped moving as notes, bounded and never a problem; and
 * nothing written, not even an installation id that is missing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleChecks::class)]
final class LifecycleChecksTest extends TestCase
{
    use WritesTheJournal;

    /** @var string When the checks run, unless a test moves the clock. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string The operation every hold a test places is placed under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string A connection to another installation's state table. */
    private const string OTHER = 'audit_other';

    /** @var string A second connection to the worker's database. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string What a missing table is asked to be created by, after its name and connection. */
    private const string PUBLISH = '; publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

    /** @var string The note on one hold past its review date, after its id. */
    private const string REVIEW_NOTE = '; review each, and release it once nothing obliges keeping it.';

    /** @var string The note on import batches that stopped moving, after their ids. */
    private const string STALE_NOTE = '; close an interrupted one with `audit-log:import --close=<batch>`.';

    /**
     * Freeze the clock, and bind the policy the package binds by default,
     * whether or not the provider has bound it yet.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * Put the clock back, drop the other installation's state table and forget
     * the connections a test configured.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (app(ConfigRepository::class)->has('database.connections.' . self::OTHER)) {
            DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable());
        }

        DB::purge(self::OTHER);
        DB::purge(self::MAINTENANCE);

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of `[the leaf under audit-log, a value it refuses]`: every
     * lifecycle, retention and import setting the readers read.
     *
     * @return iterable<string, array{0: string, 1: array<string, int>|int|string}>
     */
    public static function provideLeaves(): iterable
    {
        yield from [
            'the journal table'          => ['lifecycle.journal_table', 'Journal'],
            'the holds table'            => ['lifecycle.holds_table', 'audit-holds'],
            'the lock table'             => ['lifecycle.lock_table', '1lock'],
            'the import batches table'   => ['import.batches_table', 'Batches'],
            'the default retention'      => ['retention.after_days', 36501],
            'the retention by category'  => ['retention.categories', 'security'],
            'the preservation'           => ['retention.preserve', ['security' => -1]],
            'the prune batch'            => ['retention.batch', 99],
            'the prune time budget'      => ['retention.max_seconds', 86401],
            'the prune schedule'         => ['retention.schedule', 'nightly'],
            'the import chunk'           => ['import.chunk', 5001],
            'the import skew'            => ['import.max_skew_seconds', -1],
            'the longest import line'    => ['import.max_line_bytes', 16777217],
            'a retention under its hold' => ['retention.categories', ['security' => 30]],
        ];
    }

    /**
     * Each lifecycle, retention and import setting is read by a reader that
     * refuses it, naming it, when it is malformed, a retention shorter than its
     * preservation among them; with the shipped defaults no reader refuses
     * anything.
     *
     * @param  string  $leaf
     * @param  array<string, int>|int|string  $bad
     * @return void
     */
    #[DataProvider('provideLeaves')]
    public function testEveryLifecycleReaderIsListed(string $leaf, array|int|string $bad): void
    {
        $config  = app(ConfigRepository::class);
        $readers = LifecycleChecks::readers($config);

        self::assertCount(14, $readers);
        self::assertSame([], self::refusalsOf($readers));

        $config->set('audit-log.retention.preserve', ['security' => 60]);
        $config->set("audit-log.{$leaf}", $bad);

        $refusals = self::refusalsOf(LifecycleChecks::readers($config));

        self::assertNotSame([], $refusals);
        self::assertStringContainsString("`audit-log.{$leaf}", $refusals[0]);
    }

    /**
     * An install the shipped migrations created, with a hold placed and its
     * projection in step, has no problem and no note.
     *
     * @return void
     */
    public function testAHealthyInstallHasNoProblem(): void
    {
        $this->placeHold();

        self::assertSame([], $this->checks()->problems());
        self::assertSame([], $this->checks()->notes());
    }

    /**
     * Rows of `[the table's setting, the absent table it names, its label]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMissingTables(): iterable
    {
        yield from [
            'the journal'        => ['lifecycle.journal_table', 'audit_absent_journal', 'lifecycle journal'],
            'the holds'          => ['lifecycle.holds_table', 'audit_absent_holds', 'holds'],
            'the lock'           => ['lifecycle.lock_table', 'audit_absent_lock', 'lifecycle lock'],
            'the import batches' => ['import.batches_table', 'audit_absent_batches', 'import batches'],
        ];
    }

    /**
     * Each lifecycle table that does not exist is a problem named by its label,
     * and nothing that reads the tables is checked while one is missing:
     * neither the lock's row, the installation, nor the journal.
     *
     * @param  string  $setting
     * @param  string  $table
     * @param  string  $label
     * @return void
     */
    #[DataProvider('provideMissingTables')]
    public function testEachTableShapeProblemIsReported(string $setting, string $table, string $label): void
    {
        $state = DB::table(IntegrityTables::stateTable())->get()->all();

        app(ConfigRepository::class)->set("audit-log.{$setting}", $table);

        self::assertSame(["The {$label} table `{$table}` does not exist on connection [" . self::CONNECTION . ']' . self::PUBLISH], $this->checks()->problems());
        self::assertEquals($state, DB::table(IntegrityTables::stateTable())->get()->all());
    }

    /**
     * A table of the wrong shape is a problem too: a column the package does
     * not write on the holds table, and a missing index on the journal.
     *
     * @return void
     */
    public function testATableOfTheWrongShapeIsAProblem(): void
    {
        Schema::table('audit_log_holds', static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        Schema::table('audit_log_lifecycle', static function (Blueprint $table): void {
            $table->dropIndex('audit_log_lifecycle_hold_index');
        });

        self::assertSame([
            'Index `audit_log_lifecycle_hold_index` is missing.',
            'Column `notes` is not one the package writes.',
        ], $this->checks()->problems());
    }

    /**
     * A lock table without its one row is a problem, since no lifecycle
     * operation could lock it.
     *
     * @return void
     */
    public function testAMissingLockRowIsAProblem(): void
    {
        DB::table('audit_log_lifecycle_lock')->delete();

        self::assertSame(['The lifecycle lock row is missing; run the migrations, which seed it.'], $this->checks()->problems());
    }

    /**
     * Rows of `[the version a policy gives]`: empty, longer than 64 characters,
     * and holding a control character.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidVersions(): iterable
    {
        yield from [
            'empty'               => [''],
            '65 characters'       => [str_repeat('v', 65)],
            'a control character' => ["v1\e[31m"],
        ];
    }

    /**
     * A bound policy whose version is not 1 to 64 characters of clean text is a
     * problem naming the policy's class and what the version must be, never the
     * version.
     *
     * @param  string  $version
     * @return void
     */
    #[DataProvider('provideInvalidVersions')]
    public function testAnInvalidPolicyVersionIsAProblem(string $version): void
    {
        $policy = self::policy(static fn (): string => $version);

        app()->instance(RetentionPolicy::class, $policy);

        $message = 'The retention policy `%s` answered `version()` with something other than 1 to 64 characters of clean text; pruning refuses it.';

        self::assertSame([sprintf($message, $policy::class)], $this->checks()->problems());
    }

    /**
     * A policy that cannot be resolved, and one whose version throws, are each
     * a problem named by the class of what was thrown, never its message; a
     * version of 64 characters is no problem.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAPolicyThatCannotBeReadIsNamedByItsFailure(): void
    {
        app()->instance(RetentionPolicy::class, self::policy(static fn (): string => str_repeat('v', 64)));

        self::assertSame([], $this->checks()->problems());

        $failure = new \RuntimeException('secret-detail');

        app()->instance(RetentionPolicy::class, self::policy(static fn (): string => throw $failure));

        self::assertSame(['The bound retention policy\'s version could not be read (RuntimeException).'], $this->checks()->problems());

        $unresolvable = new BindingResolutionException('secret-detail');

        app()->offsetUnset(RetentionPolicy::class);
        app()->bind(RetentionPolicy::class, static fn (): RetentionPolicy => throw $unresolvable);

        self::assertSame(['The bound retention policy could not be read (Illuminate\Contracts\Container\BindingResolutionException).'], $this->checks()->problems());
    }

    /**
     * While the retention settings are malformed, which `config` reports, the
     * policy the package binds is not asked, so no lifecycle problem repeats
     * them.
     *
     * @return void
     */
    public function testMalformedRetentionSettingsLeaveThePolicyUnasked(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 'forever');

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A maintenance connection that reaches another installation is a problem,
     * and so is one that reaches no installation id at all.
     *
     * @return void
     */
    public function testAMismatchedInstallationIsAProblem(): void
    {
        $this->otherDatabase('01932b4e-9000-7000-8000-00000000abcd');

        self::assertSame(['The storage and maintenance connections reach different installations.'], $this->checks()->problems());

        DB::connection(self::OTHER)->table(IntegrityTables::stateTable())->delete();

        self::assertSame(['The maintenance connection reaches no installation id; it must reach the storage connection\'s database.'], $this->checks()->problems());
    }

    /**
     * A maintenance connection of its own that reaches the storage connection's
     * database reads the same installation id, so it is no problem.
     *
     * @return void
     */
    public function testAMaintenanceConnectionToTheSameDatabaseIsNoProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MAINTENANCE, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        // On SQLite a second in-memory connection is another database, so it
        // shares the worker's
        if (DB::connection(self::CONNECTION)->getDriverName() === 'sqlite') {
            DB::connection(self::MAINTENANCE)->setPdo(DB::connection(self::CONNECTION)->getPdo());
        }

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A maintenance connection that is not configured, or uses another driver,
     * is left to the `connections` subject, which reports it, so the
     * installation is not read through it.
     *
     * @return void
     */
    public function testAMaintenanceConnectionTheConnectionsSubjectReportsIsLeftToIt(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.storage.maintenance_connection', 'missing');

        self::assertSame([], $this->checks()->problems());

        $config->set('database.connections.elsewhere', ['driver' => 'other']);
        $config->set('audit-log.storage.maintenance_connection', 'elsewhere');

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A stored installation id that is malformed is the package's own refusal,
     * which names no id.
     *
     * @return void
     */
    public function testAMalformedInstallationIdIsAProblem(): void
    {
        DB::table(IntegrityTables::stateTable())->where('name', InstallationIdentity::NAME)->update(['value' => '{"id":"not-a-uuid"}']);

        self::assertSame(['The installation id the storage connection reads is malformed; it is never replaced, so it must be restored.'], $this->checks()->problems());
    }

    /**
     * Rows of `[what is done to the journal, giving the row the finding is
     * found at, the finding]`.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Feature\Console\LifecycleChecksTest): string, 1: string}>
     */
    public static function provideBrokenJournals(): iterable
    {
        yield from [
            'an edited reason' => [
                static function (self $test): string {
                    $row = $test->journalRow(JournalKind::RELEASE, ['hold_id' => '01932b4e-d000-7000-8000-000000000001'], '01932b4e-d000-7000-8000-000000000001');

                    $test->tamperJournal(1, ['reason' => 'case.closed']);

                    return $row->id;
                },
                'journal_signature',
            ],
            'a missing row' => [
                static function (self $test): string {
                    $test->journalRow(JournalKind::PRUNE_RUN, ['run_id' => '01932b4e-a000-7000-8000-000000000001', 'phase' => 'start']);

                    $row = $test->journalRow(JournalKind::PRUNE_RUN, ['run_id' => '01932b4e-a000-7000-8000-000000000002', 'phase' => 'start']);

                    $test->tamperJournal(1, ['sequence' => 7]);

                    return $row->id;
                },
                'journal_gap',
            ],
        ];
    }

    /**
     * A journal that fails verification is a problem naming the finding and the
     * row it was found at.
     *
     * @param  \Closure(self): string  $break
     * @param  string  $finding
     * @return void
     */
    #[DataProvider('provideBrokenJournals')]
    public function testABrokenJournalIsAProblem(\Closure $break, string $finding): void
    {
        $rowId = $break($this);

        self::assertSame(
            ["The lifecycle journal fails verification (`{$finding}`) at `{$rowId}`; run `audit-log:verify`, and nothing destructive runs until it is investigated."],
            $this->checks()->problems(),
        );
    }

    /**
     * A journal is verified read-only and outside any lock: the lock's row is
     * left as it was.
     *
     * @return void
     */
    public function testTheJournalIsVerifiedWithoutTheLock(): void
    {
        $this->placeHold();

        $before = (array) DB::table('audit_log_lifecycle_lock')->first();

        self::assertSame([], $this->checks()->problems());
        self::assertEquals($before, (array) DB::table('audit_log_lifecycle_lock')->first());
    }

    /**
     * A projection that drifted from the verified journal is a problem naming
     * each hold that drifted: a hold the projection lost, and a row of no hold.
     *
     * @return void
     */
    public function testProjectionDriftIsAProblemNamingTheHolds(): void
    {
        $kept = $this->placeHold();
        $lost = $this->placeHold('01932b4e-9000-7000-8000-0000000000a2');

        DB::table('audit_log_holds')->where('hold_id', $lost->id)->delete();
        DB::table('audit_log_holds')->insert([...(array) DB::table('audit_log_holds')->where('hold_id', $kept->id)->first(), 'hold_id' => '01932b4e-d000-7000-8000-0000000000ff']);

        $drifted = [$lost->id, '01932b4e-d000-7000-8000-0000000000ff'];

        sort($drifted, SORT_STRING);

        self::assertSame(
            [sprintf('The holds projection differs from the journal for `%s`, `%s`; rebuild it with `audit-log:holds --rebuild`.', ...$drifted)],
            $this->checks()->problems(),
        );
    }

    /**
     * A drifted row whose hold id is not a lower-case UUID is counted, never
     * printed, so no byte a table holds reaches a console.
     *
     * @return void
     */
    public function testAHostileDriftedIdIsCountedNotPrinted(): void
    {
        if (DB::connection(self::CONNECTION)->getDriverName() === 'pgsql') {
            self::markTestSkipped('A PostgreSQL uuid column holds nothing but a UUID, which reads back in lower case.');
        }

        $hold = $this->placeHold();

        DB::table('audit_log_holds')->where('hold_id', $hold->id)->update(['basis' => 'other']);
        DB::table('audit_log_holds')->insert([...(array) DB::table('audit_log_holds')->where('hold_id', $hold->id)->first(), 'hold_id' => "\e[31mx"]);

        self::assertSame(
            ["The holds projection differs from the journal for `{$hold->id}` and 1 more; rebuild it with `audit-log:holds --rebuild`."],
            $this->checks()->problems(),
        );
    }

    /**
     * A hold past its review date is a note, not a problem: it names the hold,
     * and a hold due later, or of no review date, is left out.
     *
     * @return void
     */
    public function testAPassedReviewDateIsANoteNotAProblem(): void
    {
        $passed = $this->placeHold(reviewBy: new CarbonImmutable('2026-11-03 00:00:00', 'UTC'));

        $this->placeHold('01932b4e-9000-7000-8000-0000000000a2', new CarbonImmutable('2026-12-01 00:00:00', 'UTC'));
        $this->placeHold('01932b4e-9000-7000-8000-0000000000a3');

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 00:00:00', 'UTC'));

        self::assertSame([], $this->checks()->problems());
        self::assertSame(["1 hold is past its review date: `{$passed->id}`" . self::REVIEW_NOTE], $this->checks()->notes());
    }

    /**
     * A note lists at most 100 ids, oldest review date first, and counts the
     * rest.
     *
     * @return void
     */
    public function testANoteListsAtMostAHundredIds(): void
    {
        $hold = $this->placeHold(reviewBy: new CarbonImmutable('2026-11-01 00:00:00', 'UTC'));
        $row  = (array) DB::table('audit_log_holds')->where('hold_id', $hold->id)->first();

        DB::table('audit_log_holds')->delete();

        $ids = array_map(static fn (int $number): string => sprintf('01932b4e-d000-7000-8000-%012d', $number), range(1, 102));

        DB::table('audit_log_holds')->insert(array_map(static fn (string $id): array => [...$row, 'hold_id' => $id], $ids));

        $listed = implode(', ', array_map(static fn (string $id): string => "`{$id}`", array_slice($ids, 0, 100)));

        self::assertSame(["102 holds are past their review date: {$listed} and 2 more" . self::REVIEW_NOTE], $this->checks()->notes());
    }

    /**
     * An import batch still running that has not moved for over an hour is a
     * note naming it; one that moved within the hour, and one that finished,
     * are left out.
     *
     * @return void
     */
    public function testAStaleRunningImportIsANote(): void
    {
        DB::table('audit_log_import_batches')->insert([
            self::batchRow('01932b4e-b000-7000-8000-000000000001', 'running', '2026-11-02 07:59:59.000000'),
            self::batchRow('01932b4e-b000-7000-8000-000000000002', 'running', '2026-11-02 08:30:00.000000'),
            self::batchRow('01932b4e-b000-7000-8000-000000000003', 'complete', '2026-11-01 00:00:00.000000'),
            self::batchRow('01932b4e-b000-7000-8000-000000000004', 'running', '2026-11-02 07:00:00.000000'),
        ]);

        self::assertSame([], $this->checks()->problems());
        self::assertSame(
            [
                '2 import batches are running with nothing written for over an hour: `01932b4e-b000-7000-8000-000000000004`,'
                    . ' `01932b4e-b000-7000-8000-000000000001`' . self::STALE_NOTE,
            ],
            $this->checks()->notes(),
        );
    }

    /**
     * A batch that last moved exactly an hour ago is not yet stale.
     *
     * @return void
     */
    public function testABatchThatMovedAnHourAgoIsNotYetStale(): void
    {
        DB::table('audit_log_import_batches')->insert(self::batchRow('01932b4e-b000-7000-8000-000000000001', 'running', '2026-11-02 08:00:00.123456'));

        self::assertSame([], $this->checks()->notes());
    }

    /**
     * Notes that cannot be read are left out, since the problems name what is
     * wrong: here the holds table is missing.
     *
     * @return void
     */
    public function testANoteThatCannotBeReadIsLeftOut(): void
    {
        app(ConfigRepository::class)->set('audit-log.lifecycle.holds_table', 'audit_absent_holds');

        self::assertSame([], $this->checks()->notes());

        app(ConfigRepository::class)->set('audit-log.lifecycle.holds_table', 'audit-holds');

        self::assertSame([], $this->checks()->notes());
    }

    /**
     * A storage connection that cannot be opened is left to the `schema`
     * subject, which reports it, so the lifecycle checks report nothing.
     *
     * @return void
     */
    public function testAStorageConnectionThatCannotBeOpenedIsLeftToTheSchema(): void
    {
        $config = app(ConfigRepository::class);

        $absent = sys_get_temp_dir() . '/audit-log-absent-' . getmypid() . '/none.sqlite';

        $config->set('database.connections.unreachable', ['driver' => 'sqlite', 'database' => $absent, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'unreachable');

        self::assertSame([], $this->checks()->problems());
        self::assertSame([], $this->checks()->notes());
    }

    /**
     * A missing installation id is a problem, which the checks report rather
     * than write: the state table is left as it was, and a second run reports
     * it again.
     *
     * @return void
     */
    public function testAMissingInstallationIdIsAProblemAndIsNeverWritten(): void
    {
        DB::table(IntegrityTables::stateTable())->delete();

        $problem = 'The storage connection reaches no installation id; the package\'s migrations seed it, and `audit-log:seal` writes it when it is missing.';

        self::assertSame([$problem], $this->checks()->problems());
        self::assertSame([$problem], $this->checks()->problems());
        self::assertSame(0, DB::table(IntegrityTables::stateTable())->count());
    }

    /**
     * The checks leave the installation id the migrations seed as it is, run
     * after run.
     *
     * @return void
     */
    public function testTheSeededInstallationIdIsOnlyRead(): void
    {
        $seeded = DB::table(IntegrityTables::stateTable())->get()->all();

        self::assertSame([], $this->checks()->problems());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-03 09:00:00', 'UTC'));

        self::assertSame([], $this->checks()->problems());
        self::assertCount(1, $seeded);
        self::assertSame(InstallationIdentity::NAME, $seeded[0]->name);
        self::assertEquals($seeded, DB::table(IntegrityTables::stateTable())->get()->all());
    }

    /**
     * The checks resolved from the container.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\LifecycleChecks
     */
    private function checks(): LifecycleChecks
    {
        return app(LifecycleChecks::class);
    }

    /**
     * Place a hold of everything under the operation given, by an operator, on
     * a legal claim, with the review date given or none.
     *
     * @param  string  $operation
     * @param  ?\DateTimeInterface  $reviewBy
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private function placeHold(string $operation = self::OPERATION, ?\DateTimeInterface $reviewBy = null): Hold
    {
        return app(HoldKeeper::class)->place($operation, HoldScope::all(), new Authority(Reference::of('App\Models\User', '7'), 'case.review'), HoldBasis::LEGAL_CLAIM, $reviewBy);
    }

    /**
     * Configure `OTHER`, a connection to another installation's state table,
     * holding the installation id given, as the maintenance connection.
     *
     * @param  string  $id
     * @return void
     */
    private function otherDatabase(string $id): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);
        $config->set('audit-log.storage.maintenance_connection', self::OTHER);

        $connection = DB::connection(self::OTHER);
        $schema     = $connection->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        $connection->table(IntegrityTables::stateTable())->insert([
            'name'       => InstallationIdentity::NAME,
            'value'      => json_encode(['id' => $id]),
            'updated_at' => '2026-10-01 00:00:00.000000',
        ]);
    }

    /**
     * The messages of the readers that refuse what they read, in order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<\Closure(): mixed>  $readers
     * @return list<string>
     */
    private static function refusalsOf(array $readers): array
    {
        $refusals = [];

        foreach ($readers as $reader) {
            try {
                $reader();
            } catch (\InvalidArgumentException $exception) {
                $refusals[] = $exception->getMessage();
            }
        }

        return $refusals;
    }

    /**
     * A policy that keeps everything forever, whose version is what the closure
     * gives.
     *
     * @param  \Closure(): string  $version
     * @return \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy
     */
    private static function policy(\Closure $version): RetentionPolicy
    {
        return new readonly class ($version) implements RetentionPolicy {
            /**
             * Constructor.
             *
             * @param  \Closure(): string  $version
             */
            public function __construct(

                /** What gives the version. */
                private \Closure $version,
            ) {}

            /**
             * The version the closure gives.
             *
             * @return string
             */
            #[\Override]
            public function version(): string
            {
                return ($this->version)();
            }

            /**
             * Forever, whatever the category.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return ?int
             */
            #[\Override]
            public function retainFor(string $category, ?Reference $tenant): ?int
            {
                return null;
            }

            /**
             * Nothing obliges keeping anything.
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
        };
    }

    /**
     * An import batch row of the status given, last written at the stored time
     * given.
     *
     * @param  string  $id
     * @param  string  $status
     * @param  string  $updatedAt
     * @return array<string, bool|int|string|null>
     */
    private static function batchRow(string $id, string $status, string $updatedAt): array
    {
        return [
            'id'                  => $id,
            'source_id'           => 'legacy',
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('a', 64),
            'externally_verified' => false,
            'hold_id'             => null,
            'status'              => $status,
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'conflict_ids'        => null,
            'started_at'          => $updatedAt,
            'updated_at'          => $updatedAt,
            'finished_at'         => $status === 'running' ? null : $updatedAt,
        ];
    }
}
