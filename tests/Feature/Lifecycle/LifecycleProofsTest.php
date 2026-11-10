<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests that prove the lifecycle end to end through
 * `AuditLog::lifecycle()` and the commands alone, as the package ships them
 * bound and registered: everything is kept forever by default and no prune is
 * scheduled; an invalid setting prunes nothing and `audit-log:check` names it;
 * two categories are pruned each by its own retention and the policy's version
 * is journalled once per change; the cut-off falls at the run's UTC midnight;
 * held and unsealed entries survive a prune that verification passes; the
 * holds projection rebuilt is the one the operations kept; no entry is ever
 * updated; overlapping holds each keep what they cover until both are
 * released; an edited journal row is found by `audit-log:verify`; an export
 * still verifies once every other entry is pruned; and a record that could not
 * be written is written by `audit-log:reconcile`.
 *
 * Entries are stored through the database store, as the application's records
 * are, at the times each test chooses; everything after that goes through the
 * facade or a command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
#[CoversClass(AuditLifecycle::class)]
final class LifecycleProofsTest extends TestCase
{
    use ReadsTheTrail, WritesTheJournal;

    /** @var string When every run starts, unless a test moves the clock. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry is recorded, unless a test gives another time. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string When an entry within thirty days happened. */
    private const string RECENT = '2026-12-10T10:00:00.000000Z';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var array<string, string> The operator every command acts as. */
    private const array OPERATOR = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.review'];

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What every failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, name this installation's source and report to a
     * recording handler. Nothing is bound or registered by hand: the provider's
     * defaults and commands are what each test uses.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Roll back any transaction a test left open, put the clock back and remove
     * the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

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
     * With the shipped settings everything is kept forever: a prune of entries
     * long past any retention completes and deletes nothing, and the schedule
     * holds no prune at all.
     *
     * @return void
     */
    public function testForeverByDefaultPrunesNothingAndSchedulesNoPrune(): void
    {
        $ids = [$this->storeEntry('2016-01-01T00:00:00.000000Z'), $this->storeEntry(self::OLD)];

        $this->seal();

        $result = $this->jsonOf('audit-log:prune');

        self::assertSame(['complete', 0, 0], [$result['status'], $result['deleted'], $result['seals']]);
        self::assertSame($this->sorted($ids), $this->present($ids));

        $commands = array_map(static fn (ScheduledEvent $event): string => (string) $event->command, app(Schedule::class)->events());

        self::assertNotEmpty(array_filter($commands, static fn (string $command): bool => str_contains($command, 'audit-log:seal')));
        self::assertSame([], array_values(array_filter($commands, static fn (string $command): bool => str_contains($command, 'audit-log:prune'))));
    }

    /**
     * Rows of `[settings, the key the refusal names]`: a malformed retention,
     * and a category kept for less than it must be preserved.
     *
     * @return iterable<string, array{0: array<string, array<string, int>|int|string>, 1: string}>
     */
    public static function provideInvalidSettings(): iterable
    {
        $underPreservation = ['audit-log.retention.categories' => ['finance' => 30], 'audit-log.retention.preserve' => ['finance' => 365]];

        yield from [
            'a retention that is not a number' => [['audit-log.retention.after_days' => 'a year'], '`audit-log.retention.after_days`'],
            'a retention under preservation'   => [$underPreservation, '`audit-log.retention.categories.finance`'],
        ];
    }

    /**
     * An invalid retention setting prunes nothing: the run is refused before
     * any delete, exits non-zero and is recorded as a failure, and
     * `audit-log:check` names the setting and fails.
     *
     * @param  array<string, array<string, int>|int|string>  $settings
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideInvalidSettings')]
    public function testAnInvalidSettingPrunesNothingAndCheckReportsIt(array $settings, string $key): void
    {
        $ids = [$this->storeEntry(self::OLD), $this->storeEntry(self::OLD)];

        $this->seal();

        app(ConfigRepository::class)->set($settings);

        [$exit, $printed] = $this->command('audit-log:prune');

        self::assertSame(1, $exit);
        self::assertStringContainsString('failed (configuration_refused)', $printed);
        self::assertSame($this->sorted($ids), $this->present($ids));
        $records = $this->readRecords('audit_log.pruned');

        self::assertCount(1, $records);
        self::assertSame(['failure', 'configuration_refused'], [$records[0]['outcome'], $records[0]['reason']]);

        [$checked, $report] = $this->command('audit-log:check');

        self::assertNotSame(0, $checked);
        self::assertStringContainsString($key, $report);
    }

    /**
     * Two categories in one seal are pruned each by its own retention, a
     * category with none is kept forever, and the configured policy's version
     * is journalled once: a second run under the same settings adds no policy
     * row, and a change of the settings journals the new version.
     *
     * @return void
     */
    public function testTwoCategoriesArePrunedIndependentlyAndTheVersionIsJournalled(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', ['security' => 7, 'finance' => 30]);

        $securityOld   = $this->storeEntry('2026-12-01T10:00:00.000000Z', ['category' => 'security']);
        $securityFresh = $this->storeEntry(self::RECENT, ['category' => 'security']);
        $financeFresh  = $this->storeEntry('2026-12-01T10:00:00.000000Z');
        $financeOld    = $this->storeEntry(self::OLD);
        $general       = $this->storeEntry('2016-01-01T00:00:00.000000Z', ['category' => 'general']);

        $this->seal();

        $first   = $this->jsonOf('audit-log:prune');
        $version = app(RetentionPolicy::class)->version();

        self::assertSame(['complete', 2, ['finance' => 1, 'security' => 1]], [$first['status'], $first['deleted'], $first['categories']]);
        self::assertSame($version, $first['policy_version']);
        self::assertStringStartsWith('config:', $version);
        self::assertSame($this->sorted([$securityFresh, $financeFresh, $general]), $this->present([$securityOld, $securityFresh, $financeFresh, $financeOld, $general]));
        self::assertSame([$version], $this->policyVersions());

        self::assertSame(0, $this->jsonOf('audit-log:prune')['deleted']);
        self::assertSame([$version], $this->policyVersions());

        app(ConfigRepository::class)->set('audit-log.retention.categories', ['security' => 1, 'finance' => 30]);

        $third = $this->jsonOf('audit-log:prune');

        self::assertSame([1, ['security' => 1]], [$third['deleted'], $third['categories']]);
        self::assertNotSame($version, $third['policy_version']);
        self::assertSame([$version, $third['policy_version']], $this->policyVersions());
    }

    /**
     * Under a frozen clock the cut-off is the run's UTC midnight less the
     * retention: an entry a microsecond before it is pruned and one at it is
     * kept, the same at the last microsecond of the day, and the next day's
     * first run takes it.
     *
     * @return void
     */
    public function testTheBoundaryDayUnderAFrozenClock(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $before = $this->storeEntry('2026-11-14T23:59:59.999999Z');
        $at     = $this->storeEntry('2026-11-15T00:00:00.000000Z');

        $this->seal();

        $plan = $this->jsonOf('audit-log:prune', ['--dry-run' => true]);

        self::assertSame(['2026-11-15T00:00:00.000000Z', 1], [$plan['plan']['pairs'][0]['cutoff'] ?? null, $plan['plan']['pairs'][0]['eligible'] ?? null]);
        self::assertSame(1, $this->jsonOf('audit-log:prune')['deleted']);
        self::assertSame([$at], $this->present([$before, $at]));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-12-15 23:59:59.999999', 'UTC'));

        self::assertSame(0, $this->jsonOf('audit-log:prune')['deleted']);

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-12-16 00:00:00', 'UTC'));

        self::assertSame(1, $this->jsonOf('audit-log:prune')['deleted']);
        self::assertSame([], $this->present([$before, $at]));
    }

    /**
     * A held entry and an unsealed one survive the prune that takes the entry
     * beside them, the run ends `partial`, and `audit-log:verify` then passes
     * with the seal `pruned`.
     *
     * @return void
     */
    public function testHeldAndUnsealedRowsSurviveAndVerifyPasses(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $held   = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $pruned = $this->storeEntry(self::OLD);

        $this->seal();

        $unsealed = $this->storeEntry(self::OLD, [], '2026-12-15 14:00:00');
        $holdId   = $this->placeHold(['--tenant' => ['organisation:org_held'], '--basis' => 'legal_claim']);
        $result   = $this->jsonOf('audit-log:prune');

        self::assertSame(['partial', 1, 1], [$result['status'], $result['deleted'], $result['held']]);
        self::assertSame($this->sorted([$held, $unsealed]), $this->present([$held, $pruned, $unsealed]));
        self::assertSame([$holdId], array_map(static fn (Hold $hold): string => $hold->id, AuditLog::lifecycle()->holds()));

        $verified = $this->verify();

        self::assertSame(0, $verified['exit']);
        self::assertSame(['pruned'], $verified['segments']);
        self::assertSame([], $verified['findings']);
    }

    /**
     * The holds projection rebuilt from the journal holds exactly the rows the
     * holds and releases kept as they went, and `audit-log:holds` lists the
     * same active holds.
     *
     * @return void
     */
    public function testTheProjectionRebuildEqualsTheLiveOne(): void
    {
        $lifecycle = AuditLog::lifecycle();
        $authority = new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');

        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'))->withTenantless();
        $first = $lifecycle->hold($scope, $authority, HoldBasis::LEGAL_CLAIM, new CarbonImmutable('2027-06-01', 'UTC'));

        $lifecycle->hold(HoldScope::all()->categories('security'), $authority, HoldBasis::REGULATORY);
        $this->placeHold(['--all' => true, '--about' => ['user:42'], '--from' => '2026-01-01', '--to' => '2026-07-01', '--basis' => 'investigation']);
        $this->command('audit-log:release', ['hold' => $first->hold->id, ...self::OPERATOR]);

        $live = $this->projection();

        self::assertCount(2, $live);

        self::assertSame(['rebuilt' => 2], $this->jsonOf('audit-log:holds', ['--rebuild' => true]));
        self::assertEquals($live, $this->projection());

        $listed = $this->jsonOf('audit-log:holds')['holds'] ?? null;

        self::assertIsArray($listed);
        self::assertSame(array_column($live, 'hold_id'), $this->sorted(array_column($listed, 'id')));
    }

    /**
     * No statement of a whole lifecycle, sealing, holds, a prune, a release, an
     * import, a reconciliation and a verification, ever updates an entry or a
     * journal row, or deletes a journal row, a seal or a member.
     *
     * @return void
     */
    public function testEntriesAreNeverUpdated(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $this->storeEntry(self::OLD);
        $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $this->seal();

        $holdId = $this->placeHold(['--tenant' => ['organisation:org_held'], '--basis' => 'other']);

        $this->jsonOf('audit-log:prune');
        $this->command('audit-log:release', ['hold' => $holdId, ...self::OPERATOR]);
        $this->jsonOf('audit-log:prune');
        $this->command('audit-log:import', ['file' => $this->importFile(), '--source' => 'crm-eu', ...self::OPERATOR]);
        $this->jsonOf('audit-log:reconcile');
        $this->seal();

        self::assertSame(0, $this->verify()['exit']);
        self::assertNotEmpty($statements);

        $forbidden = [
            'update ' . EntrySettings::table(),
            'update ' . LifecycleTables::journalTable(),
            'delete from ' . LifecycleTables::journalTable(),
            'delete from ' . IntegrityTables::checkpointsTable(),
            'delete from ' . IntegrityTables::membersTable(),
        ];

        foreach ($statements as $statement) {
            $unquoted = str_replace(['"', '`'], '', $statement);

            foreach ($forbidden as $prefix) {
                self::assertStringStartsNotWith($prefix . ' ', ltrim($unquoted), sprintf('A lifecycle statement begins `%s`.', $prefix));
            }
        }
    }

    /**
     * Two holds covering one entry each keep it: releasing one leaves it held
     * by the other while the entry only the released one held is pruned, and
     * releasing the second lets the next run take it.
     *
     * @return void
     */
    public function testOverlappingHoldsAndARelease(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $both   = $this->storeEntry(self::OLD, ['tenant_id' => 'org_a', 'category' => 'security']);
        $tenant = $this->storeEntry(self::OLD, ['tenant_id' => 'org_a']);

        $this->seal();

        $byTenant   = $this->placeHold(['--tenant' => ['organisation:org_a'], '--basis' => 'legal_claim']);
        $byCategory = $this->placeHold(['--all' => true, '--category' => ['security'], '--basis' => 'regulatory']);
        $first      = $this->jsonOf('audit-log:prune');

        self::assertSame(['partial', 0, 2], [$first['status'], $first['deleted'], $first['held']]);
        self::assertSame($this->sorted([$both, $tenant]), $this->present([$both, $tenant]));
        self::assertSame(0, $this->command('audit-log:release', ['hold' => $byTenant, ...self::OPERATOR])[0]);

        $second = $this->jsonOf('audit-log:prune');

        self::assertSame(['partial', 1, 1], [$second['status'], $second['deleted'], $second['held']]);
        self::assertSame([$both], $this->present([$both, $tenant]));
        self::assertSame(0, $this->command('audit-log:release', ['hold' => $byCategory, ...self::OPERATOR])[0]);
        self::assertSame(1, $this->command('audit-log:release', ['hold' => $byCategory, ...self::OPERATOR])[0]);

        $third = $this->jsonOf('audit-log:prune');

        self::assertSame(['complete', 1, 0], [$third['status'], $third['deleted'], $third['held']]);
        self::assertSame([], $this->present([$both, $tenant]));

        $released = $this->readRecords('audit_log.released');

        $denied = array_values(array_filter($released, static fn (array $record): bool => $record['outcome'] === 'denied'));

        // Recorded within one instant, their order is their ids', which each
        // record's code and operation derive
        self::assertEqualsCanonicalizing(['success', 'success', 'denied'], array_column($released, 'outcome'));
        self::assertSame('unknown_hold', $denied[0]['reason'] ?? null);
    }

    /**
     * A journal row edited in the database, below the package, is a
     * `journal_signature` finding of `audit-log:verify`, which fails, and every
     * lifecycle operation then refuses to build on the broken chain.
     *
     * @return void
     */
    public function testAJournalRowEditedIsFoundByVerify(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $id = $this->storeEntry(self::OLD);

        $this->placeHold(['--all' => true, '--basis' => 'legal_claim']);
        $this->seal();

        self::assertSame(0, $this->verify()['exit']);

        $this->tamperJournal(1, ['reason' => 'case.edited']);

        $verified = $this->verify();

        self::assertSame(1, $verified['exit']);
        self::assertArrayHasKey('journal_signature', $verified['findings']);

        $pruned = $this->jsonOf('audit-log:prune', [], 1);

        self::assertSame(['failed', 'journal_broken', 0], [$pruned['status'], $pruned['failure'], $pruned['deleted']]);
        self::assertSame([$id], $this->present([$id]));
        self::assertSame(1, $this->command('audit-log:hold', ['--all' => true, '--basis' => 'other', ...self::OPERATOR])[0]);
    }

    /**
     * An export's `audit_log.trail_exported` record is never pruned, so once
     * every other entry, the exported ones included, is past retention and
     * pruned, `audit-log:export --verify` still verifies the file, and
     * `audit-log:verify` passes.
     *
     * @return void
     */
    public function testAnExportStillVerifiesAfterEveryOtherRowIsPruned(): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        $this->allowEverything();

        $exported = [$this->storeEntry(self::OLD, [], '2026-11-01 11:00:00'), $this->storeEntry(self::OLD, [], '2026-11-01 11:00:00')];
        $file     = $this->exportFile();
        $viewer   = ['--viewer-type' => 'App\Models\User', '--viewer-id' => '7'];

        self::assertSame(0, $this->command('audit-log:export', ['file' => $file, ...$viewer])[0]);

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->seal();

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);

        $result = $this->jsonOf('audit-log:prune');
        $kept   = DB::connection(StorageConnection::name())->table(EntrySettings::table())->pluck('event')->all();

        self::assertGreaterThanOrEqual(2, $result['deleted']);
        self::assertSame([], $this->present($exported));
        self::assertContains('audit_log.trail_exported', $kept);
        self::assertSame(['audit_log.trail_exported'], array_values(array_unique(array_filter($kept, static fn (mixed $event): bool => $event !== 'audit_log.pruned'))));

        [$exit, $printed] = $this->command('audit-log:export', ['file' => $file, '--verify' => true, ...$viewer]);

        self::assertSame(0, $exit, $printed);

        $this->seal();

        self::assertSame(0, $this->verify()['exit']);
    }

    /**
     * A hold whose `audit_log.held` record could not be written stays placed,
     * the command warns, and `audit-log:reconcile` writes the record from the
     * journal, once.
     *
     * @return void
     */
    public function testAMissingRecordIsReconciled(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        [$exit, $printed] = $this->command('audit-log:hold', ['--all' => true, '--basis' => 'legal_claim', ...self::OPERATOR]);

        self::assertSame(0, $exit);
        self::assertStringContainsString('audit-log:reconcile writes it from the journal', $printed);
        self::assertSame([], $this->readRecords('audit_log.held'));
        self::assertCount(1, AuditLog::lifecycle()->holds());

        app(ConfigRepository::class)->set('audit-log.redaction.keys', []);

        self::assertSame(1, $this->jsonOf('audit-log:reconcile')['recorded']);

        $again = $this->jsonOf('audit-log:reconcile');

        self::assertSame([0, 1], [$again['recorded'], $again['already_recorded']]);

        $records = $this->readRecords('audit_log.held');

        self::assertCount(1, $records);
        self::assertSame(['App\Models\User', '7', 'success'], [$records[0]['actor_type'], $records[0]['actor_id'], $records[0]['outcome']]);
        self::assertSame((string) $this->journalRows()[0]['hold_id'], self::propertiesOf($records[0])['hold_id'] ?? null);
    }

    /**
     * Store a captured record with the fields given over its own, happening at
     * the instant given and recorded at the time given, and return its id.
     *
     * @param  string  $occurredAt
     * @param  array<string, ?string>  $fields
     * @param  string  $recordedAt
     * @return string
     */
    private function storeEntry(string $occurredAt, array $fields = [], string $recordedAt = self::RECORDED_AT): string
    {
        $record    = RecordFactory::withFields(['occurred_at' => $occurredAt, ...$fields]);
        $finalised = (new RecordFinaliser(FrozenClock::at($recordedAt), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * Seal every entry recorded so far through `audit-log:seal --sweep`.
     *
     * @return void
     */
    private function seal(): void
    {
        self::assertSame(0, $this->command('audit-log:seal', ['--sweep' => true])[0]);
    }

    /**
     * Place a hold through `audit-log:hold` with the options given, as the
     * operator, and return its id.
     *
     * @param  array<string, bool|list<string>|string>  $options
     * @return string
     */
    private function placeHold(array $options): string
    {
        [$exit, $printed] = $this->command('audit-log:hold', [...$options, ...self::OPERATOR]);

        self::assertSame(0, $exit, $printed);
        self::assertSame(1, preg_match('/Placed hold ([0-9a-f-]{36})\./', $printed, $matches));

        return $matches[1];
    }

    /**
     * Run `audit-log:verify --json` and return its exit code, the integrity of
     * each segment, in order, and the first id of each finding of the run, by
     * its finding.
     *
     * @return array{exit: int, segments: list<string>, findings: array<string, ?string>}
     *
     * @throws \JsonException
     */
    private function verify(): array
    {
        [$exit, $printed] = $this->command('audit-log:verify', ['--json' => true]);

        $segments = [];
        $findings = [];

        foreach (array_filter(explode("\n", $printed), static fn (string $line): bool => str_starts_with($line, '{')) as $line) {
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);

            if (($decoded['type'] ?? null) === 'segment' && is_string($decoded['integrity'] ?? null)) {
                $segments[] = $decoded['integrity'];
            }

            if (!(($decoded['type'] ?? null) === 'finding') || !(is_string($decoded['finding'] ?? null))) {
                continue;
            }

            $findings[$decoded['finding']] = is_string($decoded['first_bad_id'] ?? null) ? $decoded['first_bad_id'] : null;
        }

        return ['exit' => $exit, 'segments' => $segments, 'findings' => $findings];
    }

    /**
     * Run the command with `--json` and the parameters given, assert it exits
     * as expected, and return the object it wrote.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $command
     * @param  array<string, bool|string>  $parameters
     * @param  int  $expected
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     *
     * @phpstan-impure
     */
    private function jsonOf(string $command, array $parameters = [], int $expected = 0): array
    {
        [$exit, $printed] = $this->command($command, [...$parameters, '--json' => true]);

        self::assertSame($expected, $exit, $printed);

        $decoded = json_decode(trim($printed), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * Run the command with the parameters given and return its exit code and
     * what it printed.
     *
     * @param  string  $command
     * @param  array<string, bool|list<string>|string>  $parameters
     * @return array{0: int, 1: string}
     */
    private function command(string $command, array $parameters = []): array
    {
        $exit = Artisan::call($command, $parameters);

        return [$exit, Artisan::output()];
    }

    /**
     * The versions of the `policy` rows of the journal, in order.
     *
     * @return list<string>
     *
     * @throws \JsonException
     */
    private function policyVersions(): array
    {
        $versions = [];

        foreach ($this->journalRows() as $row) {
            if ($row['kind'] !== JournalKind::POLICY->value) {
                continue;
            }

            $payload = json_decode((string) $row['payload'], true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($payload);
            self::assertIsString($payload['version'] ?? null);

            $versions[] = $payload['version'];
        }

        return $versions;
    }

    /**
     * Every row of the holds projection, by hold id.
     *
     * @return list<array<string, scalar|null>>
     */
    private function projection(): array
    {
        /** @var list<array<string, scalar|null>> $rows */
        $rows = array_map(static fn (object $row): array => (array) $row, $this->storage()->table(LifecycleTables::holdsTable())->orderBy('hold_id')->get()->all());

        return $rows;
    }

    /**
     * The ids among those given whose entries are still stored, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        return $this->sorted(self::strings($this->storage()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all()));
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
     * A file of one line of the import format, and its path.
     *
     * @return string
     */
    private function importFile(): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'lifecycle-proofs-');

        file_put_contents($path, json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => 'rec-1',
            'occurred_at'      => '2026-12-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'category'         => 'finance',
        ]) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * Where an export is written: a path of its own, which the test removes
     * with the bundle beside it.
     *
     * @return string
     */
    private function exportFile(): string
    {
        $path = sys_get_temp_dir() . '/' . uniqid('lifecycle-proofs-export-', true) . '.ndjson';

        $this->files[] = $path;
        $this->files[] = $path . '.manifest.json';

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
