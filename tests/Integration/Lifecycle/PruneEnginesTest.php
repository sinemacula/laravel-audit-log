<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;
use SineMacula\Laravel\AuditLog\Lifecycle\SqliteDeleteTriggers;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for a real prune on every engine, under the documented
 * triggers and, on MySQL and PostgreSQL, the documented grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneChunk::class)]
#[CoversClass(SqliteDeleteTriggers::class)]
final class PruneEnginesTest extends TestCase
{
    use RunsDocumentedSql, SealsEntries;

    /** @var string When every run starts. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-12-02 13:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string When an entry within thirty days happened. */
    private const string RECENT = '2026-12-01T10:00:00.000000Z';

    /** @var string The connection the writer's login uses. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The verifier's placeholder, whose login the documented grants name. */
    private const string VERIFIER = 'audit_verifier';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /** @var bool Whether this test installed the documented triggers. */
    private bool $triggers = false;

    /**
     * Stop the clock, keep thirty days, and bind the policy and the ledger.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Drop the triggers and logins this test made, and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $root = DB::connection(self::CONNECTION);

        if ($this->triggers) {
            self::dropDocumentedTriggers($root);
        }

        foreach ($this->names === [] ? [] : [self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            DB::purge($placeholder);

            self::dropLogin($root, $this->names[$placeholder]);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The cut-off holds to the microsecond as each engine stores a time.
     *
     * @return void
     */
    public function testTheBoundaryOnEachEngine(): void
    {
        $before = $this->storeEntry('2026-11-14T23:59:59.999999Z');
        $at     = $this->storeEntry('2026-11-15T00:00:00.000000Z');
        $after  = $this->storeEntry('2026-11-15T00:00:00.000001Z');

        $this->sealAll();

        self::assertSame(1, $this->prune()->deleted);
        self::assertSame([$at, $after], $this->present([$before, $at, $after]));
    }

    /**
     * Two categories of one seal are each pruned by their own retention.
     *
     * @return void
     */
    public function testTwoCategoriesInOneSealOnEachEngine(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', ['security' => 1]);

        $security = $this->storeEntry(self::RECENT, ['category' => 'security']);
        $finance  = $this->storeEntry(self::RECENT);

        $this->sealAll();

        $result = $this->prune();

        self::assertSame([1, ['security' => 1]], [$result->deleted, $result->categories]);
        self::assertSame([$finance], $this->present([$security, $finance]));
        self::assertSame(['pruned'], $this->verify()[1]);
    }

    /**
     * Held, unsealed and protected entries survive a prune.
     *
     * @return void
     */
    public function testHeldUnsealedAndProtectedRowsSurvive(): void
    {
        $held      = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $protected = $this->storeEntry(self::OLD, ['event' => 'audit_log.trail_exported', 'category' => 'audit']);
        $pruned    = $this->storeEntry(self::OLD);

        $this->sealAll();

        $unsealed = $this->storeEntry(self::OLD);

        $scope     = HoldScope::tenants(Reference::of('organisation', 'org_held'));
        $authority = new Authority(Reference::of('App\Models\User', '7'), 'case.review');

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000a1', $scope, $authority, HoldBasis::LEGAL_CLAIM, null);

        $result = $this->prune();
        $kept   = [$held, $protected, $unsealed];

        sort($kept);

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$result->status, $result->deleted, $result->held]);
        self::assertSame($kept, $this->present([$held, $protected, $pruned, $unsealed]));
    }

    /**
     * Verification after a real prune passes.
     *
     * @return void
     */
    public function testVerifyAfterARealPrunePasses(): void
    {
        $this->storeEntry(self::OLD);
        $this->storeEntry(self::RECENT);
        $this->sealAll();
        $this->storeEntry(self::OLD);
        $this->sealAll();

        self::assertSame(2, $this->prune()->deleted);

        [$summary, $segments] = $this->verify();

        self::assertSame(['pruned', 'pruned'], $segments);
        self::assertFalse($summary->fails(false));
    }

    /**
     * On SQLite a prune drops and restores the documented delete triggers.
     *
     * @return void
     */
    public function testOnSqliteTheDocumentedTriggersAreDroppedAndRestored(): void
    {
        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite drops and recreates its delete triggers.');
        }

        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->sealAll();

        self::runDocumentedSql($root, 'sqlite-triggers', []);

        $this->triggers = true;

        self::assertSame(1, $this->prune()->deleted);
        self::assertSame([$kept], $this->present([$pruned, $kept]));

        $installed = $root->table('sqlite_master')->where('type', 'trigger')->whereIn('name', ['audit_log_entries_no_delete', 'audit_log_artifacts_no_delete'])->count();

        self::assertSame(2, $installed);

        self::assertRefusedByATrigger(static function () use ($root, $kept): void {
            $root->table(EntrySettings::table())->where('id', $kept)->delete();
        }, 'audit_log_entries', 'DELETE');
    }

    /**
     * The maintenance user prunes under the documented grants and triggers.
     *
     * @return void
     */
    public function testOnMySqlAndPostgresTheMaintenanceUserPrunesUnderTheTriggers(): void
    {
        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::createLogin($root, $this->names[$placeholder]);
        }

        self::runDocumentedGrants($root, $this->names);
        self::runDocumentedTriggers($root, $this->names);

        $this->triggers = true;

        self::connectAs(self::WRITER, self::CONNECTION, $this->names['audit_writer']);
        self::connectAs(self::MAINTENANCE, self::CONNECTION, $this->names['audit_maintenance']);

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::WRITER);
        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->sealAll();

        $result = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 1, null], [$result->status, $result->deleted, $result->failure]);
        self::assertSame([$kept], $this->present([$pruned, $kept]));
        self::assertSame(['pruned'], $this->verify()[1]);

        self::assertRefusedByATrigger(static function () use ($root, $kept): void {
            $root->table(EntrySettings::table())->where('id', $kept)->delete();
        }, 'audit_log_entries', 'DELETE');
    }

    /**
     * Run a prune.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     */
    private function prune(): PruneResult
    {
        return app(Pruner::class)->run();
    }

    /**
     * Verify the whole log through the journal's ledger.
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary, 1: list<string>}
     */
    private function verify(): array
    {
        /** @var \ArrayObject<int, string> $segments */
        $segments = new \ArrayObject;

        $summary = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($segments): void {
            $segments->append($report->integrity->value);
        });

        self::assertInstanceOf(VerificationSummary::class, $summary);

        return [$summary, array_values($segments->getArrayCopy())];
    }

    /**
     * Store a record with the fields given, occurring at the instant given.
     *
     * @param  string  $occurredAt
     * @param  array<string, ?string>  $fields
     * @return string
     */
    private function storeEntry(string $occurredAt, array $fields = []): string
    {
        $record    = RecordFactory::withFields(['occurred_at' => $occurredAt, ...$fields]);
        $finalised = (new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * The ids among those given whose entries are still stored, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        $present = self::strings($this->storage()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all());

        sort($present);

        return $present;
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
