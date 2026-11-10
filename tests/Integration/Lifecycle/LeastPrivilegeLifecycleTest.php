<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldResult;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for the lifecycle under the grants the storage note
 * documents, run exactly as written by the tables' owner, on MySQL and
 * PostgreSQL: the maintenance user, granted exactly its privileges, holds,
 * prunes and releases; the writer, granted exactly its own, imports, held, and
 * seals; the verifier verifies a pruned log reading the evidence alone; the
 * writer writes neither the journal nor the holds, and no lifecycle operation
 * runs on its credentials; the maintenance user never updates or deletes a
 * journal row; with the documented triggers installed every operation still
 * runs; and a projection row the owner deletes is refused by its trigger, while
 * one the maintenance user deletes changes nothing a hold decides.
 *
 * Each worker creates logins of its own, `audit_writer_<token>`,
 * `audit_maintenance_<token>` and `audit_verifier_<token>`, which the
 * documented grants and triggers name; the writer's login is the storage
 * connection and the maintenance user's the maintenance connection. Every
 * operation goes through `AuditLog::lifecycle()` or a command, on the
 * provider's default bindings. SQLite has no privileges, so these tests are
 * skipped there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
#[CoversClass(AuditLifecycle::class)]
final class LeastPrivilegeLifecycleTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses, which is the storage connection. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses, which is the maintenance connection. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The connection the verifier's login uses. */
    private const string VERIFIER = 'audit_verifier';

    /** @var string When every operation runs. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string When an entry within thirty days happened. */
    private const string RECENT = '2026-12-10T10:00:00.000000Z';

    /** @var string A journal row's or a hold's id no stored row has. */
    private const string FOREIGN_ID = '01932b4e-9000-7000-8000-00000000f0f9';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /** @var bool Whether this test installed the documented triggers. */
    private bool $triggers = false;

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Create this worker's logins, run the documented grants for them as the
     * tables' owner, make the writer's login the storage connection and the
     * maintenance user's the maintenance connection, keep every category thirty
     * days, freeze the clock and report to a recording handler, on MySQL and
     * PostgreSQL only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root = $this->root();

        if ($root->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::createLogin($root, $this->names[$placeholder]);
        }

        self::runDocumentedGrants($root, $this->names);

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::connectAs($placeholder, self::CONNECTION, $this->names[$placeholder]);
        }

        app(ConfigRepository::class)->set([
            'audit-log.storage.connection'             => self::WRITER,
            'audit-log.storage.maintenance_connection' => self::MAINTENANCE,
            'audit-log.source.id'                      => 'app-eu-1',
            'audit-log.retention.after_days'           => 30,
        ]);

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Drop the documented triggers when this test installed them, close the
     * logins' connections, drop the logins, put the clock back and remove the
     * files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->names !== []) {
            $this->dropLogins();
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
     * The maintenance user, granted exactly its documented privileges, places a
     * hold, prunes around it, releases it and prunes what it kept, rebuilds the
     * projection, and journals each step; every operation is recorded through
     * the writer, and the writer then verifies the pruned log.
     *
     * @return void
     */
    public function testAMaintenanceUserGrantedExactlyTheDocumentedPrivilegesPrunesHoldsAndReleases(): void
    {
        $held   = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->seal();

        $hold  = $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')));
        $first = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1, true], [$first->status, $first->deleted, $first->held, $first->recorded]);
        self::assertSame(self::sorted([$held, $kept]), $this->present([$held, $pruned, $kept]));

        $release = AuditLog::lifecycle()->release($hold->hold->id, self::authority());
        $second  = AuditLog::lifecycle()->prune();

        self::assertTrue($release->recorded);
        self::assertSame([PruneStatus::COMPLETE, 1, true], [$second->status, $second->deleted, $second->recorded]);
        self::assertSame([$kept], $this->present([$held, $pruned, $kept]));
        self::assertSame(0, AuditLog::lifecycle()->rebuildHolds());

        $kinds = array_unique(self::strings($this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->pluck('kind')->all()));

        foreach ([JournalKind::HOLD, JournalKind::POLICY, JournalKind::PRUNE_RUN, JournalKind::PRUNE, JournalKind::RELEASE] as $kind) {
            self::assertContains($kind->value, $kinds);
        }

        $codes = self::strings($this->root()->table(EntrySettings::table())->where('event', 'like', 'audit_log.%')->pluck('event')->all());

        self::assertSame(['audit_log.held', 'audit_log.pruned', 'audit_log.pruned', 'audit_log.released'], self::sorted($codes));
        self::assertSame([0, ['pruned']], $this->verify());
    }

    /**
     * The writer, granted exactly its documented privileges, imports a file
     * with a hold placed on its start, writing the batch and its entries while
     * the maintenance user journals the start, the hold and the finish; the
     * writer then seals the imported entries and verifies them.
     *
     * @return void
     */
    public function testAWriterGrantedExactlyTheDocumentedPrivilegesImportsAndSeals(): void
    {
        $result = AuditLog::lifecycle()->import(ImportSource::fromFile($this->importFile(['rec-1', 'rec-2']), 'crm-eu'), self::authority(), hold: true);

        self::assertSame([ImportStatus::COMPLETE, 2, true], [$result->status, $result->imported, $result->recorded]);
        self::assertInstanceOf(Hold::class, $result->hold);
        self::assertSame('complete', $this->root()->table(LifecycleTables::importBatchesTable())->where('id', $result->batchId)->value('status'));
        self::assertSame(
            [JournalKind::IMPORT_STARTED->value, JournalKind::HOLD->value, JournalKind::IMPORT_FINISHED->value],
            self::strings($this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->pluck('kind')->all()),
        );

        $this->seal();

        $imported = self::strings($this->root()->table(EntrySettings::table())->where('import_batch_id', $result->batchId)->pluck('id')->all());
        $members  = self::strings($this->root()->table(IntegrityTables::membersTable())->whereIn('entry_id', $imported)->pluck('entry_id')->all());

        self::assertCount(2, $imported);
        self::assertSame(self::sorted($imported), self::sorted($members));
        self::assertSame(0, $this->verify()[0]);
    }

    /**
     * After the maintenance user prunes, the verifier, which reads the entries,
     * the seals, the members, the journal, the holds and the key tables and
     * writes only the progress of verification, verifies the whole log, the
     * seal `pruned`, and can change none of the evidence.
     *
     * @return void
     */
    public function testAVerifierWithOnlySelectVerifiesAfterAPrune(): void
    {
        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->seal();

        self::assertSame(1, AuditLog::lifecycle()->prune()->deleted);

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::VERIFIER);

        self::assertSame([0, ['pruned']], $this->verify());

        $verifier = DB::connection(self::VERIFIER);
        $driver   = $verifier->getDriverName();
        $journal  = (array) $this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->first();

        $refusals = [
            'delete an entry'      => static fn () => $verifier->table(EntrySettings::table())->where('id', $kept)->delete(),
            'insert a journal row' => static fn () => $verifier->table(LifecycleTables::journalTable())->insert([...$journal, 'id' => self::FOREIGN_ID, 'sequence' => 99]),
            'delete a seal'        => static fn () => $verifier->table(IntegrityTables::checkpointsTable())->delete(),
            'take the lock'        => static fn () => $verifier->table(LifecycleTables::lockTable())->where('id', 1)->update(['token' => 'verifier']),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The verifier's attempt to {$what}");
        }

        self::assertSame([$kept], $this->present([$pruned, $kept]));
    }

    /**
     * The writer can insert, update or delete no journal row, insert or delete
     * no hold and take no lock, and a lifecycle operation run on the writer's
     * credentials as its maintenance connection is refused before it writes
     * anything.
     *
     * @return void
     */
    public function testTheWriterCannotWriteTheJournalOrTheHolds(): void
    {
        $hold    = $this->hold(HoldScope::all());
        $writer  = DB::connection(self::WRITER);
        $driver  = $writer->getDriverName();
        $journal = (array) $this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->first();
        $holdRow = (array) $this->root()->table(LifecycleTables::holdsTable())->where('hold_id', $hold->hold->id)->first();

        $refusals = [
            'insert a journal row' => static fn () => $writer->table(LifecycleTables::journalTable())->insert([...$journal, 'id' => self::FOREIGN_ID, 'sequence' => 99]),
            'update a journal row' => static fn () => $writer->table(LifecycleTables::journalTable())->update(['reason' => 'rewritten']),
            'delete a journal row' => static fn () => $writer->table(LifecycleTables::journalTable())->delete(),
            'insert a hold'        => static fn () => $writer->table(LifecycleTables::holdsTable())->insert([...$holdRow, 'hold_id' => self::FOREIGN_ID]),
            'delete a hold'        => static fn () => $writer->table(LifecycleTables::holdsTable())->delete(),
            'take the lock'        => static fn () => $writer->table(LifecycleTables::lockTable())->where('id', 1)->update(['token' => 'writer']),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The writer's attempt to {$what}");
        }

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::WRITER);

        $refusal = null;

        try {
            AuditLog::lifecycle()->hold(HoldScope::tenantless(), self::authority(), HoldBasis::OTHER);
        } catch (\Throwable $exception) {
            $refusal = $exception;
        }

        self::assertNotNull($refusal, 'A hold on the writer\'s credentials was placed.');

        self::assertSame(1, $this->root()->table(LifecycleTables::journalTable())->count());
        self::assertSame([$hold->hold->id], self::strings($this->root()->table(LifecycleTables::holdsTable())->pluck('hold_id')->all()));
    }

    /**
     * The maintenance user inserts journal rows through the lifecycle, and can
     * update or delete none of them, nor truncate the journal, update a hold,
     * read a batch, or insert or update an entry: the journal stays as it was
     * written, and the writer still verifies it.
     *
     * @return void
     */
    public function testTheMaintenanceUserCannotUpdateOrDeleteTheJournal(): void
    {
        $id = $this->storeEntry(self::RECENT);

        $this->hold(HoldScope::all());
        $this->seal();

        $maintenance = DB::connection(self::MAINTENANCE);
        $driver      = $maintenance->getDriverName();
        $before      = $this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->get()->all();
        $entry       = (array) $this->root()->table(EntrySettings::table())->where('id', $id)->first();

        $refusals = [
            'update a journal row'  => static fn () => $maintenance->table(LifecycleTables::journalTable())->update(['reason' => 'rewritten']),
            'delete a journal row'  => static fn () => $maintenance->table(LifecycleTables::journalTable())->delete(),
            'truncate the journal'  => static fn () => $maintenance->statement(sprintf('TRUNCATE TABLE %s', LifecycleTables::journalTable())),
            'update a hold'         => static fn () => $maintenance->table(LifecycleTables::holdsTable())->update(['reason' => 'rewritten']),
            'read the batches'      => static fn () => $maintenance->table(LifecycleTables::importBatchesTable())->count(),
            'insert an entry'       => static fn () => $maintenance->table(EntrySettings::table())->insert([...$entry, 'id' => self::FOREIGN_ID]),
            'update an entry'       => static fn () => $maintenance->table(EntrySettings::table())->where('id', $id)->update(['outcome' => 'failure']),
            'insert a lock row'     => static fn () => $maintenance->table(LifecycleTables::lockTable())->insert(['id' => 2]),
            'update the lock\'s id' => static fn () => $maintenance->table(LifecycleTables::lockTable())->where('id', 1)->update(['id' => 2]),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The maintenance user's attempt to {$what}");
        }

        self::assertEquals($before, $this->root()->table(LifecycleTables::journalTable())->orderBy('sequence')->get()->all());
        self::assertSame(0, $this->verify()[0]);
    }

    /**
     * With the documented triggers installed beside the grants, every lifecycle
     * operation still runs on the users' own credentials: sealing, holds, an
     * import held on its start, prunes, releases, a projection rebuild, a
     * reconciliation and a verification.
     *
     * @return void
     */
    public function testWithTheTriggersInstalledEveryOperationStillRuns(): void
    {
        $this->installTriggers();

        $held   = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $pruned = $this->storeEntry(self::OLD);

        $this->seal();

        $hold   = $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')));
        $import = AuditLog::lifecycle()->import(ImportSource::fromFile($this->importFile(['rec-1']), 'crm-eu'), self::authority(), hold: true);

        self::assertSame([ImportStatus::COMPLETE, 1], [$import->status, $import->imported]);

        $first = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, null], [$first->status, $first->deleted, $first->failure]);
        self::assertSame([$held], $this->present([$held, $pruned]));
        self::assertTrue(AuditLog::lifecycle()->release($hold->hold->id, self::authority())->recorded);
        self::assertSame(1, AuditLog::lifecycle()->rebuildHolds());

        $second = AuditLog::lifecycle()->prune();

        self::assertSame([1, null], [$second->deleted, $second->failure]);
        self::assertSame([], $this->present([$held, $pruned]));
        self::assertTrue(AuditLog::lifecycle()->reconcile()->isComplete());

        $this->seal();

        self::assertSame(0, $this->verify()[0]);
    }

    /**
     * With the documented triggers installed, the tables' owner's delete of a
     * projection row is refused by its trigger; the maintenance user's, which a
     * rebuild makes, is allowed, and with the row gone the hold still keeps its
     * entry through a prune and is still listed, since both read the journal; a
     * rebuild puts the row back.
     *
     * @return void
     */
    public function testDeletingAProjectionRowIsRefusedByTheTriggerAndWithItRemovedChangesNothing(): void
    {
        $this->installTriggers();

        $held  = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $other = $this->storeEntry(self::OLD);

        $this->seal();

        $hold  = $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')));
        $holds = LifecycleTables::holdsTable();
        $root  = $this->root();

        self::assertRefusedByATrigger(static fn () => $root->table($holds)->delete(), $holds, 'DELETE');
        self::assertRefusedByTheGrants(static fn () => DB::connection(self::WRITER)->table($holds)->delete(), $root->getDriverName(), 'The writer\'s delete of a hold');
        self::assertSame(1, DB::connection(self::MAINTENANCE)->table($holds)->delete());
        self::assertSame(0, $this->root()->table($holds)->count());

        $result = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$result->status, $result->deleted, $result->held]);
        self::assertSame([$held], $this->present([$held, $other]));
        self::assertSame([$hold->hold->id], array_map(static fn (Hold $active): string => $active->id, AuditLog::lifecycle()->holds()));
        self::assertSame(1, AuditLog::lifecycle()->rebuildHolds());
        self::assertSame([$hold->hold->id], self::strings($this->root()->table($holds)->pluck('hold_id')->all()));
    }

    /**
     * Roll back and close the logins' connections, drop the documented triggers
     * when this test installed them, then drop the logins.
     *
     * @return void
     */
    private function dropLogins(): void
    {
        $root = $this->root();

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            $connection = DB::connection($placeholder);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            DB::purge($placeholder);
        }

        if ($this->triggers) {
            self::dropDocumentedTriggers($root);
        }

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::dropLogin($root, $this->names[$placeholder]);
        }
    }

    /**
     * Install the engine's documented triggers, for this worker's logins, as
     * the tables' owner.
     *
     * @return void
     */
    private function installTriggers(): void
    {
        $root = $this->root();

        self::runDocumentedTriggers($root, $this->names);

        $this->triggers = true;
    }

    /**
     * Place a hold of the scope through the lifecycle, on the test's authority,
     * and assert it was recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldResult
     */
    private function hold(HoldScope $scope): HoldResult
    {
        $result = AuditLog::lifecycle()->hold($scope, self::authority(), HoldBasis::LEGAL_CLAIM);

        self::assertTrue($result->recorded);

        return $result;
    }

    /**
     * Store a captured record with the fields given over its own, happening at
     * the instant given and recorded at the test's time, through the writer,
     * and return its id.
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
     * Seal every entry recorded so far through `audit-log:seal --sweep`, on the
     * storage connection's credentials.
     *
     * @return void
     */
    private function seal(): void
    {
        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]), Artisan::output());
    }

    /**
     * Run `audit-log:verify --json` on the storage connection's credentials and
     * return its exit code and each segment's integrity, in order.
     *
     * @return array{0: int, 1: list<string>}
     *
     * @phpstan-impure
     */
    private function verify(): array
    {
        $exit     = Artisan::call('audit-log:verify', ['--json' => true]);
        $segments = [];

        foreach (array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => str_starts_with($line, '{')) as $line) {
            $decoded = json_decode($line, true);

            if (!is_array($decoded) || ($decoded['type'] ?? null) !== 'segment' || !is_string($decoded['integrity'] ?? null)) {
                continue;
            }

            $segments[] = $decoded['integrity'];
        }

        return [$exit, $segments];
    }

    /**
     * The ids among those given whose entries are still stored, read as the
     * tables' owner, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        return self::sorted(self::strings($this->root()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all()));
    }

    /**
     * A file of a line of the import format for each record id, and its path.
     *
     * @param  list<string>  $recordIds
     * @return string
     */
    private function importFile(array $recordIds): string
    {
        $lines = array_map(static fn (string $recordId): string => (string) json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-12-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'category'         => 'finance',
        ]), $recordIds);

        $path = (string) tempnam(sys_get_temp_dir(), 'least-privilege-lifecycle-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The authority every operation is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * The strings given, sorted bytewise.
     *
     * @param  list<string>  $strings
     * @return list<string>
     */
    private static function sorted(array $strings): array
    {
        sort($strings, SORT_STRING);

        return $strings;
    }

    /**
     * The worker's own connection, as the tables' owner.
     *
     * @return \Illuminate\Database\Connection
     */
    private function root(): Connection
    {
        return DB::connection(self::CONNECTION);
    }
}
