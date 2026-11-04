<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldProjection;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\Journal;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for placing and releasing holds and rebuilding their
 * projection, on whichever engine the suite runs against: a hold's journal row
 * and projection row commit in one lifecycle transaction behind the lock;
 * overlapping holds each count and a release removes only its own; a release of
 * a hold never placed or already released is refused writing nothing; a
 * hold id is never placed twice; a broken chain refuses a hold and a release;
 * `placeIn()` joins the caller's transaction; and every decision, a release's
 * and the active holds', is read from the verified chain, never from the
 * projection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldKeeper::class)]
final class HoldKeeperTest extends TestCase
{
    use WritesTheJournal;

    /** @var string When every operation runs. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string The operation every test runs, unless it names another. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string A hold id an import minted. */
    private const string MINTED = '01932b4e-d000-7000-8000-000000000001';

    /** @var string A hold id no hold was ever placed under. */
    private const string UNKNOWN = '01932b4e-d000-7000-8000-00000000ffff';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
    }

    /**
     * Roll back any transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A hold is placed in one lifecycle transaction: the lock first, then the
     * journal row and the projection row, then the commit; the hold returned is
     * the one the journal row and the projection row record.
     *
     * @return void
     */
    public function testAHoldIsJournalledAndProjectedInOneTransaction(): void
    {
        $log  = $this->statements();
        $hold = $this->keeper()->place(self::OPERATION, self::scope(), self::authority(), HoldBasis::LEGAL_CLAIM, new CarbonImmutable('2027-05-01 00:00:00', 'UTC'));

        $labels = ['begin', 'commit', 'rollback', 'lock', 'journal', 'holds'];
        $writes = array_values(array_filter($log->getArrayCopy(), static fn (string $entry): bool => in_array($entry, $labels, true)));

        self::assertSame(['begin', 'lock', 'journal', 'holds', 'commit'], $writes);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $hold->id);

        $row = JournalRow::fromRow($this->journalRows()[0], true);

        self::assertSame(JournalKind::HOLD, $row->kind);
        self::assertSame($hold->id, $row->holdId);
        self::assertSame(self::OPERATION, $row->operationId);
        $payload = ['hold_id' => $hold->id, 'scope' => self::scope()->toArray(), 'basis' => 'legal_claim', 'review_by' => '2027-05-01T00:00:00.000000Z'];

        self::assertSame(CanonicalEncoder::encode($payload), $row->payload);
        self::assertSame('2026-11-02T09:00:00.123456Z', $hold->placedAt);
        self::assertSame('2027-05-01T00:00:00.000000Z', $hold->reviewBy);
        self::assertSame(1, $hold->journalSequence);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $hold->operator->toArray());
        self::assertSame('app:ticket-123', $hold->externalReference);
        self::assertSame([$hold->id], array_column($this->projectionRows(), 'hold_id'));
        self::assertSame([], $this->projection()->drift($this->keeper()->active(), $this->projectionRows()));
    }

    /**
     * Placing a hold confirms the installation first, writing its id once on an
     * installation that lost the one the migrations seed.
     *
     * @return void
     */
    public function testAHoldConfirmsTheInstallation(): void
    {
        $state = DB::connection(StorageConnection::name())->table(IntegrityTables::stateTable())->where('name', InstallationIdentity::NAME);

        (clone $state)->delete();

        $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::OTHER, null);

        self::assertSame(1, (clone $state)->count());
    }

    /**
     * Overlapping holds each count: two holds of entries both keep are both
     * active, and the entries stay kept by one when the other is released.
     *
     * @return void
     */
    public function testOverlappingHoldsEachCount(): void
    {
        $tenant = $this->keeper()->place(self::OPERATION, HoldScope::tenants(Reference::of('organisation', 'org_01')), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        $actor  = $this->keeper()->place(self::OPERATION, HoldScope::all()->about(Reference::of('user', '42')), self::authority(), HoldBasis::INVESTIGATION, null);
        $row    = [
            'tenant_type' => 'organisation',
            'tenant_id'   => 'org_01',
            'actor_type'  => 'user',
            'actor_id'    => '42',
            'category'    => 'finance',
            'occurred_at' => '2026-11-01 12:00:00',
        ];

        $active = $this->keeper()->active();

        self::assertSame([$tenant->id, $actor->id], array_map(static fn (Hold $hold): string => $hold->id, $active));
        self::assertCount(2, array_filter($active, static fn (Hold $hold): bool => $hold->scope->matches($row)));

        $this->keeper()->release(self::OPERATION, $tenant->id, self::authority());

        self::assertSame([$actor->id], array_map(static fn (Hold $hold): string => $hold->id, $this->keeper()->active()));
        self::assertTrue($this->keeper()->active()[0]->scope->matches($row));
    }

    /**
     * A release removes its own hold alone, from the chain and the projection,
     * journalling the release under its authority, and returns the hold as it
     * was.
     *
     * @return void
     */
    public function testAReleaseRemovesOnlyItsHold(): void
    {
        $first  = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        $second = $this->keeper()->place(self::OPERATION, HoldScope::tenantless(), self::authority(), HoldBasis::REGULATORY, null);

        $released = $this->keeper()->release('01932b4e-9000-7000-8000-0000000000a2', $first->id, new Authority(Reference::of('App\Models\User', '8'), 'claim.settled'));

        self::assertSame($first->toArray(), $released->toArray());
        self::assertSame([$second->id], array_map(static fn (Hold $hold): string => $hold->id, $this->keeper()->active()));
        self::assertSame([$second->id], array_column($this->projectionRows(), 'hold_id'));

        $row = JournalRow::fromRow($this->journalRows()[2], true);

        self::assertSame(JournalKind::RELEASE, $row->kind);
        self::assertSame($first->id, $row->holdId);
        self::assertSame(['hold_id' => $first->id], $row->payloadMap());
        self::assertSame('8', $row->authorityId);
        self::assertSame('claim.settled', $row->reason);
        self::assertSame('01932b4e-9000-7000-8000-0000000000a2', $row->operationId);
    }

    /**
     * A release of a hold never placed is refused, naming the hold, and writes
     * nothing: no journal row, no projection change, and the lock's row as it
     * was.
     *
     * @return void
     */
    public function testReleasingAnUnknownHoldIsRefusedAndWritesNothing(): void
    {
        $hold  = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        $token = $this->lockToken();

        $this->expectUnknown(self::UNKNOWN);

        self::assertCount(1, $this->journalRows());
        self::assertSame([$hold->id], array_column($this->projectionRows(), 'hold_id'));
        self::assertSame($token, $this->lockToken());
    }

    /**
     * A second release of one hold is refused as unknown, and writes nothing.
     *
     * @return void
     */
    public function testADoubleReleaseIsRefused(): void
    {
        $hold = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $this->keeper()->release(self::OPERATION, $hold->id, self::authority());

        $this->expectUnknown($hold->id);

        self::assertCount(2, $this->journalRows());
    }

    /**
     * A hold id placed before, released or active, is never placed again, and
     * the refusal writes nothing; one never placed is placed under that id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReleasedHoldIdIsNeverPlacedAgain(): void
    {
        $hold = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null, self::MINTED);

        self::assertSame(self::MINTED, $hold->id);

        foreach (['active' => false, 'released' => true] as $state => $release) {
            if ($release) {
                $this->keeper()->release(self::OPERATION, self::MINTED, self::authority());
            }

            $rows = count($this->journalRows());

            try {
                $this->keeper()->place(self::OPERATION, HoldScope::tenantless(), self::authority(), HoldBasis::OTHER, null, self::MINTED);

                self::fail("Expected a hold id placed before, {$state}, to be refused.");
            } catch (\LogicException $exception) {
                self::assertSame('The hold id `' . self::MINTED . '` was placed before; a hold id is never reused.', $exception->getMessage());
            }

            self::assertCount($rows, $this->journalRows());
        }
    }

    /**
     * A hold id that is not a lower-case UUID v7 is refused for a hold and for
     * a release, before anything is read or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldIdThatIsNotAUuidV7IsRefused(): void
    {
        $place = fn (string $holdId): Hold => $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::OTHER, null, $holdId);

        $calls = [
            'a hold under an upper-case id' => static fn (): Hold => $place(strtoupper(self::MINTED)),
            'a hold under a UUID v4'        => static fn (): Hold => $place('0c5cbc7e-63d1-4b49-9f62-3a8e1c1a1a1a'),
            'a release of no UUID'          => fn (): Hold => $this->keeper()->release(self::OPERATION, 'hold-1', self::authority()),
        ];

        foreach ($calls as $label => $call) {
            try {
                $call();

                self::fail("Expected {$label} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A hold id must be a lower-case UUID v7.', $exception->getMessage());
            }
        }

        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->projectionRows());
    }

    /**
     * A hold, a release and a rebuild on a journal that fails verification are
     * refused fail closed, and write nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldOnABrokenChainIsRefused(): void
    {
        $hold = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $this->tamperJournal(1, ['reason' => 'other.reason']);

        $calls = [
            'a hold'    => fn (): Hold => $this->keeper()->place(self::OPERATION, HoldScope::tenantless(), self::authority(), HoldBasis::OTHER, null),
            'a release' => fn (): Hold => $this->keeper()->release(self::OPERATION, $hold->id, self::authority()),
            'a rebuild' => fn (): int => $this->keeper()->rebuild(self::OPERATION),
            'a listing' => fn (): array => $this->keeper()->active(),
        ];

        foreach ($calls as $label => $call) {
            try {
                $call();

                self::fail("Expected {$label} to be refused.");
            } catch (JournalBrokenException $exception) {
                self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding, $label);
            }
        }

        self::assertCount(1, $this->journalRows());
        self::assertSame([$hold->id], array_column($this->projectionRows(), 'hold_id'));
    }

    /**
     * `placeIn()` joins the transaction its caller opened: the hold commits
     * with the caller's own journal row, onto the replay it returned, and a
     * rollback of the caller's transaction leaves no hold row and no projection
     * row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPlaceInJoinsTheCallersTransaction(): void
    {
        $journal = app(Journal::class);

        $failure = null;

        try {
            app(MaintenanceTransaction::class)->run(self::OPERATION, function (Connection $connection): void {
                $replay = $this->replay()->verify($connection);

                $this->keeper()->placeIn($connection, $replay, self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null, self::MINTED);

                throw new \RuntimeException('The caller failed after placing the hold.');
            });
        } catch (\RuntimeException $exception) {
            $failure = $exception->getMessage();
        }

        self::assertSame('The caller failed after placing the hold.', $failure);

        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->projectionRows());

        [$hold, $replay] = app(MaintenanceTransaction::class)->run(self::OPERATION, function (Connection $connection) use ($journal): array {
            $replay          = $this->replay()->verify($connection);
            $started         = ['batch_id' => 'batch-1'];
            $replay          = $journal->append($connection, $replay, JournalKind::IMPORT_STARTED, self::OPERATION, self::authority(), $started, null, self::MINTED);
            $scope           = HoldScope::all()->importBatch('01932b4e-b000-7000-8000-000000000001');
            [$hold, $replay] = $this->keeper()->placeIn($connection, $replay, self::OPERATION, $scope, self::authority(), HoldBasis::LEGAL_CLAIM, null, self::MINTED);

            return [$hold, $replay];
        });

        self::assertSame(self::MINTED, $hold->id);
        self::assertSame(2, $hold->journalSequence);
        self::assertSame([2, JournalRow::fromRow($this->journalRows()[1], false)->hmac], $replay->head());
        self::assertSame([self::MINTED], array_column($this->projectionRows(), 'hold_id'));
        self::assertSame('01932b4e-b000-7000-8000-000000000001', $this->projectionRows()[0]['import_batch_id']);
    }

    /**
     * A hold id placed before is refused by `placeIn()` too, before anything is
     * appended in the caller's transaction.
     *
     * @return void
     */
    public function testPlaceInRefusesAHoldIdPlacedBefore(): void
    {
        $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null, self::MINTED);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The hold id `' . self::MINTED . '` was placed before; a hold id is never reused.');

        app(MaintenanceTransaction::class)->run(self::OPERATION, fn (Connection $connection): array => $this->keeper()->placeIn(
            $connection,
            $this->replay()->verify($connection),
            self::OPERATION,
            HoldScope::all(),
            self::authority(),
            HoldBasis::LEGAL_CLAIM,
            null,
            self::MINTED,
        ));
    }

    /**
     * The rebuild replays the verified chain: rows deleted, inserted and
     * changed by hand are replaced by exactly the active holds.
     *
     * @return void
     */
    public function testTheRebuildReplaysTheVerifiedChain(): void
    {
        $kept     = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        $released = $this->keeper()->place(self::OPERATION, HoldScope::tenantless(), self::authority(), HoldBasis::OTHER, null);
        $changed  = $this->keeper()->place(self::OPERATION, HoldScope::all()->categories('finance'), self::authority(), HoldBasis::REGULATORY, null);

        $this->keeper()->release(self::OPERATION, $released->id, self::authority());

        $live  = $this->projectionRows();
        $holds = DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable());

        $holds->clone()->where('hold_id', $kept->id)->delete();
        $holds->clone()->where('hold_id', $changed->id)->update(['scope' => CanonicalEncoder::encode(HoldScope::tenantless()->toArray()), 'basis' => 'other']);
        $holds->clone()->insert([...$live[0], 'hold_id' => $released->id, 'journal_sequence' => 2]);

        $drifted = [$kept->id, $changed->id, $released->id];

        sort($drifted, SORT_STRING);

        self::assertSame($drifted, $this->projection()->drift($this->keeper()->active(), $this->projectionRows()));
        self::assertSame(2, $this->keeper()->rebuild(self::OPERATION));
        self::assertEquals($live, $this->projectionRows());
        self::assertSame([], $this->projection()->drift($this->keeper()->active(), $this->projectionRows()));
    }

    /**
     * The active holds are read only from the verified chain: a projection row
     * deleted by hand leaves its hold active, and its release still succeeds.
     *
     * @return void
     */
    public function testHoldsAreReadOnlyFromTheVerifiedChain(): void
    {
        $hold = $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable())->delete();

        self::assertSame([$hold->toArray()], array_map(static fn (Hold $active): array => $active->toArray(), $this->keeper()->active()));
        self::assertSame($hold->id, $this->keeper()->release(self::OPERATION, $hold->id, self::authority())->id);
        self::assertSame([], $this->keeper()->active());
    }

    /**
     * A release is decided from the chain, not the projection: a projection row
     * inserted by hand for a hold the chain never placed does not make it
     * releasable, and the row is left as it was.
     *
     * @return void
     */
    public function testAReleaseIsDecidedFromTheChainNotTheProjection(): void
    {
        $operator = Reference::of('App\Models\User', '7');
        $forged   = new Hold(self::UNKNOWN, HoldScope::all(), HoldBasis::OTHER, null, '2026-11-01T00:00:00.000000Z', $operator, 'case.review', null, self::OPERATION, 1);

        $this->projection()->insert(DB::connection(StorageConnection::forMaintenance()), $forged);

        $this->expectUnknown(self::UNKNOWN);

        self::assertSame([], $this->journalRows());
        self::assertSame([self::UNKNOWN], array_column($this->projectionRows(), 'hold_id'));
    }

    /**
     * Listing the active holds runs behind the lock under an operation of its
     * own, a UUID v7, and journals nothing.
     *
     * @return void
     */
    public function testListingTheActiveHoldsTakesTheLock(): void
    {
        $this->keeper()->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $before = $this->lockToken();

        self::assertCount(1, $this->keeper()->active());

        $after = (string) $this->lockToken();

        self::assertNotSame($before, $after);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[0-9a-f]{16}\z/', $after);
        self::assertStringStartsNotWith(self::OPERATION, $after);
        self::assertCount(1, $this->journalRows());
    }

    /**
     * Expect the release of the hold id to be refused as unknown, naming it,
     * and nothing else to be thrown.
     *
     * @param  string  $holdId
     * @return void
     *
     * @throws \Throwable
     */
    private function expectUnknown(string $holdId): void
    {
        try {
            $this->keeper()->release(self::OPERATION, $holdId, self::authority());

            self::fail('Expected the release to be refused.');
        } catch (UnknownHoldException $exception) {
            self::assertSame(UnknownHoldException::for($holdId)->getMessage(), $exception->getMessage());
        }
    }

    /**
     * Record each statement and each transaction event from now on, in order:
     * `lock` for the lock's update, `journal` for an insert of a journal row,
     * `holds` for a change of the projection, and the SQL's first word for
     * anything else.
     *
     * @return \ArrayObject<int, string>
     */
    private function statements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $log */
        $log    = new \ArrayObject;
        $tables = ['lock' => LifecycleTables::lockTable(), 'journal' => LifecycleTables::journalTable(), 'holds' => LifecycleTables::holdsTable()];

        DB::listen(static function (QueryExecuted $query) use ($log, $tables): void {
            $verb = strtolower((string) strtok($query->sql, ' '));

            foreach ($tables as $label => $table) {
                if ($verb !== 'select' && preg_match('/\b' . $table . '\b/', $query->sql) === 1) {
                    $log->append($label);

                    return;
                }
            }

            $log->append($verb);
        });

        Event::listen(TransactionBeginning::class, static function () use ($log): void {
            $log->append('begin');
        });
        Event::listen(TransactionCommitted::class, static function () use ($log): void {
            $log->append('commit');
        });
        Event::listen(TransactionRolledBack::class, static function () use ($log): void {
            $log->append('rollback');
        });

        return $log;
    }

    /**
     * The token the lock row holds.
     *
     * @return ?string
     */
    private function lockToken(): ?string
    {
        $token = DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->where('id', 1)->value('token');

        return is_string($token) ? $token : null;
    }

    /**
     * Every row of the projection.
     *
     * @return list<array<string, scalar|null>>
     */
    private function projectionRows(): array
    {
        return $this->projection()->rows(DB::connection(StorageConnection::name()));
    }

    /**
     * The keeper the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper
     */
    private function keeper(): HoldKeeper
    {
        return app(HoldKeeper::class);
    }

    /**
     * The projection the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldProjection
     */
    private function projection(): HoldProjection
    {
        return app(HoldProjection::class);
    }

    /**
     * A replay of nothing yet, of the configured log.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId());
    }

    /**
     * The scope most holds are placed on: one tenant's finance entries.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope
     */
    private static function scope(): HoldScope
    {
        return HoldScope::tenants(Reference::of('organisation', 'org_01'))->categories('finance');
    }

    /**
     * The authority every hold is placed with, unless a test gives another.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }
}
