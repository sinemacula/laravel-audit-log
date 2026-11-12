<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldProjection;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\TestCase;

/**
 * Feature tests for the holds projection, its rebuild and its drift.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldProjection::class)]
final class HoldProjectionTest extends TestCase
{
    /** @var string When every hold is placed. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-b000-7000-8000-000000000001';

    /** @var string When every hold built by hand was placed. */
    private const string PLACED_AT = '2026-11-01T12:00:00.123456Z';

    /** @var string The operation every hold is placed under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

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
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A row carries its hold's scope, digest, batch, times and authority.
     *
     * @return void
     */
    public function testTheRowCarriesItsScopeDigestAndBatch(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'))->importBatch(self::BATCH);
        $hold  = self::hold('01932b4e-d000-7000-8000-000000000001', $scope, '2027-05-01T00:00:00.000000Z');

        $this->projection()->insert($this->maintenance(), $hold);

        $row = $this->projection()->rows($this->maintenance())[0];

        self::assertSame($hold->id, $row['hold_id']);
        self::assertSame(CanonicalEncoder::encode($scope->toArray()), $row['scope']);
        self::assertSame($scope->digest(), $row['scope_digest']);
        self::assertSame('regulatory', $row['basis']);
        self::assertSame(self::BATCH, $row['import_batch_id']);
        self::assertSame('2026-11-01T12:00:00.123456Z', StoredTime::fromStorage((string) $row['placed_at']));
        self::assertSame('2027-05-01T00:00:00.000000Z', StoredTime::fromStorage((string) $row['review_by']));
        self::assertSame('App\Models\User', $row['authority_type']);
        self::assertSame('7', $row['authority_id']);
        self::assertSame('case.review', $row['reason']);
        self::assertSame('app:ticket-123', $row['external_reference']);
        self::assertSame(self::OPERATION, $row['operation_id']);
        self::assertSame(3, (int) $row['journal_sequence']);
    }

    /**
     * A hold of no review date and no batch leaves both `null`.
     *
     * @return void
     */
    public function testARowOfNoReviewAndNoBatchLeavesThemNull(): void
    {
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000001'));

        $row = $this->projection()->rows($this->maintenance())[0];

        self::assertNull($row['review_by']);
        self::assertNull($row['import_batch_id']);
    }

    /**
     * The rows are listed in the order their holds were journalled.
     *
     * @return void
     */
    public function testTheRowsAreInJournalOrder(): void
    {
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000003', journalSequence: 9));
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000001', journalSequence: 10));
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000002', journalSequence: 2));

        self::assertSame(
            ['01932b4e-d000-7000-8000-000000000002', '01932b4e-d000-7000-8000-000000000003', '01932b4e-d000-7000-8000-000000000001'],
            array_column($this->projection()->rows($this->maintenance()), 'hold_id'),
        );
    }

    /**
     * Deleting a row removes that hold's row alone, and a missing one is no
     * error.
     *
     * @return void
     */
    public function testDeleteRemovesOnlyItsRow(): void
    {
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000001'));
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000002'));

        $this->projection()->delete($this->maintenance(), '01932b4e-d000-7000-8000-000000000001');
        $this->projection()->delete($this->maintenance(), '01932b4e-d000-7000-8000-000000000009');

        self::assertSame(['01932b4e-d000-7000-8000-000000000002'], array_column($this->projection()->rows($this->maintenance()), 'hold_id'));
    }

    /**
     * A rebuild from the verified chain equals the projection kept live.
     *
     * @return void
     */
    public function testTheRebuildEqualsTheLiveProjection(): void
    {
        $keeper = app(HoldKeeper::class);

        $keeper->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        $released = $keeper->place(self::OPERATION, HoldScope::tenantless(), self::authority(), HoldBasis::OTHER, null);
        $keeper->place(self::OPERATION, HoldScope::all()->importBatch(self::BATCH), self::authority(), HoldBasis::REGULATORY, new CarbonImmutable('2027-01-01 00:00:00', 'UTC'));
        $keeper->release(self::OPERATION, $released->id, self::authority());

        $live = $this->projection()->rows($this->maintenance());

        self::assertCount(2, $live);

        $holds = DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable());

        $holds->where('hold_id', $live[0]['hold_id'])->delete();
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000009'));

        self::assertSame(2, $keeper->rebuild(self::OPERATION));
        self::assertEquals($live, $this->projection()->rows($this->maintenance()));
    }

    /**
     * Rebuilding replaces every row with exactly the holds given and returns
     * their count.
     *
     * @return void
     */
    public function testRebuildReplacesEveryRow(): void
    {
        $this->projection()->insert($this->maintenance(), self::hold('01932b4e-d000-7000-8000-000000000001'));

        $holds = [self::hold('01932b4e-d000-7000-8000-000000000002'), self::hold('01932b4e-d000-7000-8000-000000000003')];

        self::assertSame(2, $this->projection()->rebuild($this->maintenance(), $holds));
        $rows = $this->projection()->rows($this->maintenance());

        self::assertSame(['01932b4e-d000-7000-8000-000000000002', '01932b4e-d000-7000-8000-000000000003'], array_column($rows, 'hold_id'));
        self::assertSame(0, $this->projection()->rebuild($this->maintenance(), []));
        self::assertSame([], $this->projection()->rows($this->maintenance()));
    }

    /**
     * Drift names, sorted, every hold missing, extra or changed.
     *
     * @return void
     */
    public function testDriftNamesMissingExtraAndChangedHolds(): void
    {
        $ids = [
            'missing' => '01932b4e-d000-7000-8000-00000000000a',
            'digest'  => '01932b4e-d000-7000-8000-000000000003',
            'basis'   => '01932b4e-d000-7000-8000-000000000002',
            'review'  => '01932b4e-d000-7000-8000-000000000005',
            'scope'   => '01932b4e-d000-7000-8000-000000000004',
            'in step' => '01932b4e-d000-7000-8000-000000000001',
            'extra'   => '01932b4e-d000-7000-8000-000000000000',
        ];

        $replayed = [];

        foreach (['missing', 'digest', 'basis', 'review', 'scope', 'in step'] as $label) {
            $replayed[] = self::hold($ids[$label], reviewBy: '2027-05-01T00:00:00.000000Z');
        }

        foreach ([...array_slice($replayed, 1), self::hold($ids['extra'])] as $hold) {
            $this->projection()->insert($this->maintenance(), $hold);
        }

        $table = DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable());

        $table->clone()->where('hold_id', $ids['digest'])->update(['scope_digest' => str_repeat('f', 64)]);
        $table->clone()->where('hold_id', $ids['basis'])->update(['basis' => 'other']);
        $table->clone()->where('hold_id', $ids['review'])->update(['review_by' => '2027-05-01 00:00:00.000001']);
        $table->clone()->where('hold_id', $ids['scope'])->update(['scope' => CanonicalEncoder::encode(HoldScope::tenantless()->toArray())]);

        $drift = $this->projection()->drift($replayed, $this->projection()->rows($this->maintenance()));

        $expected = [$ids['extra'], $ids['basis'], $ids['digest'], $ids['scope'], $ids['review'], $ids['missing']];

        self::assertSame($expected, $drift);
    }

    /**
     * A projection in step, or empty with no holds, has no drift.
     *
     * @return void
     */
    public function testAProjectionInStepHasNoDrift(): void
    {
        $holds = [
            self::hold('01932b4e-d000-7000-8000-000000000001', HoldScope::all()->importBatch(self::BATCH), '2027-05-01T00:00:00.000000Z'),
            self::hold('01932b4e-d000-7000-8000-000000000002'),
        ];

        self::assertSame([], $this->projection()->drift([], []));

        $this->projection()->rebuild($this->maintenance(), $holds);

        self::assertSame([], $this->projection()->drift($holds, $this->projection()->rows($this->maintenance())));
    }

    /**
     * An unreadable, added or dropped review date drifts.
     *
     * @return void
     */
    public function testAnUnreadableOrMismatchedReviewDateDrifts(): void
    {
        $dated   = self::hold('01932b4e-d000-7000-8000-000000000001', reviewBy: '2027-05-01T00:00:00.000000Z');
        $undated = self::hold('01932b4e-d000-7000-8000-000000000002');
        $rows    = [...$this->rowsOf([$dated]), ...$this->rowsOf([$undated])];

        $rows[0]['review_by'] = 'next spring';

        self::assertSame([$dated->id], $this->projection()->drift([$dated, $undated], $rows));

        $rows[0]['review_by'] = null;
        $rows[1]['review_by'] = '2027-05-01 00:00:00';

        self::assertSame([$dated->id, $undated->id], $this->projection()->drift([$dated, $undated], $rows));
    }

    /**
     * The stored rows of the holds, inserted and read back.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @return list<array<string, scalar|null>>
     */
    private function rowsOf(array $holds): array
    {
        $this->projection()->rebuild($this->maintenance(), $holds);

        return $this->projection()->rows($this->maintenance());
    }

    /**
     * A hold of the id given, of the scope and review date given or every entry
     * and none.
     *
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  ?string  $reviewBy
     * @param  int  $journalSequence
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function hold(string $id, ?HoldScope $scope = null, ?string $reviewBy = null, int $journalSequence = 3): Hold
    {
        $operator = Reference::of('App\Models\User', '7');

        $scope ??= HoldScope::all();

        return new Hold($id, $scope, HoldBasis::REGULATORY, $reviewBy, self::PLACED_AT, $operator, 'case.review', 'app:ticket-123', self::OPERATION, $journalSequence);
    }

    /**
     * The authority every hold is placed with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
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
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
