<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for a hold's scope: what each dimension keeps of a stored entry
 * row, a tenant's hold never keeping an entry of no tenant, every dimension
 * ANDed, the window half-open to the microsecond, narrowing that only ever
 * intersects, the refusals of an empty list, a limit exceeded and a window that
 * keeps nothing, and the canonical form, its digest and its strict reading
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldScope::class)]
final class HoldScopeTest extends TestCase
{
    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-b000-7000-8000-000000000001';

    /** @var string Another import batch's id. */
    private const string OTHER_BATCH = '01932b4e-b000-7000-8000-000000000002';

    /**
     * Every row matches the scope of every entry, with a tenant or without,
     * with any actor or none, at any time, of any batch.
     *
     * @return void
     */
    public function testAllMatchesEveryRow(): void
    {
        $scope = HoldScope::all();

        foreach (self::rows() as $label => $row) {
            self::assertTrue($scope->matches($row), "The scope of every entry must match {$label}.");
        }
    }

    /**
     * A tenant's hold matches a row only when both tenant columns are the
     * tenant's pair: another id, another type, or the type and id of two
     * different tenants never match.
     *
     * @return void
     */
    public function testATenantHoldMatchesOnlyItsExactPair(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'), Reference::of('team', 'team_9'));

        self::assertTrue($scope->matches(self::row()));
        self::assertTrue($scope->matches(self::row(['tenant_type' => 'team', 'tenant_id' => 'team_9'])));
        self::assertFalse($scope->matches(self::row(['tenant_id' => 'org_02'])));
        self::assertFalse($scope->matches(self::row(['tenant_type' => 'team'])));
        self::assertFalse($scope->matches(self::row(['tenant_type' => 'organisation', 'tenant_id' => 'team_9'])));
        self::assertFalse($scope->matches(self::row(['tenant_id' => 'ORG_01'])));
    }

    /**
     * A tenant's hold never matches a row of no tenant, nor one whose tenant is
     * half `null`: no `NULL` comparison makes a tenant's hold keep every entry
     * of no tenant.
     *
     * @return void
     */
    public function testATenantHoldNeverMatchesATenantlessRow(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'));

        self::assertFalse($scope->matches(self::row(['tenant_type' => null, 'tenant_id' => null])));
        self::assertFalse($scope->matches(self::row(['tenant_type' => 'organisation', 'tenant_id' => null])));
        self::assertFalse($scope->matches(self::row(['tenant_type' => null, 'tenant_id' => 'org_01'])));
        self::assertFalse($scope->matches(array_diff_key(self::row(), ['tenant_type' => true, 'tenant_id' => true])));
    }

    /**
     * Adding the entries of no tenant to a tenant's hold adds those rows and no
     * other tenant's.
     *
     * @return void
     */
    public function testWithTenantlessAddsOnlyTenantlessRows(): void
    {
        $tenant = HoldScope::tenants(Reference::of('organisation', 'org_01'));
        $scope  = $tenant->withTenantless();

        self::assertTrue($scope->matches(self::row()));
        self::assertTrue($scope->matches(self::row(['tenant_type' => null, 'tenant_id' => null])));
        self::assertFalse($scope->matches(self::row(['tenant_id' => 'org_02'])));
        self::assertFalse($tenant->matches(self::row(['tenant_type' => null, 'tenant_id' => null])), 'Narrowing must leave the scope it was called on as it was.');
        self::assertTrue(HoldScope::all()->withTenantless()->matches(self::row(['tenant_id' => 'org_02'])));
    }

    /**
     * The scope of no tenant matches only rows whose two tenant columns are
     * both `null`.
     *
     * @return void
     */
    public function testTenantlessMatchesOnlyTenantlessRows(): void
    {
        $scope = HoldScope::tenantless();

        self::assertTrue($scope->matches(self::row(['tenant_type' => null, 'tenant_id' => null])));
        self::assertFalse($scope->matches(self::row()));
        self::assertFalse($scope->matches(self::row(['tenant_type' => 'organisation', 'tenant_id' => null])));
        self::assertSame($scope->toArray(), $scope->withTenantless()->toArray());
    }

    /**
     * A reference's activity is matched as the actor's pair or the subject's,
     * never as a type and an id from different columns.
     *
     * @return void
     */
    public function testAboutMatchesTheActorOrTheSubject(): void
    {
        $scope = HoldScope::all()->about(Reference::of('user', '42'));

        self::assertTrue($scope->matches(self::row()));
        self::assertTrue($scope->matches(self::row(['actor_type' => null, 'actor_id' => null, 'subject_type' => 'user', 'subject_id' => '42'])));
        self::assertFalse($scope->matches(self::row(['actor_id' => '43'])));
        self::assertFalse($scope->matches(self::row(['actor_type' => 'invoice', 'actor_id' => '42', 'subject_type' => 'user', 'subject_id' => 'inv_0042'])));
        self::assertFalse($scope->matches(self::row(['actor_type' => null, 'actor_id' => null])));
    }

    /**
     * Categories keep only rows of those categories, and narrowing them again
     * keeps the intersection.
     *
     * @return void
     */
    public function testCategoriesNarrow(): void
    {
        $scope = HoldScope::all()->categories('finance', 'security');

        self::assertTrue($scope->matches(self::row()));
        self::assertTrue($scope->matches(self::row(['category' => 'security'])));
        self::assertFalse($scope->matches(self::row(['category' => 'audit'])));
        self::assertFalse($scope->matches(self::row(['category' => null])));

        $narrowed = $scope->categories('security', 'audit');

        self::assertSame(['security'], $narrowed->toArray()['categories']);
        self::assertFalse($narrowed->matches(self::row()));
        self::assertTrue($scope->matches(self::row()), 'Narrowing must leave the scope it was called on as it was.');
    }

    /**
     * The window keeps a row at its start and before its end, never at its end,
     * and either end may be open.
     *
     * @return void
     */
    public function testTheWindowIsHalfOpen(): void
    {
        $scope = HoldScope::all()->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-11-02 00:00:00.000000'));

        self::assertTrue($scope->matches(self::row(['occurred_at' => '2026-11-01 00:00:00.000000'])));
        self::assertTrue($scope->matches(self::row(['occurred_at' => '2026-11-01 23:59:59.999999'])));
        self::assertFalse($scope->matches(self::row(['occurred_at' => '2026-11-02 00:00:00.000000'])));

        $from = HoldScope::all()->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), null);
        $to   = HoldScope::all()->occurredBetween(null, self::instant('2026-11-01 00:00:00.000000'));

        self::assertTrue($from->matches(self::row(['occurred_at' => '2099-01-01 00:00:00.000000'])));
        self::assertFalse($from->matches(self::row(['occurred_at' => '2026-10-31 23:59:59.999999'])));
        self::assertTrue($to->matches(self::row(['occurred_at' => '2000-01-01 00:00:00.000000'])));
        self::assertFalse($to->matches(self::row(['occurred_at' => '2026-11-01 00:00:00.000000'])));
    }

    /**
     * Rows of `[stored time, whether the window keeps it]`: one microsecond
     * either side of each end, in each form an engine stores a time in.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideTimesAroundTheWindow(): iterable
    {
        yield from [
            'a microsecond before the start'  => ['2026-11-01 11:59:59.999999', false],
            'at the start'                    => ['2026-11-01 12:00:00.000000', true],
            'at the start, as PostgreSQL'     => ['2026-11-01 12:00:00', true],
            'a microsecond after the start'   => ['2026-11-01 12:00:00.000001', true],
            'a microsecond before the end'    => ['2026-11-01 12:00:00.499999', true],
            'at the end'                      => ['2026-11-01 12:00:00.500000', false],
            'at the end, as PostgreSQL'       => ['2026-11-01 12:00:00.5', false],
            'a microsecond after the end'     => ['2026-11-01 12:00:00.500001', false],
            'a tenth before the end, trimmed' => ['2026-11-01 12:00:00.4', true],
        ];
    }

    /**
     * The window is compared to the microsecond, whatever form the engine
     * returned the time in.
     *
     * @param  string  $occurredAt
     * @param  bool  $kept
     * @return void
     */
    #[DataProvider('provideTimesAroundTheWindow')]
    public function testOneMicrosecondEitherSideOfTheWindow(string $occurredAt, bool $kept): void
    {
        $scope = HoldScope::all()->occurredBetween(self::instant('2026-11-01 12:00:00.000000'), self::instant('2026-11-01 12:00:00.500000'));

        self::assertSame($kept, $scope->matches(self::row(['occurred_at' => $occurredAt])));
    }

    /**
     * A row whose time is missing or cannot be read is kept by any window, so a
     * hold never lets go of an entry it cannot place; a scope with no window
     * keeps it too.
     *
     * @return void
     */
    public function testARowWhoseTimeCannotBeReadIsKeptByAnyWindow(): void
    {
        $scope = HoldScope::all()->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-11-02 00:00:00.000000'));

        self::assertTrue($scope->matches(self::row(['occurred_at' => 'yesterday'])));
        self::assertTrue($scope->matches(self::row(['occurred_at' => null])));
        self::assertTrue($scope->matches(self::row(['occurred_at' => 20261101])));
        self::assertTrue(HoldScope::all()->matches(self::row(['occurred_at' => 'yesterday'])));
    }

    /**
     * Narrowing the window again keeps the later start and the earlier end.
     *
     * @return void
     */
    public function testNarrowingTheWindowKeepsTheLaterStartAndTheEarlierEnd(): void
    {
        $scope = HoldScope::all()
            ->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-11-10 00:00:00.000000'))
            ->occurredBetween(self::instant('2026-10-01 00:00:00.000000'), self::instant('2026-11-05 00:00:00.000000'))
            ->occurredBetween(self::instant('2026-11-02 00:00:00.000000'), null)
            ->occurredBetween(null, self::instant('2026-11-20 00:00:00.000000'));

        self::assertSame('2026-11-02T00:00:00.000000Z', $scope->toArray()['from']);
        self::assertSame('2026-11-05T00:00:00.000000Z', $scope->toArray()['to']);
    }

    /**
     * A window's ends given in another time zone are kept as instants in UTC.
     *
     * @return void
     */
    public function testTheWindowIsKeptInUtc(): void
    {
        $scope = HoldScope::all()->occurredBetween(new CarbonImmutable('2026-11-01 13:00:00.000001', 'Europe/London'), null);

        self::assertSame('2026-11-01T13:00:00.000001Z', $scope->toArray()['from']);

        $scope = HoldScope::all()->occurredBetween(new CarbonImmutable('2026-07-01 13:00:00.000001', 'Europe/London'), null);

        self::assertSame('2026-07-01T12:00:00.000001Z', $scope->toArray()['from']);
    }

    /**
     * An import batch's hold matches only that batch's rows, never a row of no
     * batch or of another.
     *
     * @return void
     */
    public function testImportBatchMatchesOnlyItsBatch(): void
    {
        $scope = HoldScope::all()->importBatch(self::BATCH);

        self::assertTrue($scope->matches(self::row(['import_batch_id' => self::BATCH])));
        self::assertFalse($scope->matches(self::row(['import_batch_id' => self::OTHER_BATCH])));
        self::assertFalse($scope->matches(self::row()));
        self::assertSame($scope->toArray(), $scope->importBatch(self::BATCH)->toArray());
    }

    /**
     * Every dimension is ANDed: a row that fails any one of them is not kept,
     * however many others it meets.
     *
     * @return void
     */
    public function testDimensionsAreAnded(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'))
            ->about(Reference::of('user', '42'))
            ->categories('finance')
            ->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-11-02 00:00:00.000000'))
            ->importBatch(self::BATCH);

        $kept = self::row(['import_batch_id' => self::BATCH]);

        self::assertTrue($scope->matches($kept));

        $misses = [
            'another tenant'     => ['tenant_id' => 'org_02'],
            'no tenant'          => ['tenant_type' => null, 'tenant_id' => null],
            'another actor'      => ['actor_id' => '43'],
            'another category'   => ['category' => 'security'],
            'outside the window' => ['occurred_at' => '2026-11-02 00:00:00.000000'],
            'another batch'      => ['import_batch_id' => self::OTHER_BATCH],
        ];

        foreach ($misses as $label => $columns) {
            self::assertFalse($scope->matches(array_replace($kept, $columns)), "A row with {$label} must not be kept.");
        }
    }

    /**
     * Rows of `[what builds the scope, the message]`: an empty list in each
     * dimension that takes one.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope, 1: string}>
     */
    public static function provideEmptyLists(): iterable
    {
        $empty = 'A hold scope\'s %s must name at least one; an empty list never means everything.';

        yield from [
            'no tenant'    => [static fn (): HoldScope => HoldScope::tenants(), sprintf($empty, 'tenants')],
            'no reference' => [static fn (): HoldScope => HoldScope::all()->about(), sprintf($empty, 'about-references')],
            'no category'  => [static fn (): HoldScope => HoldScope::all()->categories(), sprintf($empty, 'categories')],
        ];
    }

    /**
     * An empty list is refused, naming the dimension, never read as everything.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $build
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideEmptyLists')]
    public function testRefusesAnEmptyList(\Closure $build, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    /**
     * One beyond each limit is refused, naming the limit, and the limit itself,
     * counted after duplicates are dropped, is kept.
     *
     * @return void
     */
    public function testRefusesMoreThanItsLimits(): void
    {
        $references = static fn (int $count): array => array_map(static fn (int $index): Reference => Reference::of('user', (string) $index), range(1, $count));
        $categories = static fn (int $count): array => array_map(static fn (int $index): string => 'category_' . $index, range(1, $count));

        self::assertCount(100, HoldScope::tenants(...$references(100), ...$references(100))->toArray()['tenants'] ?? []);
        self::assertCount(100, HoldScope::all()->about(...$references(100))->toArray()['about'] ?? []);
        self::assertCount(50, HoldScope::all()->categories(...$categories(50), ...$categories(50))->toArray()['categories'] ?? []);

        $refusals = [
            'A hold scope holds at most 100 tenants.'          => static fn (): HoldScope => HoldScope::tenants(...$references(101)),
            'A hold scope holds at most 100 about-references.' => static fn (): HoldScope => HoldScope::all()->about(...$references(101)),
            'A hold scope holds at most 50 categories.'        => static fn (): HoldScope => HoldScope::all()->categories(...$categories(51)),
        ];

        foreach ($refusals as $message => $build) {
            try {
                $build();

                self::fail("Expected the scope to be refused: {$message}");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[what builds the scope, the message]`: windows that keep
     * nothing, given or narrowed to.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope, 1: string}>
     */
    public static function provideWindowsThatKeepNothing(): iterable
    {
        $backward = 'A hold scope\'s window must start before it ends.';
        $first    = self::instant('2026-11-01 00:00:00.000000');
        $second   = self::instant('2026-11-02 00:00:00.000000');
        $earlier  = self::instant('2026-10-01 00:00:00.000000');

        yield from [
            'no end at all'         => [static fn (): HoldScope => HoldScope::all()->occurredBetween(null, null), 'A hold scope\'s window must have a start, an end or both.'],
            'backward'              => [static fn (): HoldScope => HoldScope::all()->occurredBetween($second, $first), $backward],
            'empty'                 => [static fn (): HoldScope => HoldScope::all()->occurredBetween($first, $first), $backward],
            'narrowed past its end' => [static fn (): HoldScope => HoldScope::all()->occurredBetween(null, $first)->occurredBetween($first, null), $backward],
            'narrowed before start' => [static fn (): HoldScope => HoldScope::all()->occurredBetween($first, null)->occurredBetween(null, $earlier), $backward],
        ];
    }

    /**
     * A window that would keep nothing is refused.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $build
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideWindowsThatKeepNothing')]
    public function testRefusesABackwardOrEmptyWindow(\Closure $build, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    /**
     * Rows of `[what builds the scope, the message]`: narrowings that would
     * keep nothing, and values a dimension refuses.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope, 1: string}>
     */
    public static function provideOtherRefusals(): iterable
    {
        $nothing  = 'A hold scope\'s %s, narrowed again, would hold nothing.';
        $one      = Reference::of('user', '1');
        $two      = Reference::of('user', '2');
        $batch    = 'A hold scope\'s import batch must be a lower-case UUID.';
        $category = 'A hold scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.';

        yield from [
            'disjoint references'     => [static fn (): HoldScope => HoldScope::all()->about($one)->about($two), sprintf($nothing, 'about-references')],
            'disjoint categories'     => [static fn (): HoldScope => HoldScope::all()->categories('finance')->categories('security'), sprintf($nothing, 'categories')],
            'another batch'           => [static fn (): HoldScope => HoldScope::all()->importBatch(self::BATCH)->importBatch(self::OTHER_BATCH), sprintf($nothing, 'import batch')],
            'an upper-case batch'     => [static fn (): HoldScope => HoldScope::all()->importBatch(strtoupper(self::BATCH)), $batch],
            'a batch that is no UUID' => [static fn (): HoldScope => HoldScope::all()->importBatch('batch-1'), $batch],
            'an upper-case category'  => [static fn (): HoldScope => HoldScope::all()->categories('Finance'), $category],
            'a category with a digit' => [static fn (): HoldScope => HoldScope::all()->categories('1finance'), $category],
        ];
    }

    /**
     * A narrowing that would keep nothing, and a value outside its dimension's
     * grammar, are refused, naming the dimension.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $build
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideOtherRefusals')]
    public function testRefusesANarrowingThatKeepsNothing(\Closure $build, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $build();
    }

    /**
     * Narrowing the references again keeps those given that were held, and a
     * reference given twice counts once.
     *
     * @return void
     */
    public function testNarrowingTheReferencesKeepsTheIntersection(): void
    {
        $scope = HoldScope::all()
            ->about(Reference::of('user', '1'), Reference::of('user', '2'), Reference::of('user', '2'))
            ->about(Reference::of('user', '2'), Reference::of('user', '3'));

        self::assertSame([['user', '2']], $scope->toArray()['about']);
    }

    /**
     * The canonical form sorts tenants and references by type then id, and
     * categories bytewise, each once, so scopes built in any order have the
     * same form and digest; the digest is the SHA-256 of its canonical
     * encoding.
     *
     * @return void
     */
    public function testTheCanonicalFormIsSortedAndStable(): void
    {
        $one = HoldScope::tenants(Reference::of('team', 'b'), Reference::of('organisation', 'z'), Reference::of('organisation', 'a'))
            ->withTenantless()
            ->about(Reference::of('user', '9'), Reference::of('invoice', '10'), Reference::of('user', '10'))
            ->categories('security', 'audit', 'finance', 'audit')
            ->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-12-01 00:00:00.000000'))
            ->importBatch(self::BATCH);

        $two = HoldScope::tenants(Reference::of('organisation', 'a'), Reference::of('team', 'b'), Reference::of('organisation', 'z'), Reference::of('team', 'b'))
            ->importBatch(self::BATCH)
            ->categories('finance', 'security', 'audit')
            ->occurredBetween(self::instant('2026-11-01 00:00:00.000000'), self::instant('2026-12-01 00:00:00.000000'))
            ->about(Reference::of('user', '10'), Reference::of('user', '9'), Reference::of('invoice', '10'))
            ->withTenantless();

        $form = [
            'v'            => 1,
            'tenants'      => [['organisation', 'a'], ['organisation', 'z'], ['team', 'b']],
            'tenantless'   => true,
            'about'        => [['invoice', '10'], ['user', '10'], ['user', '9']],
            'categories'   => ['audit', 'finance', 'security'],
            'from'         => '2026-11-01T00:00:00.000000Z',
            'to'           => '2026-12-01T00:00:00.000000Z',
            'import_batch' => self::BATCH,
        ];

        self::assertSame($form, $one->toArray());
        self::assertSame($form, $two->toArray());
        self::assertSame(hash('sha256', CanonicalEncoder::encode($form)), $one->digest());
        self::assertSame($one->digest(), $two->digest());
        self::assertNotSame($one->digest(), HoldScope::all()->digest());
    }

    /**
     * The canonical forms of the three starting points.
     *
     * @return void
     */
    public function testTheStartingPointsCanonicalForms(): void
    {
        $open = ['about' => null, 'categories' => null, 'from' => null, 'to' => null, 'import_batch' => null];

        self::assertSame(['v' => 1, 'tenants' => null, 'tenantless' => true, ...$open], self::ordered(HoldScope::all()->toArray()));
        self::assertSame(['v' => 1, 'tenants' => [], 'tenantless' => true, ...$open], self::ordered(HoldScope::tenantless()->toArray()));
        $tenant = HoldScope::tenants(Reference::of('organisation', 'org_01'));

        self::assertSame(['v' => 1, 'tenants' => [['organisation', 'org_01']], 'tenantless' => false, ...$open], self::ordered($tenant->toArray()));
    }

    /**
     * Rows of `[scope]`: every starting point and every dimension.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope}>
     */
    public static function provideScopes(): iterable
    {
        yield from [
            'every entry'           => [HoldScope::all()],
            'no tenant'             => [HoldScope::tenantless()],
            'tenants'               => [HoldScope::tenants(Reference::of('organisation', 'org_01'), Reference::of('team', 'b'))],
            'tenants and no tenant' => [HoldScope::tenants(Reference::of('organisation', 'org_01'))->withTenantless()],
            'about'                 => [HoldScope::all()->about(Reference::of('user', '42'))],
            'categories'            => [HoldScope::all()->categories('finance', 'audit')],
            'a window'              => [HoldScope::all()->occurredBetween(self::instant('2026-11-01 00:00:00.000001'), self::instant('2026-11-02 00:00:00.000000'))],
            'an open start'         => [HoldScope::all()->occurredBetween(null, self::instant('2026-11-02 00:00:00.000000'))],
            'an open end'           => [HoldScope::all()->occurredBetween(self::instant('2026-11-02 00:00:00.000000'), null)],
            'an import batch'       => [HoldScope::tenantless()->importBatch(self::BATCH)],
        ];
    }

    /**
     * A scope's canonical form, encoded and decoded as the journal stores it,
     * reads back as the same scope.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return void
     */
    #[DataProvider('provideScopes')]
    public function testFromArrayRoundTrips(HoldScope $scope): void
    {
        $stored = json_decode(CanonicalEncoder::encode($scope->toArray()), true, 64, JSON_THROW_ON_ERROR);

        self::assertIsArray($stored);

        $read = HoldScope::fromArray($stored);

        self::assertSame($scope->toArray(), $read->toArray());
        self::assertSame($scope->digest(), $read->digest());
    }

    /**
     * Rows of `[the keys to change, the key the refusal names]`: each way a
     * stored form departs from the canonical one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedForms(): iterable
    {
        $many = array_map(static fn (int $index): array => ['user', (string) $index], range(1, 101));

        yield from [
            'another version'               => [['v' => 2], 'v'],
            'the version as text'           => [['v' => '1'], 'v'],
            'tenants that are a map'        => [['tenants' => ['a' => ['organisation', 'a']]], 'tenants'],
            'tenants that are text'         => [['tenants' => 'organisation'], 'tenants'],
            'a tenant of three parts'       => [['tenants' => [['organisation', 'a', 'b']]], 'tenants'],
            'a tenant whose id is a number' => [['tenants' => [['organisation', 1]]], 'tenants'],
            'a tenant of an empty type'     => [['tenants' => [['', 'a']]], 'tenants'],
            'tenants out of order'          => [['tenants' => [['team', 'b'], ['organisation', 'a']], 'tenantless' => false], 'tenants'],
            'a tenant twice'                => [['tenants' => [['organisation', 'a'], ['organisation', 'a']], 'tenantless' => false], 'tenants'],
            'too many tenants'              => [['tenants' => $many, 'tenantless' => false], 'tenants'],
            'no tenant, none tenantless'    => [['tenants' => [], 'tenantless' => false], 'tenantless'],
            'every tenant, none tenantless' => [['tenantless' => false], 'tenantless'],
            'tenantless as text'            => [['tenantless' => 'true'], 'tenantless'],
            'about of no reference'         => [['about' => []], 'about'],
            'about out of order'            => [['about' => [['user', '2'], ['user', '1']]], 'about'],
            'categories of none'            => [['categories' => []], 'categories'],
            'categories out of order'       => [['categories' => ['security', 'audit']], 'categories'],
            'a category in upper case'      => [['categories' => ['Audit']], 'categories'],
            'a category that is a number'   => [['categories' => [1]], 'categories'],
            'categories that are text'      => [['categories' => 'audit'], 'categories'],
            'a start in storage form'       => [['from' => '2026-11-01 00:00:00.000000'], 'from'],
            'an end that is a number'       => [['to' => 20261101], 'to'],
            'a backward window'             => [['from' => '2026-11-02T00:00:00.000000Z', 'to' => '2026-11-01T00:00:00.000000Z'], 'to'],
            'a batch in upper case'         => [['import_batch' => strtoupper(self::BATCH)], 'import_batch'],
            'a batch that is a number'      => [['import_batch' => 1], 'import_batch'],
        ];
    }

    /**
     * Each departure from the canonical form is refused, naming the key and
     * never its value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMalformedForms')]
    public function testFromArrayRefusesAMalformedKey(array $changes, string $key): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage("A stored hold scope's `{$key}` is malformed.");

        HoldScope::fromArray(array_replace(HoldScope::all()->toArray(), $changes));
    }

    /**
     * A stored form missing a key is refused naming the key, and one holding a
     * key it does not define is refused without naming it.
     *
     * @return void
     */
    public function testFromArrayRefusesAMissingOrAnUnknownKey(): void
    {
        $form = HoldScope::all()->toArray();

        foreach (array_keys($form) as $key) {
            $without = $form;

            unset($without[$key]);

            try {
                HoldScope::fromArray($without);

                self::fail("Expected a form without `{$key}` to be refused.");
            } catch (\UnexpectedValueException $exception) {
                self::assertSame("A stored hold scope's `{$key}` is malformed.", $exception->getMessage());
            }
        }

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored hold scope holds a key it does not define.');

        HoldScope::fromArray([...$form, 'owner' => null]);
    }

    /**
     * Every row a scope is tested against, by what it is: an entry of a tenant
     * by a user on an invoice, one of no tenant, one of no actor, one of
     * another time and one of an import batch.
     *
     * @return array<string, array<string, int|string|null>>
     */
    private static function rows(): array
    {
        return [
            'an entry of a tenant'      => self::row(),
            'an entry of no tenant'     => self::row(['tenant_type' => null, 'tenant_id' => null]),
            'an entry of no actor'      => self::row(['actor_type' => null, 'actor_id' => null]),
            'an entry of another time'  => self::row(['occurred_at' => '1999-12-31 23:59:59.999999']),
            'an entry of an import'     => self::row(['import_batch_id' => self::BATCH]),
            'an entry of an odd tenant' => self::row(['tenant_type' => 'organisation', 'tenant_id' => null]),
        ];
    }

    /**
     * A stored entry row: by a user on an invoice of an organisation, in the
     * finance category, at noon on the first of November, of no batch, with the
     * columns given replacing those.
     *
     * @param  array<string, int|string|null>  $columns
     * @return array<string, int|string|null>
     */
    private static function row(array $columns = []): array
    {
        return array_replace([
            'id'              => '01932b4e-a000-7000-8000-000000000001',
            'category'        => 'finance',
            'actor_type'      => 'user',
            'actor_id'        => '42',
            'subject_type'    => 'invoice',
            'subject_id'      => 'inv_0042',
            'tenant_type'     => 'organisation',
            'tenant_id'       => 'org_01',
            'import_batch_id' => null,
            'occurred_at'     => '2026-11-01 12:00:00.000000',
        ], $columns);
    }

    /**
     * The stored time as an instant in UTC.
     *
     * @param  string  $stored
     * @return \Carbon\CarbonImmutable
     */
    private static function instant(string $stored): CarbonImmutable
    {
        return new CarbonImmutable($stored, 'UTC');
    }

    /**
     * The canonical form with its keys in the order the comparison lists them.
     *
     * @param  array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>  $form
     * @return array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>
     */
    private static function ordered(array $form): array
    {
        $keys = ['v', 'tenants', 'tenantless', 'about', 'categories', 'from', 'to', 'import_batch'];

        return array_replace(array_fill_keys($keys, null), $form);
    }
}
