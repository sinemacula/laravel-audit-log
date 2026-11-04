<?php

declare(strict_types = 1);

namespace Tests\Integration\Access;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\Position;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\TestCase;

/**
 * Integration tests for the one compiler of every read on whichever engine the
 * suite runs against, its statements run on rows the engine stored: a tenant
 * matches as an exact pair, the tenantless rows are those with both tenant
 * columns `null`, a caller's filter cannot reach past a scope of several
 * tenants, ids of one microsecond compare in the type the migration gave them,
 * and an export's keyset visits every row up to its bound exactly once.
 *
 * Rows are seeded with literal inserts of the columns each test is about, so
 * the statements read what the engine stored, not what the package wrote.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeCompiler::class)]
final class ScopeCompilerEnginesTest extends TestCase
{
    /** @var string The time every row occurred and was recorded at unless a test says otherwise. */
    private const string AT = '2026-11-01 12:00:00.000000';

    /**
     * A scope of two tenants sees exactly their two pairs, never the type of
     * one with the id of the other.
     *
     * @return void
     */
    public function testATenantPairIsMatchedExactlyNotByTypeAndIdApart(): void
    {
        self::insert(1, ['tenant_type' => 'team', 'tenant_id' => '1']);
        self::insert(2, ['tenant_type' => 'team', 'tenant_id' => '2']);
        self::insert(3, ['tenant_type' => 'org', 'tenant_id' => '1']);
        self::insert(4, ['tenant_type' => 'org', 'tenant_id' => '2']);

        $scope = AccessScope::tenants(Reference::of('team', '1'), Reference::of('org', '2'));

        self::assertSame([self::id(1), self::id(4)], self::idsUnder($scope, TrailFilters::none()));
    }

    /**
     * The tenantless rows are those with both tenant columns `null`: a row with
     * a type and no id, or an id and no type, is not one of them.
     *
     * @return void
     */
    public function testTenantlessMeansBothColumnsNull(): void
    {
        self::insert(1, ['tenant_type' => 'team', 'tenant_id' => '1']);
        self::insert(2, ['tenant_type' => null, 'tenant_id' => null]);
        self::insert(3, ['tenant_type' => 'team', 'tenant_id' => null]);
        self::insert(4, ['tenant_type' => null, 'tenant_id' => '1']);
        self::insert(5, ['tenant_type' => 'team', 'tenant_id' => '2']);

        $scope = AccessScope::tenants(Reference::of('team', '1'))->withTenantless();

        self::assertSame([self::id(1), self::id(2)], self::idsUnder($scope, TrailFilters::none()));
        self::assertSame([self::id(1)], self::idsUnder(AccessScope::tenants(Reference::of('team', '1')), TrailFilters::none()));
    }

    /**
     * A caller's filter after a scope of several tenants narrows within them
     * and never reaches another tenant's rows, even a filter naming that
     * tenant, which the compiler already knows matches nothing.
     *
     * @return void
     */
    public function testACallerFilterCannotEscapeAMultiTenantScope(): void
    {
        self::insert(1, ['tenant_type' => 'team', 'tenant_id' => '1', 'actor_type' => 'user', 'actor_id' => '1']);
        self::insert(2, ['tenant_type' => 'team', 'tenant_id' => '2', 'actor_type' => 'user', 'actor_id' => '1']);
        self::insert(3, ['tenant_type' => 'team', 'tenant_id' => '3', 'actor_type' => 'user', 'actor_id' => '1']);
        self::insert(4, ['tenant_type' => 'team', 'tenant_id' => '1', 'actor_type' => 'user', 'actor_id' => '2']);

        $scope = AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '2'))->withTenantless();
        $actor = TrailFilters::none()->withReference('actor', Reference::of('user', '1'));

        self::assertSame([self::id(1), self::id(2)], self::idsUnder($scope, $actor));

        $outside = $actor->withReference('tenant', Reference::of('team', '3'));

        self::assertTrue((new ScopeCompiler)->isEmpty($scope, $outside));
        self::assertSame([], self::idsUnder($scope, $outside));
    }

    /**
     * Two rows of one microsecond are ordered by their ids as the migrated
     * column compares them, and the strict cursor after the higher one returns
     * exactly the lower one and the older rows, never itself.
     *
     * @return void
     */
    public function testIdsCompareInTheMigratedTypeOnEveryEngine(): void
    {
        $lower  = '0192f5a0-7c1e-7000-8000-000000000009';
        $higher = '0192f5a0-7c1e-7000-8000-00000000000a';
        $older  = '0192f5a0-7c1e-7000-8000-0000000000ff';

        self::insertRow($higher, ['occurred_at' => '2026-11-01 12:00:00.123456']);
        self::insertRow($lower, ['occurred_at' => '2026-11-01 12:00:00.123456']);
        self::insertRow($older, ['occurred_at' => '2026-11-01 12:00:00.123455']);

        $page = static fn (Builder $query): array => array_values(array_map(strval(...), $query->orderByDesc('occurred_at')->orderByDesc('id')->pluck('id')->all()));

        self::assertSame([$higher, $lower, $older], $page(self::entries()));

        $compiler = new ScopeCompiler;

        self::assertSame([$lower, $older], $page($compiler->before(self::entries(), new Position('2026-11-01T12:00:00.123456Z', $higher))));
        self::assertSame([$older], $page($compiler->before(self::entries(), new Position('2026-11-01T12:00:00.123456Z', $lower))));
        self::assertSame([], $page($compiler->before(self::entries(), new Position('2026-11-01T12:00:00.123455Z', $older))));
    }

    /**
     * Walking an export's keyset in chunks visits every row recorded up to the
     * bound exactly once, in recording order, ties of one microsecond included,
     * and never a row past the bound.
     *
     * @return void
     */
    public function testTheExportKeysetVisitsEveryRowOnce(): void
    {
        $times = ['12:00:00.000001', '12:00:00.000001', '12:00:00.000001', '12:00:00.000002', '12:00:00.500000', '12:00:00.500000', '12:00:01.000000'];

        foreach (range(1, 21) as $index) {
            self::insert($index, ['recorded_at' => '2026-11-01 ' . $times[$index % count($times)]]);
        }

        $all   = self::recordingOrder(self::entries());
        $bound = $all[17];

        self::insert(99, ['recorded_at' => '2026-11-01 12:00:01.000000']);

        $compiler = new ScopeCompiler;
        $visited  = [];
        $position = null;

        do {
            $chunk = self::recordingOrder($compiler->after(self::entries(), $position, $bound)->limit(4));

            array_push($visited, ...$chunk);

            $position = $chunk === [] ? null : $chunk[array_key_last($chunk)];
        } while ($position !== null);

        $pairs = static fn (array $positions): array => array_map(static fn (Position $row): array => $row->toArray(), $positions);

        self::assertSame($pairs(array_slice($all, 0, 18)), $pairs($visited));
        self::assertNotContains(self::id(99), array_map(static fn (Position $row): string => $row->id, $visited));
    }

    /**
     * The ids of the rows the scope and the filters see, in id order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return list<string>
     */
    private static function idsUnder(AccessScope $scope, TrailFilters $filters): array
    {
        $ids = (new ScopeCompiler)->apply(self::entries(), $scope, $filters)->orderBy('id')->pluck('id')->all();

        return array_values(array_map(strval(...), $ids));
    }

    /**
     * The rows of the query in recording order, each as its recorded time and
     * id.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return list<\SineMacula\Laravel\AuditLog\Querying\Position>
     */
    private static function recordingOrder(Builder $query): array
    {
        $positions = [];

        foreach ($query->orderBy('recorded_at')->orderBy('id')->get(['recorded_at', 'id']) as $row) {
            $columns     = (array) $row;
            $positions[] = new Position(StoredTime::fromStorage((string) $columns['recorded_at']), (string) $columns['id']);
        }

        return $positions;
    }

    /**
     * The id of the row of the index.
     *
     * @param  int  $index
     * @return string
     */
    private static function id(int $index): string
    {
        return sprintf('0192f5a0-7c1e-7000-8000-%012x', $index);
    }

    /**
     * Insert the row of the index, with the columns given.
     *
     * @param  int  $index
     * @param  array<string, ?string>  $columns
     * @return void
     */
    private static function insert(int $index, array $columns): void
    {
        self::insertRow(self::id($index), $columns);
    }

    /**
     * Insert a row of the id, with the columns given over a valid row's.
     *
     * @param  string  $id
     * @param  array<string, ?string>  $columns
     * @return void
     */
    private static function insertRow(string $id, array $columns): void
    {
        self::entries()->insert([
            'id'                => $id,
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'general',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => self::AT,
            'recorded_at'       => self::AT,
            'integrity_version' => 1,
            'key_id'            => 'k1',
            'hmac'              => str_repeat('0', 64),
            ...$columns,
        ]);
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }
}
