<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\Engine\Mt19937;
use Random\Randomizer;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Integration tests for the plans each engine chooses for a page of the trail,
 * on whichever engine the suite runs against: a read narrowed on one dimension
 * reads that dimension's index in the page's order, `occurred_at` then `id`,
 * both descending, and sorts nothing, the first page and a page after a cursor
 * alike; a read that combines conditions uses an index of the table and filters
 * the rest of its conditions row by row.
 *
 * Each plan is of the very statement the trail runs: a page of 50 is read
 * through `AuditTrail` for a viewer the policy gives the scope, after a page
 * read the same way when a cursor is wanted, and its one select of the entries
 * table is captured as the engine ran it, with its bindings, so a change to the
 * columns, the order, the limit or the clauses the reader adds is a change to
 * what is explained. The plan is the engine's own: `EXPLAIN QUERY PLAN` on
 * SQLite, `EXPLAIN
 * FORMAT=JSON` on MySQL and `EXPLAIN (FORMAT JSON)` on PostgreSQL, read after
 * 2,000 rows over 20 tenants, 10 actors and 30 codes are stored in the order
 * they occurred and the table is analysed, so the planner chooses from the
 * table's own statistics.
 *
 * Marked `#[CoversNothing]` because a migration's indexes and the planner's
 * choices are not code PHPUnit can attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class TrailPlansTest extends TestCase
{
    use ReadsTheTrail;

    /** @var int How many rows are stored. */
    private const int ROWS = 2000;

    /** @var int How many entries a page shows; the read asks for one more. */
    private const int PER_PAGE = 50;

    /** @var int The instant the first row occurred at, as a Unix timestamp: 2026-11-01T00:00:00Z. */
    private const int FIRST = 1793491200;

    /** @var int The seed the rows' actors, subjects, principals and codes are drawn with, so every run stores the same rows. */
    private const int SEED = 2026;

    /** @var array<string, array{0: int, 1: string}> How many of each reference the rows are spread over, with the reference's type. */
    private const array SPREAD = [
        'actor'     => [10, 'user'],
        'subject'   => [50, 'invoice'],
        'principal' => [10, 'user'],
    ];

    /** @var int How many codes the rows are spread over; each code's category is its number modulo ten. */
    private const int CODES = 30;

    /**
     * Bind the read path, store the rows and analyse the table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();

        $randomizer = new Randomizer(new Mt19937(self::SEED));
        $rows       = [];

        for ($number = 0; $number < self::ROWS; $number++) {
            $rows[] = self::row($number, $randomizer);
        }

        foreach (array_chunk($rows, 200) as $chunk) {
            self::entries()->insert($chunk);
        }

        self::analyse(self::connection());
    }

    /**
     * A page of one tenant's entries reads the tenant index, and the read is a
     * full page with its look-ahead row.
     *
     * @return void
     */
    public function testASingleTenantReadUsesTheTenantIndex(): void
    {
        $statement = $this->page(AccessScope::tenants(Reference::of('team', '4')), static fn (AuditTrail $trail): AuditTrail => $trail);
        $plan      = self::plan($statement);

        self::assertContains(self::index('_tenant_index'), $plan['indexes'], $plan['text']);
        self::assertCount(self::PER_PAGE + 1, self::rowsOf($statement));
    }

    /**
     * A page of one actor's entries, under a scope of every tenant, reads the
     * actor index, and the read is a full page with its look-ahead row.
     *
     * @return void
     */
    public function testAnActorReadUsesTheActorIndex(): void
    {
        $statement = $this->page(AccessScope::all(), static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '3')));
        $plan      = self::plan($statement);

        self::assertContains(self::index('_actor_index'), $plan['indexes'], $plan['text']);
        self::assertCount(self::PER_PAGE + 1, self::rowsOf($statement));
    }

    /**
     * A page of one code's entries, under a scope of every tenant, reads the
     * event index, and the read is a full page with its look-ahead row.
     *
     * @return void
     */
    public function testAnEventReadUsesTheEventIndex(): void
    {
        $statement = $this->page(AccessScope::all(), static fn (AuditTrail $trail): AuditTrail => $trail->forEvent('trail.event_07'));
        $plan      = self::plan($statement);

        self::assertContains(self::index('_event_index'), $plan['indexes'], $plan['text']);
        self::assertCount(self::PER_PAGE + 1, self::rowsOf($statement));
    }

    /**
     * Rows of `[the scope, what narrows the trail, whether the page is read
     * after a first one's cursor, the suffix of the index the read uses]`: each
     * read narrowed on one dimension, the first page and a page after a
     * cursor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Access\AccessScope, 1: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail, 2: bool, 3: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideSingleDimensionReads(): iterable
    {
        $none      = static fn (AuditTrail $trail): AuditTrail => $trail;
        $actor     = static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '3'));
        $principal = static fn (AuditTrail $trail): AuditTrail => $trail->forPrincipal(Reference::of('user', '5'));
        $all       = AccessScope::all();
        $tenant    = AccessScope::tenants(Reference::of('team', '4'));

        yield from [
            'a scope of one tenant'              => [$tenant, $none, false, '_tenant_index'],
            'a scope of one tenant after a page' => [$tenant, $none, true, '_tenant_index'],
            'a tenant filter'                    => [$all, static fn (AuditTrail $trail): AuditTrail => $trail->forTenant(Reference::of('team', '9')), false, '_tenant_index'],
            'an actor'                           => [$all, $actor, false, '_actor_index'],
            'an actor after a page'              => [$all, $actor, true, '_actor_index'],
            'a subject'                          => [$all, static fn (AuditTrail $trail): AuditTrail => $trail->forSubject(Reference::of('invoice', '7')), false, '_subject_index'],
            'a principal'                        => [$all, $principal, false, '_principal_index'],
            'a code'                             => [$all, static fn (AuditTrail $trail): AuditTrail => $trail->forEvent('trail.event_07'), false, '_event_index'],
            'a category'                         => [$all, static fn (AuditTrail $trail): AuditTrail => $trail->inCategory('area_3'), false, '_category_index'],
            'the whole trail'                    => [$all, $none, false, '_occurred_index'],
            'the whole trail after a page'       => [$all, $none, true, '_occurred_index'],
        ];
    }

    /**
     * A page narrowed on one dimension reads that dimension's own index in its
     * order and is never sorted: MySQL uses no filesort, PostgreSQL has no
     * `Sort` node and SQLite builds no temporary B-tree for the order, the page
     * after a cursor included.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $narrow
     * @param  bool  $afterAPage
     * @param  string  $suffix
     * @return void
     */
    #[DataProvider('provideSingleDimensionReads')]
    public function testAPageReadsNoFilesort(AccessScope $scope, \Closure $narrow, bool $afterAPage, string $suffix): void
    {
        $statement = $this->page($scope, $narrow, $afterAPage);
        $plan      = self::plan($statement);

        if ($afterAPage) {
            self::assertMatchesRegularExpression('/occurred_at. < \?/', $statement['sql']);
        }

        self::assertContains(self::index($suffix), $plan['indexes'], $plan['text']);
        self::assertFalse($plan['sorted'], $plan['text']);
    }

    /**
     * A page of one actor's entries under a scope of three tenants and the
     * entries of no tenant uses an index of the table, and returns only that
     * actor's entries in those tenants.
     *
     * No index covers both the tenants and the actor, so the planner reads one
     * index, the actor's, the tenant's over each pair, or the time's, and
     * filters the rest of the conditions row by row: the read costs the rows
     * that index matches, not the rows the page returns, and an engine may sort
     * what it matched. That is the documented cost of a combined read.
     *
     * @return void
     */
    public function testAMultiTenantReadUsesAnIndexAndFiltersTheRest(): void
    {
        $scope     = AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '2'), Reference::of('team', '3'))->withTenantless();
        $statement = $this->page($scope, static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '3')));
        $plan      = self::plan($statement);

        self::assertNotSame([], array_intersect($plan['indexes'], self::tableIndexes()), $plan['text']);

        $rows = self::rowsOf($statement);

        self::assertNotEmpty($rows);

        foreach ($rows as $row) {
            self::assertSame(['user', '3'], [$row['actor_type'], $row['actor_id']]);
            self::assertContains($row['tenant_id'], ['1', '2', '3']);
        }
    }

    /**
     * A page of one code's entries under a scope of one tenant uses an index of
     * the table, and returns only that code's entries in that tenant.
     *
     * Both the tenant index and the event index match, so the planner reads
     * one, whichever its statistics make cheaper, and filters the other's
     * conditions row by row; PostgreSQL may instead combine the two in a bitmap
     * and sort the few rows both match. Either way the read costs the rows one
     * index matches, not the rows the page returns.
     *
     * @return void
     */
    public function testASelectiveFilterUnderATenantScopeUsesOneIndexAndFiltersTheRest(): void
    {
        $statement = $this->page(AccessScope::tenants(Reference::of('team', '5')), static fn (AuditTrail $trail): AuditTrail => $trail->forEvent('trail.event_07'));
        $plan      = self::plan($statement);

        self::assertNotSame([], array_intersect($plan['indexes'], self::tableIndexes()), $plan['text']);

        foreach (self::rowsOf($statement) as $row) {
            self::assertSame(['team', '5', 'trail.event_07'], [$row['tenant_type'], $row['tenant_id'], $row['event']]);
        }
    }

    /**
     * The one select of the entries table the trail runs for a page of 50, as
     * the engine ran it with its bindings: read for a viewer the policy gives
     * the scope, narrowed as given, and, when asked, after the cursor of a
     * first page read the same way.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $narrow
     * @param  bool  $afterAPage
     * @return array{sql: string, bindings: array<array-key, scalar|null>}
     */
    private function page(AccessScope $scope, \Closure $narrow, bool $afterAPage = false): array
    {
        $this->usePolicy(static fn (): AccessScope => $scope);

        $trail  = $narrow(app(AuditTrail::class)->visibleTo($this->viewer()));
        $cursor = null;

        if ($afterAPage) {
            $cursor = $trail->cursorPaginate(self::PER_PAGE)->nextCursor;

            self::assertIsString($cursor, 'The first page has no next page to read after.');
        }

        $this->captureQueries();

        $trail->cursorPaginate(self::PER_PAGE, $cursor);

        $isPage = static fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select') && str_contains($query->sql, 'order by');
        $reads  = array_values(array_filter($this->capturedQueries(), $isPage));

        self::assertCount(1, $reads, 'A page runs one select of the entries.');

        /** @var array<array-key, scalar|null> $bindings */
        $bindings = $reads[0]->bindings;

        return ['sql' => $reads[0]->sql, 'bindings' => $bindings];
    }

    /**
     * The rows the statement returns, run again as it was run, each as an
     * array.
     *
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return list<array<string, scalar|null>>
     */
    private static function rowsOf(array $statement): array
    {
        /** @var list<array<string, scalar|null>> */
        return array_map(static fn (object $row): array => (array) $row, self::connection()->select($statement['sql'], $statement['bindings']));
    }

    /**
     * The plan the engine chooses for the statement: the indexes it reads,
     * whether it sorts, and the plan as the engine gave it, for a failure's
     * message.
     *
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return array{indexes: list<string>, sorted: bool, text: string}
     *
     * @throws \JsonException
     */
    private static function plan(array $statement): array
    {
        $connection = self::connection();
        $driver     = $connection->getDriverName();

        if ($driver === 'sqlite') {
            $rows = $connection->select('EXPLAIN QUERY PLAN ' . $statement['sql'], $statement['bindings']);

            return self::sqlitePlan(array_map(static fn (object $row): string => (string) ((array) $row)['detail'], $rows));
        }

        $explain = $driver === 'mysql' ? 'EXPLAIN FORMAT=JSON ' : 'EXPLAIN (FORMAT JSON) ';
        $text    = array_values((array) $connection->selectOne($explain . $statement['sql'], $statement['bindings']))[0] ?? null;

        self::assertIsString($text);

        $tree = json_decode($text, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($tree, $text);

        return self::jsonPlan($driver, $tree, $text);
    }

    /**
     * The plan MySQL or PostgreSQL gives as JSON: each index a node names, as
     * MySQL's `key` or `index_name` or PostgreSQL's `Index Name`, and whether a
     * node sorts, as MySQL's `using_filesort` or a sort access, or a `Sort` or
     * `Incremental Sort` node of PostgreSQL's.
     *
     * @param  string  $driver
     * @param  array<array-key, array<array-key, bool|float|int|string|null>|bool|float|int|string|null>  $tree
     * @param  string  $text
     * @return array{indexes: list<string>, sorted: bool, text: string}
     */
    private static function jsonPlan(string $driver, array $tree, string $text): array
    {
        $names = $driver === 'mysql' ? ['key', 'index_name'] : ['Index Name'];
        $sorts = $driver === 'mysql'
            ? [['using_filesort', true], ['access_type', 'sort']]
            : [['Node Type', 'Sort'], ['Node Type', 'Incremental Sort']];

        $indexes = [];
        $sorted  = false;

        foreach (new \RecursiveIteratorIterator(new \RecursiveArrayIterator($tree)) as $key => $value) {
            if (in_array($key, $names, true) && is_string($value)) {
                $indexes[] = $value;
            }

            $sorted = $sorted || in_array([$key, $value], $sorts, true);
        }

        return ['indexes' => array_values(array_unique($indexes)), 'sorted' => $sorted, 'text' => $text];
    }

    /**
     * The plan SQLite gives as the details of its steps: each index a step
     * searches or scans, and whether a step builds a temporary B-tree for the
     * order, all of it or a part.
     *
     * @param  list<string>  $details
     * @return array{indexes: list<string>, sorted: bool, text: string}
     */
    private static function sqlitePlan(array $details): array
    {
        $indexes = [];

        foreach ($details as $detail) {
            if (preg_match('/USING (?:COVERING )?INDEX (\S+)/', $detail, $match) !== 1) {
                continue;
            }

            $indexes[] = $match[1];
        }

        return [
            'indexes' => array_values(array_unique($indexes)),
            'sorted'  => preg_grep('/TEMP B-TREE FOR .*ORDER BY/', $details) !== [],
            'text'    => implode("\n", $details),
        ];
    }

    /**
     * Analyse the table, so the planner chooses from the rows just stored.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private static function analyse(Connection $connection): void
    {
        $table = $connection->getQueryGrammar()->wrapTable(EntrySettings::table());

        match ($connection->getDriverName()) {
            'mysql' => $connection->select('ANALYZE TABLE ' . $table),
            'pgsql' => $connection->statement('ANALYZE ' . $table),
            default => $connection->statement('ANALYZE'),
        };
    }

    /**
     * The row of the number: the tenant its number gives, an actor, a subject,
     * a principal and a code drawn from the seeded generator, and a time one
     * second and a fraction after the row before, so the rows are stored in the
     * order they occurred.
     *
     * @param  int  $number
     * @param  \Random\Randomizer  $randomizer
     * @return array<string, int|string>
     */
    private static function row(int $number, Randomizer $randomizer): array
    {
        $references = [];

        foreach (self::SPREAD as $dimension => [$count, $type]) {
            $references[$dimension . '_type'] = $type;
            $references[$dimension . '_id']   = (string) $randomizer->getInt(1, $count);
        }

        $code = $randomizer->getInt(0, self::CODES - 1);
        $time = self::storedTime($number);

        return [
            'id'             => self::id($number),
            'record_version' => 1,
            'event'          => sprintf('trail.event_%02d', $code),
            'event_version'  => 1,
            'category'       => 'area_' . ($code % 10),
            'outcome'        => 'success',
            ...$references,
            'tenant_type'       => 'team',
            'tenant_id'         => (string) ($number % 20 + 1),
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => $time,
            'recorded_at'       => $time,
            'integrity_version' => 1,
            'key_id'            => 'k1',
            'hmac'              => str_repeat('0', 64),
        ];
    }

    /**
     * The id of the row of the number, a lower-case UUID that grows with it.
     *
     * @param  int  $number
     * @return string
     */
    private static function id(int $number): string
    {
        return sprintf('0195f4a2-7b1c-7000-8000-%012x', $number + 1);
    }

    /**
     * The time the row of the number occurred, as it is stored.
     *
     * @param  int  $number
     * @return string
     */
    private static function storedTime(int $number): string
    {
        return gmdate('Y-m-d H:i:s', self::FIRST + $number) . sprintf('.%06d', ($number * 7919) % 1000000);
    }

    /**
     * The name of the table's index of the suffix.
     *
     * @param  string  $suffix
     * @return string
     */
    private static function index(string $suffix): string
    {
        return EntrySettings::table() . $suffix;
    }

    /**
     * The name of every index the migration gives the table.
     *
     * @return list<string>
     */
    private static function tableIndexes(): array
    {
        return array_map(self::index(...), array_keys(TableShape::entries()->indexes));
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function entries(): Builder
    {
        return self::connection()->table(EntrySettings::table());
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
