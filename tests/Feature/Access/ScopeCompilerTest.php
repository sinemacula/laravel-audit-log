<?php

declare(strict_types = 1);

namespace Tests\Feature\Access;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\Position;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\TestCase;

/**
 * Feature tests for the one compiler of every read: the statement it builds on
 * the storage connection, read with `toSql()` and `getBindings()`, with the
 * grammar's identifier quotes taken out so it reads the same on every engine.
 *
 * The compiled form is tenant AND category AND about AND the caller's filters
 * AND the cursor, every internal `or` grouped, references as exact pairs, the
 * tenantless rows as both columns `null`, times bound with six fractional
 * digits, the prefix through an explicit `like` with its own escape, no
 * collation, and nothing the caller gives in the SQL text. A denied scope is
 * refused, an empty one is known without a query, and an entry is looked up
 * under the scope like any other read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeCompiler::class)]
final class ScopeCompilerTest extends TestCase
{
    /** @var string An entry id. */
    private const string ID = '0192f5a0-7c1e-7000-8000-00000000000a';

    /** @var string Another entry id. */
    private const string OTHER_ID = '0192f5a0-7c1e-7000-8000-00000000000b';

    /** @var string A value a caller gives that must never become SQL text. */
    private const string HOSTILE = 'x\' or 1=1 -- ) or (';

    /**
     * A scope of tenants and the tenantless rows, only some categories and one
     * about-reference, with filters on every dimension and a cursor, compiles
     * to tenant AND category AND about AND the filters AND the cursor, in that
     * order, with every value bound in the same order.
     *
     * @return void
     */
    public function testTheCompiledFormIsTenantAndCategoryAndAboutAndFiltersAndCursor(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '2'))
            ->withTenantless()
            ->onlyCategories('billing', 'auth')
            ->onlyAbout(Reference::of('user', '42'));

        $filters = TrailFilters::none()
            ->withReference('actor', Reference::of('user', '42'))
            ->withReference('principal', Reference::of('service', '9'))
            ->withEventPrefix('invoice.')
            ->withCategories(['billing'])
            ->withOutcomes([Outcome::SUCCESS, Outcome::DENIED])
            ->withWindow(new \DateTimeImmutable('2026-11-01T00:00:00Z'), new \DateTimeImmutable('2026-11-02T00:00:00.5Z'))
            ->withCorrelation('app:ticket-123');

        $compiler = new ScopeCompiler;
        $query    = $compiler->before($compiler->apply(self::entries(), $scope, $filters), new Position('2026-11-01T12:00:00.123456Z', self::ID));

        $where = '((tenant_type = ? and tenant_id = ?) or (tenant_type = ? and tenant_id = ?) or (tenant_type is null and tenant_id is null))'
            . ' and category in (?, ?)'
            . ' and ((actor_type = ? and actor_id = ?) or (subject_type = ? and subject_id = ?))'
            . ' and actor_type = ? and actor_id = ? and principal_type = ? and principal_id = ?'
            . ' and event like ? escape \'!\' and category in (?) and outcome in (?, ?)'
            . ' and occurred_at >= ? and occurred_at < ? and correlation_id = ?'
            . ' and (occurred_at <= ? and (occurred_at < ? or (occurred_at = ? and id < ?)))';

        self::assertSame('select * from audit_log_entries where ' . $where, self::sqlOf($query));
        self::assertSame([
            'team', '1', 'team', '2',
            'auth', 'billing',
            'user', '42', 'user', '42',
            'user', '42', 'service', '9',
            'invoice.%', 'billing', 'denied', 'success',
            '2026-11-01 00:00:00.000000', '2026-11-02 00:00:00.500000', 'app:ticket-123',
            '2026-11-01 12:00:00.123456', '2026-11-01 12:00:00.123456', '2026-11-01 12:00:00.123456', self::ID,
        ], $query->getBindings());
    }

    /**
     * A scope of every row and filters that narrow nothing add no condition at
     * all.
     *
     * @return void
     */
    public function testAScopeOfEveryRowAddsNothing(): void
    {
        $query = (new ScopeCompiler)->apply(self::entries(), AccessScope::all(), TrailFilters::none());

        self::assertSame('select * from audit_log_entries', self::sqlOf($query));
        self::assertSame([], $query->getBindings());
    }

    /**
     * Every `or` the compiler writes is inside a group of its own, so a caller
     * filter after a scope of several tenants and several about-references sits
     * outside the tenant group and cannot widen it.
     *
     * @return void
     */
    public function testEveryInternalOrIsGrouped(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '2'), Reference::of('org', '3'))
            ->withTenantless()
            ->exceptCategories('auth')
            ->onlyAbout(Reference::of('user', '1'), Reference::of('user', '2'));

        $filters = TrailFilters::none()->withReference('actor', Reference::of('user', '1'))->withEvents(['invoice.approved', 'invoice.voided']);

        $compiler = new ScopeCompiler;
        $query    = $compiler->apply(self::entries(), $scope, $filters);
        $compiler->before($query, new Position('2026-11-01T12:00:00.000000Z', self::ID));
        $compiler->after($query, new Position('2026-11-01T11:00:00.000000Z', self::ID), new Position('2026-11-01T13:00:00.000000Z', self::OTHER_ID));

        $sql = self::sqlOf($query);

        self::assertSame(0, self::topLevelOrs($sql));
        self::assertSame(1, self::topLevelOrs('select * from t where a = ? or (b = ? or c = ?)'));
        self::assertStringContainsString('or (tenant_type is null and tenant_id is null)) and category not in (?) and (', $sql);
        self::assertStringContainsString('or (subject_type = ? and subject_id = ?)) and actor_type = ? and actor_id = ? and event in (?, ?)', $sql);
    }

    /**
     * The tenantless rows are those with both tenant columns `null`, as one
     * pair inside the tenant group.
     *
     * @return void
     */
    public function testTenantlessMeansBothColumnsNull(): void
    {
        $query = (new ScopeCompiler)->apply(self::entries(), AccessScope::tenants(Reference::of('team', '1'))->withTenantless(), TrailFilters::none());

        self::assertSame('select * from audit_log_entries where ((tenant_type = ? and tenant_id = ?) or (tenant_type is null and tenant_id is null))', self::sqlOf($query));
        self::assertSame(['team', '1'], $query->getBindings());
    }

    /**
     * The page cursor takes the entries strictly after the position in
     * newest-first order, as one group led by the bound on the time it implies.
     *
     * @return void
     */
    public function testTheCursorPredicateIsStrictAndGrouped(): void
    {
        $query = (new ScopeCompiler)->before(self::entries(), new Position('2026-11-01T12:00:00.000001Z', self::ID));

        self::assertSame('select * from audit_log_entries where (occurred_at <= ? and (occurred_at < ? or (occurred_at = ? and id < ?)))', self::sqlOf($query));
        self::assertSame(['2026-11-01 12:00:00.000001', '2026-11-01 12:00:00.000001', '2026-11-01 12:00:00.000001', self::ID], $query->getBindings());
    }

    /**
     * An export's keyset takes the entries strictly after the position when
     * there is one, and always those up to the bound inclusive, each as one
     * group, in recording order.
     *
     * @return void
     */
    public function testTheExportKeysetIsBoundedAndGrouped(): void
    {
        $compiler = new ScopeCompiler;
        $bound    = new Position('2026-11-01T13:00:00.000000Z', self::OTHER_ID);

        $first = $compiler->after(self::entries(), null, $bound);

        self::assertSame('select * from audit_log_entries where (recorded_at < ? or (recorded_at = ? and id <= ?))', self::sqlOf($first));
        self::assertSame(['2026-11-01 13:00:00.000000', '2026-11-01 13:00:00.000000', self::OTHER_ID], $first->getBindings());

        $next = $compiler->after(self::entries(), new Position('2026-11-01T12:00:00.250000Z', self::ID), $bound);

        self::assertSame(
            'select * from audit_log_entries where (recorded_at > ? or (recorded_at = ? and id > ?)) and (recorded_at < ? or (recorded_at = ? and id <= ?))',
            self::sqlOf($next),
        );
        self::assertSame(
            ['2026-11-01 12:00:00.250000', '2026-11-01 12:00:00.250000', self::ID, '2026-11-01 13:00:00.000000', '2026-11-01 13:00:00.000000', self::OTHER_ID],
            $next->getBindings(),
        );
    }

    /**
     * Every time is bound in UTC with six fractional digits, a whole second and
     * a time zone's offset included.
     *
     * @return void
     */
    public function testTimesAreBoundWithSixFractionalDigits(): void
    {
        $filters = TrailFilters::none()->withWindow(
            new \DateTimeImmutable('2026-11-01T13:00:00', new \DateTimeZone('Europe/Paris')),
            new \DateTimeImmutable('2026-11-01T12:00:01.1Z'),
        );

        $query = (new ScopeCompiler)->apply(self::entries(), AccessScope::all(), $filters);

        self::assertSame(['2026-11-01 12:00:00.000000', '2026-11-01 12:00:01.100000'], $query->getBindings());

        foreach ($query->getBindings() as $binding) {
            self::assertMatchesRegularExpression('/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}\z/', $binding);
        }
    }

    /**
     * A prefix is bound as its escaped pattern in an explicit `like` with the
     * `!` escape, never the framework's `like`, which a case-sensitive SQLite
     * turns into `glob`.
     *
     * @return void
     */
    public function testThePrefixIsBoundWithAnExplicitEscape(): void
    {
        $query = (new ScopeCompiler)->apply(self::entries(), AccessScope::all(), TrailFilters::none()->withEventPrefix('app.a_b.'));

        self::assertSame('select * from audit_log_entries where event like ? escape \'!\'', self::sqlOf($query));
        self::assertSame(['app.a!_b.%'], $query->getBindings());
        self::assertStringNotContainsStringIgnoringCase('glob', $query->toSql());
        self::assertSame('!', ScopeCompiler::LIKE_ESCAPE);
    }

    /**
     * Rows of `[prefix, pattern]`: each character `like` treats specially, the
     * escape character itself among them, escaped, then `%`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideLikePatterns(): iterable
    {
        yield from [
            'nothing special'      => ['app.', 'app.%'],
            'an underscore'        => ['app.a_b.', 'app.a!_b.%'],
            'a percent sign'       => ['a%b', 'a!%b%'],
            'the escape character' => ['a!b', 'a!!b%'],
            'an escaped sequence'  => ['!_', '!!!_%'],
            'every one together'   => ['a!%_b', 'a!!!%!_b%'],
            'empty'                => ['', '%'],
        ];
    }

    /**
     * The pattern escapes `!`, `%` and `_` with `!`, the escape character first
     * so an escape is never read as another's.
     *
     * @param  string  $prefix
     * @param  string  $pattern
     * @return void
     */
    #[DataProvider('provideLikePatterns')]
    public function testTheLikePatternEscapesItsOwnCharacters(string $prefix, string $pattern): void
    {
        self::assertSame($pattern, ScopeCompiler::likePattern($prefix));
    }

    /**
     * No collation is ever applied, whatever the scope, filters and cursor.
     *
     * @return void
     */
    public function testNoCollationIsApplied(): void
    {
        $compiler = new ScopeCompiler;
        $scope    = AccessScope::tenants(Reference::of('team', '1'))->withTenantless()->exceptCategories('auth')->onlyAbout(Reference::of('user', '1'));
        $filters  = TrailFilters::none()->withReference('subject', Reference::of('invoice', '1'))->withEventPrefix('invoice.')->withCorrelation('app:x');

        $query = $compiler->before($compiler->apply(self::entries(), $scope, $filters), new Position('2026-11-01T12:00:00.000000Z', self::ID));
        $entry = $compiler->entry(self::entries(), $scope, self::ID);
        $keys  = $compiler->after(self::entries(), new Position('2026-11-01T12:00:00.000000Z', self::ID), new Position('2026-11-01T13:00:00.000000Z', self::ID));

        foreach ([$query, $entry, $keys] as $built) {
            self::assertStringNotContainsStringIgnoringCase('collate', $built->toSql());
        }
    }

    /**
     * A denied scope is never compiled, nor an entry looked up under one: the
     * caller checks `isEmpty()` first.
     *
     * @return void
     */
    public function testADeniedScopeIsRefused(): void
    {
        $refusals = [
            'a read'   => static fn (): Builder => (new ScopeCompiler)->apply(self::entries(), AccessScope::none(), TrailFilters::none()),
            'an entry' => static fn (): Builder => (new ScopeCompiler)->entry(self::entries(), AccessScope::all()->onlyAbout(), self::ID),
        ];

        foreach ($refusals as $label => $refusal) {
            try {
                $refusal();

                self::fail("Expected {$label} to be refused.");
            } catch (\LogicException $exception) {
                self::assertSame('A denied access scope is never compiled into a statement; check isEmpty() first.', $exception->getMessage(), $label);
            }
        }
    }

    /**
     * Rows of `[scope, filters, whether nothing can match]`: each way a scope
     * and filters are disjoint, and the controls that are not.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Access\AccessScope, 1: \SineMacula\Laravel\AuditLog\Querying\TrailFilters, 2: bool}>
     */
    public static function provideScopesAndFilters(): iterable
    {
        $t1      = Reference::of('team', '1');
        $t2      = Reference::of('team', '2');
        $u1      = Reference::of('user', '1');
        $u2      = Reference::of('user', '2');
        $none    = TrailFilters::none();
        $invoice = Reference::of('invoice', '1');

        yield from [
            'denied'                              => [AccessScope::none(), $none, true],
            'a tenant outside the listed tenants' => [AccessScope::tenants($t1)->withTenantless(), $none->withReference('tenant', $t2), true],
            'a tenant among the listed tenants'   => [AccessScope::tenants($t1, $t2), $none->withReference('tenant', $t2), false],
            'a tenant under every tenant'         => [AccessScope::all(), $none->withReference('tenant', $t2), false],
            'a type matching but not the pair'    => [AccessScope::tenants($t1), $none->withReference('tenant', Reference::of('team', '2')), true],
            'categories all outside only'         => [AccessScope::all()->onlyCategories('auth'), $none->withCategories(['billing', 'audit']), true],
            'one category inside only'            => [AccessScope::all()->onlyCategories('auth'), $none->withCategories(['billing', 'auth']), false],
            'categories all excepted'             => [AccessScope::all()->exceptCategories('billing', 'audit'), $none->withCategories(['billing', 'audit']), true],
            'one category not excepted'           => [AccessScope::all()->exceptCategories('billing'), $none->withCategories(['billing', 'auth']), false],
            'no category filter under only'       => [AccessScope::all()->onlyCategories('auth'), $none, false],
            'an actor and subject outside about'  => [AccessScope::all()->onlyAbout($u1), $none->withReference('actor', $u2)->withReference('subject', $invoice), true],
            'the actor inside about'              => [AccessScope::all()->onlyAbout($u1), $none->withReference('actor', $u1)->withReference('subject', $u2), false],
            'the subject inside about'            => [AccessScope::all()->onlyAbout($u1), $none->withReference('actor', $u2)->withReference('subject', $u1), false],
            'only an actor outside about'         => [AccessScope::all()->onlyAbout($u1), $none->withReference('actor', $u2), false],
            'only a subject outside about'        => [AccessScope::all()->onlyAbout($u1), $none->withReference('subject', $u2), false],
            'an actor and subject with no about'  => [AccessScope::all(), $none->withReference('actor', $u2)->withReference('subject', $u2), false],
            'every row'                           => [AccessScope::all(), $none, false],
        ];
    }

    /**
     * Whether nothing can match is answered from the scope and the filters
     * alone, and no statement is run to answer it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  bool  $empty
     * @return void
     */
    #[DataProvider('provideScopesAndFilters')]
    public function testIsEmpty(AccessScope $scope, TrailFilters $filters, bool $empty): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->enableQueryLog();
        $connection->flushQueryLog();

        self::assertSame($empty, (new ScopeCompiler)->isEmpty($scope, $filters));
        self::assertSame([], $connection->getQueryLog());
    }

    /**
     * What a caller gives, in a reference or a correlation id, is bound and
     * never written into the SQL text; only the compiler's own columns,
     * operators and escape character are.
     *
     * @return void
     */
    public function testNothingTheCallerGivesBecomesSqlText(): void
    {
        $hostile = Reference::of(self::HOSTILE, self::HOSTILE);

        $filters = TrailFilters::none()
            ->withReference('actor', $hostile)
            ->withReference('subject', $hostile)
            ->withReference('principal', $hostile)
            ->withReference('tenant', $hostile)
            ->withCorrelation('app:' . self::HOSTILE);

        $compiler = new ScopeCompiler;
        $query    = $compiler->apply(self::entries(), AccessScope::tenants($hostile)->onlyAbout($hostile), $filters);

        self::assertStringNotContainsString(self::HOSTILE, $query->toSql());
        self::assertStringNotContainsString('1=1', $query->toSql());
        self::assertContains(self::HOSTILE, $query->getBindings());
        self::assertContains('app:' . self::HOSTILE, $query->getBindings());
        self::assertCount(substr_count($query->toSql(), '?'), $query->getBindings());
    }

    /**
     * An entry is looked up by its id under the scope, so an entry outside the
     * scope is never found, and one inside it is.
     *
     * @return void
     */
    public function testAnEntryIsLookedUpUnderTheScope(): void
    {
        self::insert(self::ID, 'team', '1');
        self::insert(self::OTHER_ID, 'team', '2');

        $compiler = new ScopeCompiler;
        $scope    = AccessScope::tenants(Reference::of('team', '1'));

        $query = $compiler->entry(self::entries(), $scope, self::OTHER_ID);

        self::assertSame('select * from audit_log_entries where ((tenant_type = ? and tenant_id = ?)) and id = ?', self::sqlOf($query));
        self::assertSame(['team', '1', self::OTHER_ID], $query->getBindings());
        self::assertNull($query->first());
        self::assertSame(self::ID, $compiler->entry(self::entries(), $scope, self::ID)->value('id'));
        self::assertSame(self::OTHER_ID, $compiler->entry(self::entries(), AccessScope::all(), self::OTHER_ID)->value('id'));
    }

    /**
     * Rows of `[id]`: ids that are not a lower-case UUID.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedIds(): iterable
    {
        yield from [
            'upper case'  => [strtoupper(self::ID)],
            'no hyphens'  => [str_replace('-', '', self::ID)],
            'a line feed' => [self::ID . "\n"],
            'a prefix'    => ['x' . self::ID],
            'a wildcard'  => ['%'],
            'empty'       => [''],
        ];
    }

    /**
     * An entry's id must be a lower-case UUID, refused before anything is added
     * to the query.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideMalformedIds')]
    public function testAnEntryIdMustBeAUuid(string $id): void
    {
        $query = self::entries();

        try {
            (new ScopeCompiler)->entry($query, AccessScope::tenants(Reference::of('team', '1')), $id);

            self::fail('Expected the id to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An entry is looked up by its id, a lower-case UUID.', $exception->getMessage());
        }

        self::assertSame('select * from audit_log_entries', self::sqlOf($query));
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

    /**
     * The query's SQL with the grammar's identifier quotes taken out, so it
     * reads the same on every engine.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return string
     */
    private static function sqlOf(Builder $query): string
    {
        return str_replace(['"', '`'], '', $query->toSql());
    }

    /**
     * How many `or`s of the SQL's conditions are outside every bracket.
     *
     * @param  string  $sql
     * @return int
     */
    private static function topLevelOrs(string $sql): int
    {
        $depth = 0;
        $found = 0;
        $where = (string) strstr($sql, ' where ');

        foreach (preg_split('/(\(|\)| or )/', $where, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY) ?: [] as $part) {
            $depth += match ($part) {
                '('     => 1,
                ')'     => -1,
                default => 0,
            };

            $found += $part === ' or ' && $depth === 0 ? 1 : 0;
        }

        return $found;
    }

    /**
     * Insert an entry of the id in the tenant.
     *
     * @param  string  $id
     * @param  string  $tenantType
     * @param  string  $tenantId
     * @return void
     */
    private static function insert(string $id, string $tenantType, string $tenantId): void
    {
        self::entries()->insert([
            'id'                => $id,
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'general',
            'outcome'           => 'success',
            'tenant_type'       => $tenantType,
            'tenant_id'         => $tenantId,
            'provenance'        => 'native',
            'source_id'         => 'app',
            'occurred_at'       => '2026-11-01 12:00:00.000000',
            'recorded_at'       => '2026-11-01 12:00:00.000000',
            'integrity_version' => 1,
            'key_id'            => 'k1',
            'hmac'              => str_repeat('0', 64),
        ]);
    }
}
