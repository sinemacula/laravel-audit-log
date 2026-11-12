<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\CursorCodec;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;

/**
 * Feature tests for what a viewer's access scope lets the read API return.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditTrail::class)]
#[CoversClass(TrailReader::class)]
#[CoversClass(ScopeCompiler::class)]
#[CoversClass(CursorCodec::class)]
final class AccessControlTest extends TestCase
{
    use ReadsTheTrail;

    /** @var string The tenant type every seeded entry is in. */
    private const string TENANT_TYPE = 'organisation';

    /** @var array<string, string> The index of each cursor part after the version, by name. */
    private const array CURSOR_PARTS = ['key id' => '1', 'payload' => '2', 'mac' => '3'];

    /**
     * Bind the read path.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
    }

    /**
     * With no policy bound, every read is denied, empty and recorded.
     *
     * @return void
     */
    public function testTheDefaultPolicyReturnsNothing(): void
    {
        $this->seedEntries(3);
        $this->captureQueries();

        $page = $this->financeTrail()->cursorPaginate();

        self::assertInstanceOf(DenyAllPolicy::class, app(AuditAccessPolicy::class));
        self::assertSame([[], null], [$page->entries, $page->nextCursor]);
        self::assertSame(0, $this->financeTrail()->count());
        self::assertSame([], $this->entryReads());

        foreach ($this->readRecords() as $record) {
            self::assertSame(['denied', 'no_scope'], [$record['outcome'], $record['reason']]);
            self::assertSame(DenyAllPolicy::class, self::propertiesOf($record)['policy']);
        }

        self::assertCount(2, $this->readRecords());
    }

    /**
     * A bound policy is asked on every read and named in each record.
     *
     * @return void
     */
    public function testABoundPolicyIsUsed(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::tenants(self::tenant('org_01')));
        $mine   = $this->seedEntry(['tenant_id' => 'org_01']);

        $this->seedEntry(['tenant_id' => 'org_02']);

        self::assertSame([$mine], self::idsOf($this->financeTrail()->cursorPaginate()));
        self::assertSame([$mine], self::idsOf($this->financeTrail()->cursorPaginate()));
        self::assertSame(1, $this->financeTrail()->count());
        self::assertSame([ReadPurpose::READ, ReadPurpose::READ, ReadPurpose::COUNT], array_column($policy->asked(), 1));

        foreach ($this->readRecords() as $record) {
            self::assertSame(ClosurePolicy::class, self::propertiesOf($record)['policy']);
        }
    }

    /**
     * A tenant filter outside the scope reads as nothing, with no query.
     *
     * @return void
     */
    public function testACrossTenantFilterIsEmpty(): void
    {
        $this->allowTenants(self::tenant('org_01'));
        $this->seedEntry(['tenant_id' => 'org_01']);
        $this->seedEntry(['tenant_id' => 'org_02']);
        $this->captureQueries();

        $trail = $this->financeTrail()->forTenant(self::tenant('org_02'));

        self::assertSame([], $trail->cursorPaginate()->entries);
        self::assertSame(0, $trail->count());
        self::assertSame([], $this->entryReads());

        foreach ($this->readRecords() as $record) {
            self::assertSame(['success', 0], [$record['outcome'], self::propertiesOf($record)['returned']]);
        }
    }

    /**
     * A guessed tenant reads exactly as an unknown one, with no query.
     *
     * @return void
     */
    public function testAGuessedTenantGivesTheSameEmptyResultAsAnUnknownOne(): void
    {
        $this->allowTenants(self::tenant('org_01'));
        $this->seedEntry(['tenant_id' => 'org_02']);
        $this->captureQueries();

        $guessed = $this->financeTrail()->forTenant(self::tenant('org_02'));
        $unknown = $this->financeTrail()->forTenant(self::tenant('org_99'));

        self::assertEquals($unknown->cursorPaginate(10), $guessed->cursorPaginate(10));
        self::assertSame($unknown->count(), $guessed->count());
        self::assertSame([], $this->entryReads());

        $records = array_map(
            static fn (array $record): array => [$record['event'], $record['outcome'], $record['reason'], self::propertiesOf($record)['returned']],
            $this->readRecords(),
        );

        self::assertCount(4, $records);
        self::assertSame($records[0], $records[1]);
        self::assertSame($records[2], $records[3]);
    }

    /**
     * A subject id outside the scope reads as one that does not exist.
     *
     * @return void
     */
    public function testAGuessedIdOutsideTheScopeIsNotFound(): void
    {
        $this->allowTenants(self::tenant('org_01'));
        $this->seedEntry(['tenant_id' => 'org_02', 'subject_id' => 'inv_0099']);

        $guessed = $this->financeTrail()->forSubject(Reference::of('invoice', 'inv_0099'));
        $unknown = $this->financeTrail()->forSubject(Reference::of('invoice', 'inv_none'));

        self::assertSame(1, DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('subject_id', 'inv_0099')->count());
        self::assertEquals($unknown->cursorPaginate(), $guessed->cursorPaginate());
        self::assertSame([0, 0], [$guessed->count(), $unknown->count()]);
    }

    /**
     * Rows of `[what narrows the trail]`: filters that might widen a scope.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail}>
     */
    public static function provideEscapingFilters(): iterable
    {
        yield from [
            'an actor'            => [static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '7'))],
            'an actor and a code' => [static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '7'))->forEvent('invoice.approved', 'invoice.voided')],
            'a code prefix'       => [static fn (AuditTrail $trail): AuditTrail => $trail->forEventsUnder('invoice.')],
            'a correlation'       => [static fn (AuditTrail $trail): AuditTrail => $trail->correlatedWith('app:ticket-123')],
        ];
    }

    /**
     * No filter escapes a multi-tenant scope, on any page or in the count.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $narrow
     * @return void
     */
    #[DataProvider('provideEscapingFilters')]
    public function testACallerFilterCannotEscapeAMultiTenantScope(\Closure $narrow): void
    {
        $this->allowTenants(self::tenant('org_01'), self::tenant('org_02'));

        $inScope = [
            $this->seedEntry(self::inTenant('org_01', ['actor_id' => '7']), self::at(0)),
            $this->seedEntry(self::inTenant('org_02', ['actor_id' => '7']), self::at(1)),
        ];

        $this->seedEntry(self::inTenant('org_03', ['actor_id' => '7']), self::at(2));
        $this->seedEntry(self::inTenant(null, ['actor_id' => '7']), self::at(3));

        $trail = $narrow($this->financeTrail());

        self::assertSame(array_reverse($inScope), self::idsOf($trail->cursorPaginate()));
        self::assertSame(array_reverse($inScope), array_merge(...array_map(self::idsOf(...), $this->walk($trail, 1))));
        self::assertCount($trail->count(), $inScope);
    }

    /**
     * A cursor handed to another viewer is refused and recorded as a denial.
     *
     * @return void
     */
    public function testACursorReusedByAnotherViewerIsRefusedAndRecorded(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->nextCursorOf($this->financeTrail()->cursorPaginate(1));
        $other  = app(AuditTrail::class)->visibleTo(Reference::of('App\Models\User', '8'))->inCategory('finance');

        $this->captureQueries();
        $this->assertCursorRefused(static fn () => $other->cursorPaginate(1, $cursor));

        self::assertSame([], $this->entryReads());

        $record = $this->readRecords('audit_log.trail_read')[1];

        self::assertSame(['denied', 'cursor_rejected', 'App\Models\User', '8'], [$record['outcome'], $record['reason'], $record['actor_type'], $record['actor_id']]);
    }

    /**
     * A cursor is refused once the viewer's scope narrows.
     *
     * @return void
     */
    public function testACursorReusedUnderANarrowerScopeIsRefused(): void
    {
        $this->allowTenants(self::tenant('org_01'), self::tenant('org_02'));
        $this->seedEntry(['tenant_id' => 'org_01'], self::at(0));
        $this->seedEntry(['tenant_id' => 'org_02'], self::at(1));

        $cursor = $this->nextCursorOf($this->financeTrail()->cursorPaginate(1));

        $this->allowTenants(self::tenant('org_01'));
        $this->assertCursorRefused(fn () => $this->financeTrail()->cursorPaginate(1, $cursor));
    }

    /**
     * Rows of `[what narrows the trail the cursor is opened on]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail}>
     */
    public static function provideOtherFilters(): iterable
    {
        yield from [
            'a filter added'   => [static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '42'))],
            'a filter removed' => [static fn (): AuditTrail => app(AuditTrail::class)->visibleTo(Reference::of('App\Models\User', '7'))],
            'a filter changed' => [static fn (): AuditTrail => app(AuditTrail::class)->visibleTo(Reference::of('App\Models\User', '7'))->inCategory('finance', 'hr')],
        ];
    }

    /**
     * A cursor is refused under other filters that select the same rows.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $narrow
     * @return void
     */
    #[DataProvider('provideOtherFilters')]
    public function testACursorWithOtherFiltersIsRefused(\Closure $narrow): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->nextCursorOf($this->financeTrail()->cursorPaginate(1));

        $this->assertCursorRefused(fn () => $narrow($this->financeTrail())->cursorPaginate(1, $cursor));
    }

    /**
     * A cursor with any part changed is refused before any read, and recorded.
     *
     * @return void
     */
    public function testATamperedCursorIsRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor   = $this->nextCursorOf($this->financeTrail()->cursorPaginate(1));
        $tampered = ['version' => 'v2' . substr($cursor, 2)];

        foreach (self::CURSOR_PARTS as $name => $index) {
            $tampered[$name] = self::tamperedPart($cursor, (int) $index);
        }

        $this->captureQueries();

        foreach ($tampered as $name => $changed) {
            self::assertNotSame($cursor, $changed, "The {$name} was not changed.");

            $this->assertCursorRefused(fn () => $this->financeTrail()->cursorPaginate(1, $changed));
        }

        self::assertSame([], $this->entryReads());

        $refused = array_slice($this->readRecords('audit_log.trail_read'), 1);

        self::assertSame(array_fill(0, 4, ['denied', 'cursor_rejected']), array_map(static fn (array $record): array => [$record['outcome'], $record['reason']], $refused));
    }

    /**
     * A cursor holds a position, so pruning its anchor row does not break it.
     *
     * @return void
     */
    public function testAPrunedAnchorRowDoesNotInvalidateTheCursor(): void
    {
        $this->allowEverything();

        $ids   = $this->seedEntries(4);
        $first = $this->financeTrail()->cursorPaginate(2);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $ids[2])->delete();

        $second = $this->financeTrail()->cursorPaginate(2, $this->nextCursorOf($first));

        self::assertSame([$ids[3], $ids[2]], self::idsOf($first));
        self::assertSame([$ids[1], $ids[0]], self::idsOf($second));
    }

    /**
     * A count counts only what the scope lets the viewer see.
     *
     * @return void
     */
    public function testACountIsLimitedToTheScope(): void
    {
        $this->allowTenants(self::tenant('org_01'));

        foreach (['org_01', 'org_01', 'org_02', null] as $tenant) {
            $this->seedEntry(self::inTenant($tenant));
        }

        self::assertSame(2, $this->financeTrail()->count());
        self::assertSame(4, DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('category', 'finance')->count());
    }

    /**
     * Rows of `[the scope, what narrows the trail]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Access\AccessScope, 1: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideScopesAndFilters(): iterable
    {
        $none     = static fn (AuditTrail $trail): AuditTrail => $trail;
        $approved = static fn (AuditTrail $trail): AuditTrail => $trail->forEvent('invoice.approved');
        $byUser42 = static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '42'));

        yield from [
            'everything'                  => [static fn (): AccessScope => AccessScope::all(), $none],
            'one tenant'                  => [static fn (): AccessScope => AccessScope::tenants(self::tenant('org_01')), $none],
            'two tenants and tenantless'  => [static fn (): AccessScope => AccessScope::tenants(self::tenant('org_01'), self::tenant('org_02'))->withTenantless(), $none],
            'one category'                => [static fn (): AccessScope => AccessScope::all()->onlyCategories('hr'), $none],
            'about an actor'              => [static fn (): AccessScope => AccessScope::all()->onlyAbout(Reference::of('user', '7')), $none],
            'one tenant and a code'       => [static fn (): AccessScope => AccessScope::tenants(self::tenant('org_02')), $approved],
            'everything but one category' => [static fn (): AccessScope => AccessScope::all()->exceptCategories('hr'), $byUser42],
        ];
    }

    /**
     * A walk of every page shows as many entries as the count counts.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $narrow
     * @return void
     */
    #[DataProvider('provideScopesAndFilters')]
    public function testAPageAndACountSeeTheSameRows(\Closure $scope, \Closure $narrow): void
    {
        $this->usePolicy(static fn (): AccessScope => $scope());
        $this->seedMixed();

        $trail = $narrow(app(AuditTrail::class)->visibleTo($this->viewer())->forEventsUnder('invoice.'));
        $shown = array_merge(...array_map(self::idsOf(...), $this->walk($trail, 2)));

        self::assertNotSame([], $shown);
        self::assertSame($shown, array_values(array_unique($shown)));
        self::assertCount($trail->count(), $shown);
    }

    /**
     * A scope about a reference sees only entries it is actor or subject of.
     *
     * @return void
     */
    public function testOnlyAboutSelectsByActorOrSubject(): void
    {
        $this->usePolicy(static fn (): AccessScope => AccessScope::all()->onlyAbout(Reference::of('user', '7')));

        $byActor   = $this->seedEntry(['actor_id' => '7'], self::at(0));
        $bySubject = $this->seedEntry(['subject_type' => 'user', 'subject_id' => '7'], self::at(1));

        $this->seedEntry(['principal_type' => 'user', 'principal_id' => '7'], self::at(2));
        $this->seedEntry(['actor_type' => 'customer', 'actor_id' => '7'], self::at(3));
        $this->seedEntry([], self::at(4));

        self::assertSame([$bySubject, $byActor], self::idsOf($this->financeTrail()->cursorPaginate()));
        self::assertSame(2, $this->financeTrail()->count());
    }

    /**
     * A tenantless entry is seen only by a scope that adds tenantless entries.
     *
     * @return void
     */
    public function testTenantlessRowsAreSeenOnlyWithTenantless(): void
    {
        $tenanted   = $this->seedEntry([], self::at(0));
        $tenantless = $this->seedEntry(['tenant_type' => null, 'tenant_id' => null], self::at(1));

        $this->allowTenants(self::tenant('org_01'));

        self::assertSame([$tenanted], self::idsOf($this->financeTrail()->cursorPaginate()));

        $this->usePolicy(static fn (): AccessScope => AccessScope::tenants(self::tenant('org_01'))->withTenantless());

        self::assertSame([$tenantless, $tenanted], self::idsOf($this->financeTrail()->cursorPaginate()));
    }

    /**
     * A category scope narrows every filter, and excepted ones are never seen.
     *
     * @return void
     */
    public function testCategoriesNarrow(): void
    {
        $finance = $this->seedEntry([], self::at(0));
        $hr      = $this->seedEntry(['category' => 'hr'], self::at(1));
        $sales   = $this->seedEntry(['category' => 'sales'], self::at(2));
        $trail   = app(AuditTrail::class)->visibleTo($this->viewer());

        $this->usePolicy(static fn (): AccessScope => AccessScope::all()->onlyCategories('finance', 'hr'));

        self::assertSame([$hr, $finance], self::idsOf($trail->cursorPaginate()));
        self::assertSame([$hr], self::idsOf($trail->inCategory('hr')->cursorPaginate()));
        self::assertSame([], self::idsOf($trail->inCategory('sales')->cursorPaginate()));

        $this->usePolicy(static fn (): AccessScope => AccessScope::all()->exceptCategories('hr', 'audit'));

        self::assertSame([$sales, $finance], self::idsOf($trail->cursorPaginate()));
        self::assertSame([$finance], self::idsOf($trail->inCategory('finance', 'hr')->cursorPaginate()));
    }

    /**
     * Every page of the trail, from the first, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @param  int  $perPage
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    private function walk(AuditTrail $trail, int $perPage): array
    {
        $pages = [$trail->cursorPaginate($perPage)];

        while (($cursor = end($pages)->nextCursor) !== null) {
            self::assertLessThan(100, count($pages), 'The walk never ended.');

            $pages[] = $trail->cursorPaginate($perPage, $cursor);
        }

        return $pages;
    }

    /**
     * Seed entries of every kind a scope or filter tells apart.
     *
     * @return void
     */
    private function seedMixed(): void
    {
        $index = 0;
        $kinds = [
            ['actor_id' => '42', 'event' => 'invoice.approved'],
            ['actor_id' => '7', 'event' => 'invoice.voided'],
            ['subject_type' => 'user', 'subject_id' => '7'],
        ];

        foreach (['org_01', 'org_02', 'org_03', null] as $tenant) {
            foreach (['finance', 'hr'] as $category) {
                foreach ($kinds as $fields) {
                    $this->seedEntry(self::inTenant($tenant, ['category' => $category, ...$fields]), self::at($index++));
                }
            }
        }
    }

    /**
     * The cursor of the page, which must have one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return string
     */
    private function nextCursorOf(TrailPage $page): string
    {
        self::assertIsString($page->nextCursor, 'The page has no cursor.');

        return $page->nextCursor;
    }

    /**
     * Assert that the read is refused as a cursor is, with the uniform message.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Querying\TrailPage  $read
     * @return void
     */
    private function assertCursorRefused(\Closure $read): void
    {
        try {
            $read();

            self::fail('Expected the cursor to be refused.');
        } catch (InvalidCursorException $refusal) {
            self::assertSame(InvalidCursorException::refused()->getMessage(), $refusal->getMessage());
        }
    }

    /**
     * The cursor with one character of the part changed, still valid base64url.
     *
     * @param  string  $cursor
     * @param  int  $index
     * @return string
     */
    private static function tamperedPart(string $cursor, int $index): string
    {
        $parts = explode('.', $cursor);

        $parts[$index] = ($parts[$index][0] === 'A' ? 'B' : 'A') . substr($parts[$index], 1);

        return implode('.', $parts);
    }

    /**
     * The fields of an entry in the organisation, or in no tenant for `null`.
     *
     * @param  ?string  $tenant
     * @param  array<string, ?string>  $fields
     * @return array<string, ?string>
     */
    private static function inTenant(?string $tenant, array $fields = []): array
    {
        return ['tenant_type' => $tenant === null ? null : self::TENANT_TYPE, 'tenant_id' => $tenant, ...$fields];
    }

    /**
     * The organisation of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function tenant(string $id): Reference
    {
        return Reference::of(self::TENANT_TYPE, $id);
    }

    /**
     * The instant the number of microseconds after the first seeded entry.
     *
     * @param  int  $microseconds
     * @return string
     */
    private static function at(int $microseconds): string
    {
        return sprintf('2026-11-01T12:00:00.%06dZ', $microseconds);
    }
}
