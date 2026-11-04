<?php

declare(strict_types = 1);

namespace Tests\Unit\Access;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the access scope algebra: what each starting scope sees, that
 * a denied scope absorbs every operation, that an empty list denies and an
 * empty except list excepts nothing, that narrowing only ever intersects, that
 * the tenantless rows are the one addition, the limits, and the sorted
 * normalised form and its fingerprint.
 *
 * What a scope sees is checked on its normalised form against a small universe
 * of rows, every combination of a tenant (a full pair, both columns `null`, or
 * a type with no id), a category, an actor and a subject, so a claim that a
 * scope sees a subset of another is a claim about rows, not about its fields.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessScope::class)]
final class AccessScopeTest extends TestCase
{
    /** @var list<array{0: ?string, 1: ?string}> The tenant columns of the universe's rows: full pairs, both `null`, and a type with no id. */
    private const array TENANTS = [['team', '1'], ['team', '2'], ['org', '1'], [null, null], ['team', null]];

    /** @var list<string> The categories of the universe's rows. */
    private const array CATEGORIES = ['audit', 'auth', 'billing'];

    /** @var list<?array{0: string, 1: string}> The actors and subjects of the universe's rows. */
    private const array PEOPLE = [['user', '1'], ['user', '2'], ['service', '1'], null];

    /**
     * Nothing is seen by `none()`, whose normalised form is the one every
     * denied scope has.
     *
     * @return void
     */
    public function testNoneDenies(): void
    {
        $scope = AccessScope::none();

        self::assertTrue($scope->isDenied());
        self::assertSame([], self::seen($scope));
        self::assertSame([
            'about'             => [],
            'denied'            => true,
            'except_categories' => [],
            'only_categories'   => [],
            'tenantless'        => false,
            'tenants'           => [],
        ], $scope->toArray());
    }

    /**
     * Every row is seen by `all()`: every tenant, the tenantless rows and a
     * type with no id among them, every category and anyone's activity.
     *
     * @return void
     */
    public function testAllAllowsEveryRow(): void
    {
        $scope = AccessScope::all();

        self::assertFalse($scope->isDenied());
        self::assertCount(count(self::universe()), self::seen($scope));
        self::assertNull($scope->tenantList());
        self::assertTrue($scope->includesTenantless());
        self::assertNull($scope->categories());
        self::assertSame([], $scope->exceptedCategories());
        self::assertNull($scope->aboutList());
    }

    /**
     * A scope of tenants sees the rows of exactly those tenants, each once, and
     * not the tenantless rows.
     *
     * @return void
     */
    public function testTenantsAreExactPairs(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '1'));

        self::assertSame([['team', '1']], $scope->toArray()['tenants']);
        self::assertFalse($scope->includesTenantless());
        self::assertSame([['team', '1']], self::tenantsSeen($scope));
    }

    /**
     * Two tenants are held as two pairs, never as a list of types and a list of
     * ids, so a type of one with the id of the other is not seen.
     *
     * @return void
     */
    public function testReferencesAreKeptAsPairsNotTypesAndIdsApart(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', '2'), Reference::of('org', '1'));

        self::assertSame([['org', '1'], ['team', '2']], $scope->toArray()['tenants']);
        self::assertSame([['team', '2'], ['org', '1']], self::tenantsSeen($scope));
        self::assertNotContains(['team', '1'], self::tenantsSeen($scope));

        $about = AccessScope::all()->onlyAbout(Reference::of('user', '2'), Reference::of('service', '1'));

        self::assertSame([['service', '1'], ['user', '2']], $about->toArray()['about']);
        self::assertSame([], array_filter(self::seen($about), static fn (string $row): bool => str_contains($row, 'actor=user:1;subject=user:1')));
    }

    /**
     * No tenant is no tenant seen: the scope is denied, never every tenant.
     *
     * @return void
     */
    public function testAnEmptyTenantListDenies(): void
    {
        self::assertTrue(AccessScope::tenants()->isDenied());
        self::assertSame(AccessScope::none()->toArray(), AccessScope::tenants()->toArray());
    }

    /**
     * The tenantless rows are those with both tenant columns `null`: a type
     * with no id is not one of them.
     *
     * @return void
     */
    public function testWithTenantlessAddsBothNullColumns(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', '1'))->withTenantless();

        self::assertTrue($scope->includesTenantless());
        self::assertTrue($scope->toArray()['tenantless']);
        self::assertSame([['team', '1'], [null, null]], self::tenantsSeen($scope));
        self::assertSame(AccessScope::all()->toArray(), AccessScope::all()->withTenantless()->toArray());
    }

    /**
     * Rows of `[operation]`: every operation that narrows, and the one that
     * adds rows.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Access\AccessScope): \SineMacula\Laravel\AuditLog\Access\AccessScope}>
     */
    public static function provideOperations(): iterable
    {
        yield from [
            'the tenantless rows'      => [static fn (AccessScope $scope): AccessScope => $scope->withTenantless()],
            'only some categories'     => [static fn (AccessScope $scope): AccessScope => $scope->onlyCategories('billing', 'auth')],
            'no category'              => [static fn (AccessScope $scope): AccessScope => $scope->onlyCategories()],
            'excepting some'           => [static fn (AccessScope $scope): AccessScope => $scope->exceptCategories('billing')],
            'excepting none'           => [static fn (AccessScope $scope): AccessScope => $scope->exceptCategories()],
            'about some'               => [static fn (AccessScope $scope): AccessScope => $scope->onlyAbout(Reference::of('user', '1'))],
            'about no one'             => [static fn (AccessScope $scope): AccessScope => $scope->onlyAbout()],
            'every operation in a row' => [static fn (AccessScope $scope): AccessScope => $scope
                ->withTenantless()
                ->onlyCategories('auth')
                ->exceptCategories('audit')
                ->onlyAbout(Reference::of('user', '1'))],
        ];
    }

    /**
     * A denied scope stays denied whatever is done to it, the tenantless rows
     * included, so it sees nothing and has the form of `none()`.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Access\AccessScope): \SineMacula\Laravel\AuditLog\Access\AccessScope  $operation
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testNoneAbsorbsEveryOperation(\Closure $operation): void
    {
        foreach ([AccessScope::none(), AccessScope::tenants(), AccessScope::all()->onlyCategories(), AccessScope::all()->onlyAbout()] as $denied) {
            $result = $operation($denied);

            self::assertTrue($result->isDenied());
            self::assertSame(AccessScope::none()->toArray(), $result->toArray());
            self::assertSame([], self::seen($result));
        }
    }

    /**
     * Only no category is no category seen: the scope is denied, never every
     * category.
     *
     * @return void
     */
    public function testAnEmptyCategoryListDenies(): void
    {
        self::assertTrue(AccessScope::all()->onlyCategories()->isDenied());
        self::assertTrue(AccessScope::tenants(Reference::of('team', '1'))->onlyCategories()->isDenied());
    }

    /**
     * Activity about no one is nothing seen: the scope is denied, never
     * anyone's activity.
     *
     * @return void
     */
    public function testAnEmptyAboutListDenies(): void
    {
        self::assertTrue(AccessScope::all()->onlyAbout()->isDenied());
        self::assertTrue(AccessScope::all()->onlyAbout(Reference::of('user', '1'))->onlyAbout()->isDenied());
    }

    /**
     * Excepting no category excepts nothing: it never means every category, on
     * a scope of every category or of only some.
     *
     * @return void
     */
    public function testExceptingNothingExceptsNothing(): void
    {
        self::assertSame(AccessScope::all()->toArray(), AccessScope::all()->exceptCategories()->toArray());

        $some = AccessScope::all()->onlyCategories('billing');

        self::assertSame($some->toArray(), $some->exceptCategories()->toArray());

        $excepted = AccessScope::all()->exceptCategories('auth');

        self::assertSame($excepted->toArray(), $excepted->exceptCategories()->toArray());
    }

    /**
     * Repeating a narrowing intersects with what the scope already holds, so a
     * second list never widens the first, and a disjoint one denies.
     *
     * @return void
     */
    public function testRepeatingANarrowingIntersects(): void
    {
        self::assertSame(['auth'], AccessScope::all()->onlyCategories('auth', 'billing')->onlyCategories('auth', 'audit')->categories());
        self::assertTrue(AccessScope::all()->onlyCategories('auth')->onlyCategories('billing')->isDenied());

        $u1 = Reference::of('user', '1');
        $u2 = Reference::of('user', '2');
        $s1 = Reference::of('service', '1');

        self::assertSame([$u2], AccessScope::all()->onlyAbout($u1, $u2)->onlyAbout($u2, $s1)->aboutList());
        self::assertTrue(AccessScope::all()->onlyAbout($u1)->onlyAbout($u2)->isDenied());

        self::assertSame(['audit', 'auth'], AccessScope::all()->exceptCategories('auth')->exceptCategories('audit', 'auth')->exceptedCategories());
    }

    /**
     * Excepting every category a scope only sees denies it, whichever comes
     * first, and excepting some leaves the rest.
     *
     * @return void
     */
    public function testExceptingEveryAllowedCategoryDenies(): void
    {
        self::assertTrue(AccessScope::all()->onlyCategories('auth', 'billing')->exceptCategories('billing', 'auth')->isDenied());
        self::assertTrue(AccessScope::all()->exceptCategories('billing', 'auth')->onlyCategories('auth', 'billing')->isDenied());
        self::assertTrue(AccessScope::all()->exceptCategories('billing')->exceptCategories('auth')->onlyCategories('auth', 'billing')->isDenied());

        $some = AccessScope::all()->exceptCategories('billing')->onlyCategories('auth', 'billing');

        self::assertSame(['auth'], $some->categories());
        self::assertSame([], $some->exceptedCategories());
        self::assertSame(['auth'], AccessScope::all()->onlyCategories('auth', 'billing')->exceptCategories('billing')->categories());
    }

    /**
     * Rows of `[scope]`: scopes of every shape, to narrow.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Access\AccessScope}>
     */
    public static function provideScopes(): iterable
    {
        $t1 = Reference::of('team', '1');
        $t2 = Reference::of('team', '2');
        $u1 = Reference::of('user', '1');

        yield from [
            'every row'                  => [AccessScope::all()],
            'nothing'                    => [AccessScope::none()],
            'one tenant'                 => [AccessScope::tenants($t1)],
            'two tenants and tenantless' => [AccessScope::tenants($t1, $t2)->withTenantless()],
            'only some categories'       => [AccessScope::all()->onlyCategories('auth', 'billing')],
            'every category but one'     => [AccessScope::tenants($t2)->exceptCategories('audit')],
            'about one'                  => [AccessScope::all()->onlyAbout($u1)],
            'about one in one tenant'    => [AccessScope::tenants($t1)->withTenantless()->onlyAbout($u1)->onlyCategories('auth')],
            'about two under an except'  => [AccessScope::all()->onlyAbout($u1, Reference::of('service', '1'))->exceptCategories('billing')],
        ];
    }

    /**
     * Whatever the scope and whichever narrowing, the rows the result sees are
     * a subset of the rows the scope saw.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    #[DataProvider('provideScopes')]
    public function testNoNarrowingWidens(AccessScope $scope): void
    {
        $before = self::seen($scope);

        $narrowings = [
            static fn (AccessScope $scope): AccessScope => $scope->onlyCategories('billing'),
            static fn (AccessScope $scope): AccessScope => $scope->onlyCategories('auth', 'audit'),
            static fn (AccessScope $scope): AccessScope => $scope->onlyCategories(),
            static fn (AccessScope $scope): AccessScope => $scope->exceptCategories('auth'),
            static fn (AccessScope $scope): AccessScope => $scope->exceptCategories(),
            static fn (AccessScope $scope): AccessScope => $scope->onlyAbout(Reference::of('user', '2')),
            static fn (AccessScope $scope): AccessScope => $scope->onlyAbout(Reference::of('user', '1'), Reference::of('service', '1')),
            static fn (AccessScope $scope): AccessScope => $scope->onlyAbout(),
        ];

        foreach ($narrowings as $index => $narrowing) {
            self::assertSame([], array_values(array_diff(self::seen($narrowing($scope)), $before)), "Narrowing {$index} widened the scope.");
        }
    }

    /**
     * The tenantless rows are the only rows `withTenantless()` adds, and the
     * scope's category and about restrictions still hold for them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    #[DataProvider('provideScopes')]
    public function testWithTenantlessAddsOnlyTenantlessRowsUnderTheSameRestrictions(AccessScope $scope): void
    {
        $before = self::seen($scope);
        $added  = array_values(array_diff(self::seen($scope->withTenantless()), $before));

        self::assertSame([], array_values(array_diff($before, self::seen($scope->withTenantless()))));

        foreach ($added as $row) {
            self::assertStringStartsWith('tenant=-:-;', $row);
        }

        $restricted = AccessScope::tenants(Reference::of('team', '1'))->onlyCategories('auth')->onlyAbout(Reference::of('user', '1'))->withTenantless();

        foreach (self::seen($restricted) as $row) {
            self::assertStringContainsString(';category=auth;', $row);
            self::assertStringContainsString('user:1', $row);
        }

        self::assertContains('tenant=-:-;category=auth;actor=user:1;subject=-', self::seen($restricted));
    }

    /**
     * A hundred tenants are held, counted once each, and a hundred and one are
     * refused, naming the limit.
     *
     * @return void
     */
    public function testRefusesMoreThanAHundredTenants(): void
    {
        $hundred = array_map(static fn (int $id): Reference => Reference::of('team', $id), range(1, AccessScope::MAX_TENANTS));

        self::assertCount(100, AccessScope::tenants(...$hundred, ...$hundred)->tenantList() ?? []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An access scope holds at most 100 tenants.');

        AccessScope::tenants(...$hundred, ...[Reference::of('team', 'one more')]);
    }

    /**
     * Fifty categories are held in each list, and fifty-one are refused,
     * whether given at once or gathered by excepting more, naming the limit.
     *
     * @return void
     */
    public function testRefusesMoreThanFiftyCategories(): void
    {
        $fifty = array_map(static fn (int $index): string => "category_{$index}", range(1, AccessScope::MAX_CATEGORIES));

        self::assertCount(50, AccessScope::all()->onlyCategories(...$fifty, ...$fifty)->categories() ?? []);
        self::assertCount(50, AccessScope::all()->exceptCategories(...$fifty)->exceptedCategories());

        $first = array_slice($fifty, 0, 25);
        $rest  = array_slice($fifty, 25);

        $refusals = [
            'only'               => static fn (): AccessScope => AccessScope::all()->onlyCategories(...$fifty, ...['one_more']),
            'except'             => static fn (): AccessScope => AccessScope::all()->exceptCategories(...$fifty, ...['one_more']),
            'excepting in steps' => static fn (): AccessScope => AccessScope::all()->exceptCategories(...$first)->exceptCategories(...$rest, ...['one_more']),
        ];

        foreach ($refusals as $label => $refusal) {
            try {
                $refusal();

                self::fail("Expected {$label} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An access scope holds at most 50 categories in each list.', $exception->getMessage(), $label);
            }
        }
    }

    /**
     * A hundred about-references are held, counted once each, and a hundred and
     * one are refused, naming the limit.
     *
     * @return void
     */
    public function testRefusesMoreThanAHundredAboutReferences(): void
    {
        $hundred = array_map(static fn (int $id): Reference => Reference::of('user', $id), range(1, AccessScope::MAX_ABOUT));

        self::assertCount(100, AccessScope::all()->onlyAbout(...$hundred, ...$hundred)->aboutList() ?? []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An access scope holds at most 100 about-references.');

        AccessScope::all()->onlyAbout(...$hundred, ...[Reference::of('user', 'one more')]);
    }

    /**
     * Rows of `[category]`: categories outside the definitions' grammar.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedCategories(): iterable
    {
        yield from [
            'empty'                => [''],
            'upper case'           => ['Billing'],
            'a leading digit'      => ['1billing'],
            'a hyphen'             => ['bill-ing'],
            'a dot'                => ['billing.x'],
            'sixty-five long'      => ['a' . str_repeat('b', 64)],
            'a trailing line feed' => ["billing\n"],
        ];
    }

    /**
     * A malformed category is refused, to only or to except, even on a denied
     * scope, with a message that never names it.
     *
     * @param  string  $category
     * @return void
     */
    #[DataProvider('provideMalformedCategories')]
    public function testRefusesAMalformedCategory(string $category): void
    {
        $refusals = [
            static fn (): AccessScope => AccessScope::all()->onlyCategories('billing', $category),
            static fn (): AccessScope => AccessScope::all()->exceptCategories($category),
            static fn (): AccessScope => AccessScope::none()->onlyCategories($category),
        ];

        foreach ($refusals as $index => $refusal) {
            try {
                $refusal();

                self::fail("Expected refusal {$index} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An access scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.', $exception->getMessage());
            }
        }
    }

    /**
     * Every way of reaching a denied scope gives the one normalised form and
     * fingerprint, so two denied scopes are equal.
     *
     * @return void
     */
    public function testTwoDeniedScopesAreEqual(): void
    {
        $denied = [
            AccessScope::tenants(),
            AccessScope::tenants(Reference::of('team', '1'))->withTenantless()->onlyCategories('auth')->onlyCategories('billing'),
            AccessScope::all()->onlyAbout(Reference::of('user', '1'))->onlyAbout(Reference::of('user', '2')),
            AccessScope::all()->exceptCategories('auth')->onlyCategories('auth'),
        ];

        foreach ($denied as $scope) {
            self::assertSame(AccessScope::none()->toArray(), $scope->toArray());
            self::assertSame(AccessScope::none()->fingerprint(), $scope->fingerprint());
        }
    }

    /**
     * Every list of the normalised form is sorted bytewise, references by type
     * then id, however the scope was given them, so two scopes given the same
     * in another order have the same form.
     *
     * @return void
     */
    public function testTheNormalisedFormIsSorted(): void
    {
        $scope = AccessScope::tenants(Reference::of('team', 'b'), Reference::of('Team', 'a'), Reference::of('team', 'B'), Reference::of('te', 'z'))
            ->withTenantless()
            ->onlyCategories('zeta', 'alpha', 'beta')
            ->onlyAbout(Reference::of('user', '10'), Reference::of('user', '9'), Reference::of('admin', '1'));

        self::assertSame([
            'about'             => [['admin', '1'], ['user', '10'], ['user', '9']],
            'denied'            => false,
            'except_categories' => [],
            'only_categories'   => ['alpha', 'beta', 'zeta'],
            'tenantless'        => true,
            'tenants'           => [['Team', 'a'], ['te', 'z'], ['team', 'B'], ['team', 'b']],
        ], $scope->toArray());

        self::assertSame(['alpha', 'zeta'], AccessScope::all()->exceptCategories('zeta', 'alpha')->toArray()['except_categories']);

        $reordered = AccessScope::tenants(Reference::of('te', 'z'), Reference::of('team', 'B'), Reference::of('Team', 'a'), Reference::of('team', 'b'))
            ->onlyAbout(Reference::of('admin', '1'), Reference::of('user', '9'), Reference::of('user', '10'))
            ->onlyCategories('beta', 'zeta', 'alpha')
            ->withTenantless();

        self::assertSame($scope->toArray(), $reordered->toArray());
    }

    /**
     * The fingerprint is the lower-case hex SHA-256 of the canonical encoding
     * of the normalised form, pinned here as text.
     *
     * @return void
     */
    public function testTheFingerprintIsTheSha256OfTheCanonicalForm(): void
    {
        $all = '{"about":null,"denied":false,"except_categories":[],"only_categories":null,"tenantless":true,"tenants":null}';

        self::assertSame(hash('sha256', $all), AccessScope::all()->fingerprint());

        $none = '{"about":[],"denied":true,"except_categories":[],"only_categories":[],"tenantless":false,"tenants":[]}';

        self::assertSame(hash('sha256', $none), AccessScope::none()->fingerprint());

        $scope = AccessScope::tenants(Reference::of('team', '1'))->exceptCategories('auth')->onlyAbout(Reference::of('user', '1'));
        $text  = '{"about":[["user","1"]],"denied":false,"except_categories":["auth"],"only_categories":null,"tenantless":false,"tenants":[["team","1"]]}';

        self::assertSame(hash('sha256', $text), $scope->fingerprint());
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $scope->fingerprint());
    }

    /**
     * Rows of `[scope, the single tenant's pair]`: the one tenant of a scope of
     * exactly one tenant and no tenantless rows, and `null` for any other.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Access\AccessScope, 1: ?array{type: string, id: string}}>
     */
    public static function provideSingleTenants(): iterable
    {
        $t1 = Reference::of('team', '1');
        $t2 = Reference::of('team', '2');

        yield from [
            'one tenant'                => [AccessScope::tenants($t1), ['type' => 'team', 'id' => '1']],
            'one tenant given twice'    => [AccessScope::tenants($t1, Reference::of('team', '1')), ['type' => 'team', 'id' => '1']],
            'one tenant, narrowed'      => [AccessScope::tenants($t1)->onlyCategories('auth')->onlyAbout(Reference::of('user', '1')), ['type' => 'team', 'id' => '1']],
            'two tenants'               => [AccessScope::tenants($t1, $t2), null],
            'one tenant and tenantless' => [AccessScope::tenants($t1)->withTenantless(), null],
            'every tenant'              => [AccessScope::all(), null],
            'nothing'                   => [AccessScope::none(), null],
            'one tenant, then denied'   => [AccessScope::tenants($t1)->onlyCategories(), null],
        ];
    }

    /**
     * The single tenant is the one tenant of a scope of exactly one tenant
     * without the tenantless rows, and `null` for any other scope.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  ?array{type: string, id: string}  $tenant
     * @return void
     */
    #[DataProvider('provideSingleTenants')]
    public function testSingleTenant(AccessScope $scope, ?array $tenant): void
    {
        self::assertSame($tenant, $scope->singleTenant()?->toArray());
    }

    /**
     * The universe's rows the scope sees, judged on its normalised form alone,
     * each as a key naming its columns.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<string>
     */
    private static function seen(AccessScope $scope): array
    {
        $form = $scope->toArray();
        $seen = [];

        foreach (self::universe() as $key => [$tenant, $category, $actor, $subject]) {
            if (!self::sees($form, $tenant, $category, $actor, $subject)) {
                continue;
            }

            $seen[] = $key;
        }

        return $seen;
    }

    /**
     * The distinct tenant columns of the rows the scope sees, in the order of
     * the universe's tenants.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<array{0: ?string, 1: ?string}>
     */
    private static function tenantsSeen(AccessScope $scope): array
    {
        $seen = self::seen($scope);

        return array_values(array_filter(
            self::TENANTS,
            static fn (array $tenant): bool => array_filter($seen, static fn (string $row): bool => str_starts_with($row, 'tenant=' . self::key($tenant) . ';')) !== [],
        ));
    }

    /**
     * Whether a row is seen under the normalised form: not denied; its tenant
     * one of the pairs, or both columns `null` when tenantless rows are seen;
     * its category among the only ones and not excepted; and its actor or
     * subject one of the about-references.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{about: ?list<array{0: string, 1: string}>, denied: bool, except_categories: list<string>, only_categories: ?list<string>, tenantless: bool, tenants: ?list<array{0: string, 1: string}>}  $form
     * @param  array{0: ?string, 1: ?string}  $tenant
     * @param  string  $category
     * @param  ?array{0: string, 1: string}  $actor
     * @param  ?array{0: string, 1: string}  $subject
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function sees(array $form, array $tenant, string $category, ?array $actor, ?array $subject): bool
    {
        $tenantSeen = $form['tenants'] === null
            || in_array($tenant, $form['tenants'], true)
            || ($form['tenantless'] && $tenant === [null, null]);

        $categorySeen = ($form['only_categories'] === null || in_array($category, $form['only_categories'], true))
            && !in_array($category, $form['except_categories'], true);

        $aboutSeen = $form['about'] === null
            || ($actor !== null && in_array($actor, $form['about'], true))
            || ($subject !== null && in_array($subject, $form['about'], true));

        return !$form['denied'] && $tenantSeen && $categorySeen && $aboutSeen;
    }

    /**
     * Every row of the universe, keyed by its columns.
     *
     * @return array<string, array{0: array{0: ?string, 1: ?string}, 1: string, 2: ?array{0: string, 1: string}, 3: ?array{0: string, 1: string}}>
     */
    private static function universe(): array
    {
        $pairs = [];

        foreach (self::PEOPLE as $actor) {
            foreach (self::PEOPLE as $subject) {
                $pairs[] = [$actor, $subject];
            }
        }

        $rows = [];

        foreach (self::TENANTS as $tenant) {
            foreach (self::CATEGORIES as $category) {
                foreach ($pairs as [$actor, $subject]) {
                    $key = 'tenant=' . self::key($tenant) . ";category={$category};actor=" . self::key($actor) . ';subject=' . self::key($subject);

                    $rows[$key] = [$tenant, $category, $actor, $subject];
                }
            }
        }

        return $rows;
    }

    /**
     * A pair's columns as `type:id`, each `-` when `null`, or `-` for no pair.
     *
     * @param  ?array{0: ?string, 1: ?string}  $pair
     * @return string
     */
    private static function key(?array $pair): string
    {
        return $pair === null ? '-' : ($pair[0] ?? '-') . ':' . ($pair[1] ?? '-');
    }
}
