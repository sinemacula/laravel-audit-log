<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Querying\Position;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Narrows a statement that reads entries for a viewer: an access scope and a
 * caller's filters, then a page's cursor or an export's keyset, compiled onto a
 * query of the entries table.
 *
 * Each part is its own grouped condition, so a filter can never widen the
 * scope. Every value is bound, and no collation is applied, so ids compare in
 * each engine's own type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScopeCompiler
{
    /** @var string The character that escapes `!`, `%` and `_` in a bound `like` pattern. */
    public const string LIKE_ESCAPE = '!';

    /** @var array<string, array{0: string, 1: string}> The type and id columns of each reference a filter names. */
    private const array REFERENCE_COLUMNS = [
        'actor'     => ['actor_type', 'actor_id'],
        'subject'   => ['subject_type', 'subject_id'],
        'principal' => ['principal_type', 'principal_id'],
        'tenant'    => ['tenant_type', 'tenant_id'],
    ];

    /** @var string Pattern of an entry id: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * The `like` pattern of every code under the prefix: `!`, `%` and `_` each
     * escaped with `!`, then `%`.
     *
     * @param  string  $prefix
     * @return string
     */
    public static function likePattern(string $prefix): string
    {
        return strtr($prefix, ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';
    }

    /**
     * Whether the scope and the filters can match no entry, answered without a
     * query so a denied or disjoint read runs no statement that could tell an
     * entry exists.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return bool
     */
    public function isEmpty(AccessScope $scope, TrailFilters $filters): bool
    {
        return $scope->isDenied()
            || self::isOutsideTenants($scope, $filters)
            || self::isOutsideCategories($scope, $filters)
            || self::isOutsideAbout($scope, $filters);
    }

    /**
     * The query narrowed to the scope, then to the filters, each a grouped
     * condition of its own in that order: tenant, category, about, then the
     * caller's filters, the owner whose data the entries hold last. A denied
     * scope is never compiled; a caller checks `isEmpty()` first.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \LogicException
     */
    public function apply(Builder $query, AccessScope $scope, TrailFilters $filters): Builder
    {
        if ($scope->isDenied()) {
            throw new \LogicException('A denied access scope is never compiled into a statement; check isEmpty() first.');
        }

        self::tenant($query, $scope);
        self::category($query, $scope);
        self::about($query, $scope);
        self::references($query, $filters);
        self::refinements($query, $filters);
        self::holding($query, $filters);

        return $query;
    }

    /**
     * The query narrowed to the entries strictly after the position in a page's
     * order, newest first: those that occurred earlier, or at the same time
     * with a lower id, as one grouped condition. The caller orders by
     * `occurred_at` then `id`, both descending.
     *
     * The leading `occurred_at <= t` gives every engine an index range after
     * the scope's equalities; without it SQLite and PostgreSQL scan from the
     * newest entry, or PostgreSQL splits the `or` across two indexes.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    public function before(Builder $query, Position $position): Builder
    {
        $time = StoredTime::toStorage($position->time);

        return $query->where(static fn (Builder $group): Builder => $group
            ->where('occurred_at', '<=', $time)
            ->where(static fn (Builder $after): Builder => $after
                ->where('occurred_at', '<', $time)
                ->orWhere(static fn (Builder $tie): Builder => $tie->where('occurred_at', '=', $time)->where('id', '<', $position->id))));
    }

    /**
     * The query narrowed to an export's keyset in recording order, oldest
     * first: after the position when one is given, those recorded later or at
     * the same time with a higher id; and always up to the bound, inclusive.
     * Each is one grouped condition. The caller orders by `recorded_at` then
     * `id`, both ascending.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @param  \SineMacula\Laravel\AuditLog\Querying\Position  $bound
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    public function after(Builder $query, ?Position $position, Position $bound): Builder
    {
        if ($position !== null) {
            $time = StoredTime::toStorage($position->time);

            $query->where(static fn (Builder $group): Builder => $group
                ->where('recorded_at', '>', $time)
                ->orWhere(static fn (Builder $tie): Builder => $tie->where('recorded_at', '=', $time)->where('id', '>', $position->id)));
        }

        $last = StoredTime::toStorage($bound->time);

        return $query->where(static fn (Builder $group): Builder => $group
            ->where('recorded_at', '<', $last)
            ->orWhere(static fn (Builder $tie): Builder => $tie->where('recorded_at', '=', $last)->where('id', '<=', $bound->id)));
    }

    /**
     * The query narrowed to the one entry of the id under the scope, so an
     * entry outside it is never found: the id must be a lower-case UUID, and a
     * denied scope is refused as `apply()` refuses it.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  string  $id
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    public function entry(Builder $query, AccessScope $scope, string $id): Builder
    {
        if (preg_match(self::UUID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException('An entry is looked up by its id, a lower-case UUID.');
        }

        return $this->apply($query, $scope, TrailFilters::none())->where('id', '=', $id);
    }

    /**
     * Narrow the query to the scope's tenants, each an exact pair, and the
     * entries of no tenant when the scope sees them, as one group; nothing for
     * a scope of every tenant.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    private static function tenant(Builder $query, AccessScope $scope): void
    {
        $tenants = $scope->tenantList();

        if ($tenants === null) {
            return;
        }

        $tenantless = $scope->includesTenantless();

        $query->where(static function (Builder $group) use ($tenants, $tenantless): void {
            foreach ($tenants as $tenant) {
                $group->orWhere(static fn (Builder $pair): Builder => $pair->where('tenant_type', '=', $tenant->type)->where('tenant_id', '=', $tenant->id));
            }

            if (!$tenantless) {
                return;
            }

            $group->orWhere(static fn (Builder $pair): Builder => $pair->whereNull('tenant_type')->whereNull('tenant_id'));
        });
    }

    /**
     * Narrow the query to the scope's only categories, and away from its
     * excepted ones.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    private static function category(Builder $query, AccessScope $scope): void
    {
        $only = $scope->categories();

        if ($only !== null) {
            $query->whereIn('category', $only);
        }

        if ($scope->exceptedCategories() === []) {
            return;
        }

        $query->whereNotIn('category', $scope->exceptedCategories());
    }

    /**
     * Narrow the query to the activity of the scope's references, each the
     * actor or the subject as an exact pair, as one group; nothing for a scope
     * of anyone's activity.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    private static function about(Builder $query, AccessScope $scope): void
    {
        $about = $scope->aboutList();

        if ($about === null) {
            return;
        }

        $query->where(static function (Builder $group) use ($about): void {
            foreach ($about as $reference) {
                $group
                    ->orWhere(static fn (Builder $pair): Builder => $pair->where('actor_type', '=', $reference->type)->where('actor_id', '=', $reference->id))
                    ->orWhere(static fn (Builder $pair): Builder => $pair->where('subject_type', '=', $reference->type)->where('subject_id', '=', $reference->id));
            }
        });
    }

    /**
     * Narrow the query to each reference the filters name, as its type and id
     * columns.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return void
     */
    private static function references(Builder $query, TrailFilters $filters): void
    {
        $named = [
            'actor'     => $filters->actor,
            'subject'   => $filters->subject,
            'principal' => $filters->principal,
            'tenant'    => $filters->tenant,
        ];

        foreach (array_filter($named) as $dimension => $reference) {
            [$type, $id] = self::REFERENCE_COLUMNS[$dimension];

            $query->where($type, '=', $reference->type)->where($id, '=', $reference->id);
        }
    }

    /**
     * Narrow the query to the filters' codes or prefix, categories, outcomes,
     * window and correlation id; the prefix through an explicit `like` with its
     * own escape character, never the framework's, which SQLite would turn into
     * a case-sensitive `glob`.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refinements(Builder $query, TrailFilters $filters): void
    {
        if ($filters->events !== []) {
            $query->whereIn('event', $filters->events);
        }

        if ($filters->eventPrefix !== null) {
            $query->whereRaw('event like ? escape \'' . self::LIKE_ESCAPE . '\'', [self::likePattern($filters->eventPrefix)]);
        }

        if ($filters->categories !== []) {
            $query->whereIn('category', $filters->categories);
        }

        if ($filters->outcomes !== []) {
            $query->whereIn('outcome', $filters->outcomes);
        }

        if ($filters->from !== null) {
            $query->where('occurred_at', '>=', StoredTime::toStorage($filters->from));
        }

        if ($filters->to !== null) {
            $query->where('occurred_at', '<', StoredTime::toStorage($filters->to));
        }

        if ($filters->correlationId === null) {
            return;
        }

        $query->where('correlation_id', '=', $filters->correlationId);
    }

    /**
     * Narrow the query to the entries with a key use of any of the owner's
     * keys, erased or not, every column qualified by its table so none is read
     * as another's.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function holding(Builder $query, TrailFilters $filters): void
    {
        $owner = $filters->holding;

        if ($owner === null) {
            return;
        }

        $entries = self::nameOf($query);
        $uses    = KeyTables::keyUsesTable();
        $keys    = KeyTables::subjectKeysTable();

        $query->whereExists(static fn (Builder $exists): Builder => $exists
            ->selectRaw('1')
            ->from($uses)
            ->join($keys, $keys . '.id', '=', $uses . '.key_id')
            ->whereColumn($uses . '.entry_id', '=', $entries . '.id')
            ->where($keys . '.owner_type', '=', $owner->type)
            ->where($keys . '.owner_id', '=', $owner->id));
    }

    /**
     * The name the query reads its table under: its alias when it has one,
     * otherwise the table's own name.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return string
     *
     * @throws \LogicException
     */
    private static function nameOf(Builder $query): string
    {
        if (!is_string($query->from) || $query->from === '') {
            throw new \LogicException('An owner\'s entries are found from a query of the entries table, named as a table.');
        }

        $alias = stripos($query->from, ' as ');

        return $alias === false ? $query->from : trim(substr($query->from, $alias + 4));
    }

    /**
     * Whether the filters name a tenant that a scope of listed tenants does not
     * hold.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return bool
     */
    private static function isOutsideTenants(AccessScope $scope, TrailFilters $filters): bool
    {
        $tenants = $scope->tenantList();

        return $filters->tenant !== null && $tenants !== null && !self::holds($tenants, $filters->tenant);
    }

    /**
     * Whether every category the filters name is outside the scope's only
     * categories, or every one is excepted.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return bool
     */
    private static function isOutsideCategories(AccessScope $scope, TrailFilters $filters): bool
    {
        if ($filters->categories === []) {
            return false;
        }

        $only = $scope->categories();

        return ($only !== null && array_intersect($filters->categories, $only) === [])
            || array_diff($filters->categories, $scope->exceptedCategories()) === [];
    }

    /**
     * Whether the scope selects activity about some references and the filters
     * name both an actor and a subject, neither of them among them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return bool
     */
    private static function isOutsideAbout(AccessScope $scope, TrailFilters $filters): bool
    {
        $about = $scope->aboutList();

        if ($about === null || $filters->actor === null || $filters->subject === null) {
            return false;
        }

        return !self::holds($about, $filters->actor) && !self::holds($about, $filters->subject);
    }

    /**
     * Whether the references hold the reference as an exact pair.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return bool
     */
    private static function holds(array $references, Reference $reference): bool
    {
        return array_filter($references, $reference->equals(...)) !== [];
    }
}
