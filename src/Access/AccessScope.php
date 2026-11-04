<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The entries a viewer may see, as an access policy answers for one read: which
 * tenants, whether entries of no tenant, which categories, and whose activity.
 *
 * A scope starts from `none()`, which sees nothing, `all()`, which sees every
 * entry, or `tenants()`, which sees the entries of exactly those tenants, each
 * matched as its type and id together, never as a type and an id apart. It is
 * then narrowed: `onlyCategories()`, `exceptCategories()` and `onlyAbout()`
 * only ever intersect with what the scope already holds, so repeating one never
 * widens it, and a list left empty denies, never means unrestricted.
 * `withTenantless()` is the one way to add entries, and only those whose tenant
 * type and tenant id are both `null`, still under every other restriction.
 *
 * A denied scope absorbs every operation: whatever is done to it, it stays
 * denied. It is immutable; each operation returns a new scope. Its normalised
 * form sorts every list bytewise, so two scopes that see the same entries by
 * the same rules have the same form and fingerprint, and every denied scope has
 * the one form of `none()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|list<array{0: string, 1: string}>|list<string>|null>
 */
final readonly class AccessScope implements Arrayable
{
    /** @var int Most tenants a scope holds. */
    public const int MAX_TENANTS = 100;

    /** @var int Most categories a scope holds in each of its lists. */
    public const int MAX_CATEGORIES = 50;

    /** @var int Most references a scope selects activity about. */
    public const int MAX_ABOUT = 100;

    /**
     * Constructor.
     *
     * @param  bool  $denied
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $tenants
     * @param  bool  $tenantless
     * @param  ?list<string>  $onlyCategories
     * @param  list<string>  $exceptCategories
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $about
     */
    private function __construct(

        /** Whether the scope sees nothing at all. */
        private bool $denied,

        /** The tenants whose entries are seen, sorted, or `null` for every tenant. */
        private ?array $tenants,

        /** Whether the entries with both tenant columns `null` are seen. */
        private bool $tenantless,

        /** The only categories seen, sorted, or `null` for every category. */
        private ?array $onlyCategories,

        /** The categories never seen, sorted; always empty when only some categories are seen. */
        private array $exceptCategories,

        /** The references whose activity, as actor or subject, is seen, sorted, or `null` for anyone's. */
        private ?array $about,
    ) {}

    /**
     * A scope that sees nothing.
     *
     * PHP lets a static factory be reached through an instance
     * (`$scope->none()`); that starts a fresh scope and discards the instance's
     * restrictions.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(true, [], false, [], [], []);
    }

    /**
     * A scope that sees every entry: every tenant, the entries of no tenant,
     * every category and anyone's activity.
     *
     * PHP lets a static factory be reached through an instance
     * (`$scope->all()`); that starts a fresh scope and discards the instance's
     * restrictions, so narrow a scope only through its instance methods.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self(false, null, true, null, [], null);
    }

    /**
     * A scope that sees the entries of exactly these tenants, each matched as
     * its type and id together, and not the entries of no tenant. Each tenant
     * counts once; given none, the scope sees nothing.
     *
     * PHP lets a static factory be reached through an instance
     * (`$scope->tenants(...)`); that starts a fresh scope and discards the
     * instance's restrictions.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$tenants
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function tenants(Reference ...$tenants): self
    {
        $held = self::references(array_values($tenants), self::MAX_TENANTS, 'tenants');

        return $held === [] ? self::none() : new self(false, $held, false, null, [], null);
    }

    /**
     * The scope with the entries whose tenant type and tenant id are both
     * `null` added, under the scope's other restrictions. A scope that sees
     * every tenant already sees them, and a denied scope stays denied.
     *
     * @return self
     */
    public function withTenantless(): self
    {
        if ($this->denied || $this->tenants === null) {
            return $this;
        }

        return new self(false, $this->tenants, true, $this->onlyCategories, $this->exceptCategories, $this->about);
    }

    /**
     * The scope seeing only these categories of what it already sees: the
     * intersection with any earlier list, less any category excepted. Given
     * none, or left with none, the scope sees nothing.
     *
     * @param  string  ...$categories
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function onlyCategories(string ...$categories): self
    {
        $given = self::categoryList(array_values($categories));

        if ($this->denied) {
            return $this;
        }

        $only = array_values(array_diff(
            $this->onlyCategories === null ? $given : array_intersect($this->onlyCategories, $given),
            $this->exceptCategories,
        ));

        return $only === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $only, [], $this->about);
    }

    /**
     * The scope seeing none of these categories: added to any earlier excepts,
     * or taken from the only categories seen, which left with none sees
     * nothing. Given none, it excepts nothing; it never means every category.
     *
     * @param  string  ...$categories
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function exceptCategories(string ...$categories): self
    {
        $given = self::categoryList(array_values($categories));

        if ($this->denied || $given === []) {
            return $this;
        }

        if ($this->onlyCategories !== null) {
            $only = array_values(array_diff($this->onlyCategories, $given));

            return $only === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $only, [], $this->about);
        }

        return new self(false, $this->tenants, $this->tenantless, null, self::categoryList([...$this->exceptCategories, ...$given]), $this->about);
    }

    /**
     * The scope seeing only the activity of these references, as the actor or
     * the subject of an entry, each matched as its type and id together: the
     * intersection with any earlier list. Given none, or left with none, the
     * scope sees nothing. It selects entries by who acted and who was acted on,
     * and is not on its own a complete disclosure policy: an entry about one of
     * them may name others.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$references
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function onlyAbout(Reference ...$references): self
    {
        $given = self::references(array_values($references), self::MAX_ABOUT, 'about-references');

        if ($this->denied) {
            return $this;
        }

        $about = $this->about === null ? $given : array_values(array_filter(
            $this->about,
            static fn (Reference $held): bool => array_filter($given, $held->equals(...)) !== [],
        ));

        return $about === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $this->onlyCategories, $this->exceptCategories, $about);
    }

    /**
     * Whether the scope sees nothing at all.
     *
     * @return bool
     */
    public function isDenied(): bool
    {
        return $this->denied;
    }

    /**
     * The one tenant of a scope that sees exactly one tenant and not the
     * entries of no tenant, or `null` for any other scope.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    public function singleTenant(): ?Reference
    {
        return !$this->tenantless && $this->tenants !== null && count($this->tenants) === 1 ? $this->tenants[0] : null;
    }

    /**
     * The tenants whose entries are seen, sorted, or `null` for every tenant.
     *
     * @return ?list<\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    public function tenantList(): ?array
    {
        return $this->tenants;
    }

    /**
     * Whether the entries with both tenant columns `null` are seen.
     *
     * @return bool
     */
    public function includesTenantless(): bool
    {
        return $this->tenantless;
    }

    /**
     * The only categories seen, sorted, or `null` for every category not
     * excepted.
     *
     * @return ?list<string>
     */
    public function categories(): ?array
    {
        return $this->onlyCategories;
    }

    /**
     * The categories never seen, sorted.
     *
     * @return list<string>
     */
    public function exceptedCategories(): array
    {
        return $this->exceptCategories;
    }

    /**
     * The references whose activity is seen, sorted, or `null` for anyone's.
     *
     * @return ?list<\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    public function aboutList(): ?array
    {
        return $this->about;
    }

    /**
     * The scope's normalised form: every list sorted bytewise, each reference
     * as its type and id, and a denied scope always the form of `none()`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{about: ?list<array{0: string, 1: string}>, denied: bool, except_categories: list<string>, only_categories: ?list<string>, tenantless: bool, tenants: ?list<array{0: string, 1: string}>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'about'             => self::pairs($this->about),
            'denied'            => $this->denied,
            'except_categories' => $this->exceptCategories,
            'only_categories'   => $this->onlyCategories,
            'tenantless'        => $this->tenantless,
            'tenants'           => self::pairs($this->tenants),
        ];
    }

    /**
     * The lower-case hex SHA-256 of the canonical encoding of the normalised
     * form.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function fingerprint(): string
    {
        return hash('sha256', CanonicalEncoder::encode($this->toArray()));
    }

    /**
     * The references, each exact pair once, sorted by type then id bytewise,
     * refused beyond the limit.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @param  int  $limit
     * @param  string  $what
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function references(array $references, int $limit, string $what): array
    {
        $unique = [];

        foreach ($references as $reference) {
            // A part holds no control character, so the NUL keeps the pair
            // apart and sorts it first
            $unique[$reference->type . "\0" . $reference->id] = $reference;
        }

        if (count($unique) > $limit) {
            throw new \InvalidArgumentException(sprintf('An access scope holds at most %d %s.', $limit, $what));
        }

        ksort($unique, SORT_STRING);

        return array_values($unique);
    }

    /**
     * The categories, each held to the definitions' grammar, each once, sorted
     * bytewise, refused beyond the limit.
     *
     * @param  list<string>  $categories
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function categoryList(array $categories): array
    {
        foreach ($categories as $category) {
            if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
                throw new \InvalidArgumentException('An access scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');
            }
        }

        $unique = array_values(array_unique($categories));

        if (count($unique) > self::MAX_CATEGORIES) {
            throw new \InvalidArgumentException(sprintf('An access scope holds at most %d categories in each list.', self::MAX_CATEGORIES));
        }

        sort($unique, SORT_STRING);

        return $unique;
    }

    /**
     * Each reference as its type and id, or `null` for no list.
     *
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @return ?list<array{0: string, 1: string}>
     */
    private static function pairs(?array $references): ?array
    {
        return $references === null ? null : array_map(static fn (Reference $reference): array => [$reference->type, $reference->id], $references);
    }
}
