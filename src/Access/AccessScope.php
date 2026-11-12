<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The entries a viewer may see, as an access policy answers for one read: which
 * tenants, whether entries of no tenant, which categories, and whose activity.
 *
 * Narrowing only intersects and an empty list denies; `withTenantless()` is the
 * only way to add entries, and a denied scope stays denied. Each operation
 * returns a new scope, and equal scopes share one normalised form.
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
     * @param  bool  $reveal
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

        /** Whether the encrypted fields of the entries seen are revealed through the field reader. */
        private bool $reveal,
    ) {}

    /**
     * A scope that sees nothing.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(true, [], false, [], [], [], false);
    }

    /**
     * A scope that sees every entry: every tenant, the entries of no tenant,
     * every category and anyone's activity.
     *
     * Called on an instance, it starts a fresh scope and discards that
     * instance's restrictions.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self(false, null, true, null, [], null, false);
    }

    /**
     * A scope that sees the entries of exactly these tenants, each matched as
     * its type and id together, and not the entries of no tenant. Each tenant
     * counts once; given none, the scope sees nothing.
     *
     * Called on an instance, it starts a fresh scope and discards that
     * instance's restrictions.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$tenants
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function tenants(Reference ...$tenants): self
    {
        $held = ScopeValues::references(array_values($tenants), self::MAX_TENANTS, 'tenants');

        return $held === [] ? self::none() : new self(false, $held, false, null, [], null, false);
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

        return new self(false, $this->tenants, true, $this->onlyCategories, $this->exceptCategories, $this->about, $this->reveal);
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
        $given = ScopeValues::categoryList(array_values($categories));

        if ($this->denied) {
            return $this;
        }

        $only = array_values(array_diff(
            $this->onlyCategories === null ? $given : array_intersect($this->onlyCategories, $given),
            $this->exceptCategories,
        ));

        return $only === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $only, [], $this->about, $this->reveal);
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
        $given = ScopeValues::categoryList(array_values($categories));

        if ($this->denied || $given === []) {
            return $this;
        }

        if ($this->onlyCategories !== null) {
            $only = array_values(array_diff($this->onlyCategories, $given));

            return $only === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $only, [], $this->about, $this->reveal);
        }

        return new self(false, $this->tenants, $this->tenantless, null, ScopeValues::categoryList([...$this->exceptCategories, ...$given]), $this->about, $this->reveal);
    }

    /**
     * The scope seeing only the activity of these references, as the actor or
     * the subject of an entry, each matched as its type and id together: the
     * intersection with any earlier list. Given none, or left with none, the
     * scope sees nothing. An entry about one of them may still name others.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$references
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function onlyAbout(Reference ...$references): self
    {
        $given = ScopeValues::references(array_values($references), self::MAX_ABOUT, 'about-references');

        if ($this->denied) {
            return $this;
        }

        $about = $this->about === null ? $given : array_values(array_filter(
            $this->about,
            static fn (Reference $held): bool => array_filter($given, $held->equals(...)) !== [],
        ));

        return $about === [] ? self::none() : new self(false, $this->tenants, $this->tenantless, $this->onlyCategories, $this->exceptCategories, $about, $this->reveal);
    }

    /**
     * The scope with the encrypted fields of the entries it sees revealed
     * through the field reader, from rows whose signature verifies, whoever
     * owns them. A denied scope stays denied.
     *
     * @return self
     */
    public function revealingEncryptedFields(): self
    {
        if ($this->denied) {
            return $this;
        }

        return new self(false, $this->tenants, $this->tenantless, $this->onlyCategories, $this->exceptCategories, $this->about, true);
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
     * Whether the encrypted fields of the entries seen are revealed through the
     * field reader; never for a denied scope.
     *
     * @return bool
     */
    public function revealsEncryptedFields(): bool
    {
        return $this->reveal;
    }

    /**
     * The scope's normalised form: every list sorted bytewise, each reference
     * as its type and id, and a denied scope always the form of `none()`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{about: ?list<array{0: string, 1: string}>, denied: bool, except_categories: list<string>, only_categories: ?list<string>, reveal: bool, tenantless: bool, tenants: ?list<array{0: string, 1: string}>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'about'             => ScopeValues::pairs($this->about),
            'denied'            => $this->denied,
            'except_categories' => $this->exceptCategories,
            'only_categories'   => $this->onlyCategories,
            'reveal'            => $this->reveal,
            'tenantless'        => $this->tenantless,
            'tenants'           => ScopeValues::pairs($this->tenants),
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
}
