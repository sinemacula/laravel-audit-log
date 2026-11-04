<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The entries a hold keeps: which tenants, whether entries of no tenant, whose
 * activity, which categories, when, and which import batch, every dimension
 * ANDed with the others.
 *
 * A scope starts from `all()`, every entry, `tenants()`, the entries of exactly
 * those tenants, each matched as its type and id together, or `tenantless()`,
 * the entries whose tenant type and tenant id are both `null`. It is then
 * narrowed: `withTenantless()` adds the entries of no tenant to a scope of
 * listed tenants; `about()` keeps the activity of the references given, as
 * actor or subject; `categories()` keeps those categories; `occurredBetween()`
 * keeps a half-open window, from its start inclusive to its end exclusive; and
 * `importBatch()` keeps one import's entries. Narrowing a dimension again
 * intersects with what it holds, so it never widens the scope. An empty list is
 * refused, never read as everything, and so is a narrowing that would leave a
 * dimension holding nothing: a hold that keeps no entry is a mistake, not a
 * hold. At most 100 tenants, 100 references and 50 categories are held, each
 * once. Every refusal is an `InvalidArgumentException` naming the dimension.
 *
 * The canonical form sorts every list bytewise, references by type then id, so
 * two scopes that keep the same entries by the same rules have the same form
 * and digest; it is what the journal signs and the projection stores, and
 * `fromArray()` reads it back strictly, refusing any other form with an
 * `UnexpectedValueException` naming the key.
 *
 * Whether a scope keeps an entry is answered by `matches()` over the entry's
 * stored row, in PHP and never in SQL, so any number of holds is evaluated
 * alike on every engine and no `NULL` comparison can make a tenant's hold keep
 * every entry of no tenant. A row whose time cannot be read is kept by any
 * window, so a hold never lets go of an entry it cannot place.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>
 */
final readonly class HoldScope implements Arrayable
{
    /** @var int The version of the canonical form. */
    public const int VERSION = 1;

    /** @var int Most tenants a scope holds. */
    public const int MAX_TENANTS = 100;

    /** @var int Most references a scope keeps the activity of. */
    public const int MAX_ABOUT = 100;

    /** @var int Most categories a scope holds. */
    public const int MAX_CATEGORIES = 50;

    /** @var list<string> The keys of the canonical form, each exactly once. */
    private const array KEYS = ['v', 'tenants', 'tenantless', 'about', 'categories', 'from', 'to', 'import_batch'];

    /** @var string Pattern of an import batch's id: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string Why a stored scope is refused, by the key it names. */
    private const string MALFORMED = 'A stored hold scope\'s `%s` is malformed.';

    /** @var string Why a window is refused that starts at or after its end. */
    private const string BACKWARD_WINDOW = 'A hold scope\'s window must start before it ends.';

    /**
     * Constructor.
     *
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $tenants
     * @param  bool  $tenantless
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $about
     * @param  ?list<string>  $categories
     * @param  ?string  $from
     * @param  ?string  $to
     * @param  ?string  $importBatch
     */
    private function __construct(

        /** The tenants whose entries are kept, sorted, or `null` for every tenant. */
        #[\SensitiveParameter]
        private ?array $tenants,

        /** Whether the entries with both tenant columns `null` are kept. */
        private bool $tenantless,

        /** The references whose activity, as actor or subject, is kept, sorted, or `null` for anyone's. */
        #[\SensitiveParameter]
        private ?array $about,

        /** The categories kept, sorted, or `null` for every category. */
        private ?array $categories,

        /** The instant the window starts at, inclusive, or `null` for none. */
        private ?string $from,

        /** The instant the window ends before, or `null` for none. */
        private ?string $to,

        /** The import batch whose entries are kept, or `null` for any. */
        private ?string $importBatch,
    ) {}

    /**
     * A scope that keeps every entry: every tenant, the entries of no tenant,
     * anyone's activity, every category, at any time, of any batch.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self(null, true, null, null, null, null, null);
    }

    /**
     * A scope that keeps the entries of exactly these tenants, each matched as
     * its type and id together, and not the entries of no tenant. Each tenant
     * counts once; at least one is given and at most 100.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$tenants
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function tenants(#[\SensitiveParameter] Reference ...$tenants): self
    {
        return new self(self::references(array_values($tenants), self::MAX_TENANTS, 'tenants'), false, null, null, null, null, null);
    }

    /**
     * A scope that keeps only the entries whose tenant type and tenant id are
     * both `null`.
     *
     * @return self
     */
    public static function tenantless(): self
    {
        return new self([], true, null, null, null, null, null);
    }

    /**
     * The scope with the entries of no tenant added, under its other
     * dimensions. A scope of every tenant, or of no tenant, already keeps them.
     *
     * @return self
     */
    public function withTenantless(): self
    {
        return new self($this->tenants, true, $this->about, $this->categories, $this->from, $this->to, $this->importBatch);
    }

    /**
     * The scope keeping only the activity of these references, as the actor or
     * the subject of an entry, each matched as its type and id together: the
     * intersection with any earlier list. At least one is given, at most 100,
     * and the intersection must keep one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$references
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function about(#[\SensitiveParameter] Reference ...$references): self
    {
        $given = self::references(array_values($references), self::MAX_ABOUT, 'about-references');
        $held  = $this->about;

        $about = $held === null ? $given : array_values(array_filter(
            $given,
            static fn (#[\SensitiveParameter] Reference $reference): bool => self::holdsPair($held, $reference->type, $reference->id),
        ));

        if ($about === []) {
            throw new \InvalidArgumentException('A hold scope\'s about-references, narrowed again, would hold nothing.');
        }

        return new self($this->tenants, $this->tenantless, $about, $this->categories, $this->from, $this->to, $this->importBatch);
    }

    /**
     * The scope keeping only these categories: the intersection with any
     * earlier list. At least one is given, at most 50, each held to the
     * definitions' grammar, and the intersection must keep one.
     *
     * @param  string  ...$categories
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function categories(string ...$categories): self
    {
        $given = self::categoryList(array_values($categories));
        $kept  = $this->categories === null ? $given : array_values(array_intersect($given, $this->categories));

        if ($kept === []) {
            throw new \InvalidArgumentException('A hold scope\'s categories, narrowed again, would hold nothing.');
        }

        return new self($this->tenants, $this->tenantless, $this->about, $kept, $this->from, $this->to, $this->importBatch);
    }

    /**
     * The scope keeping only the entries that occurred in the half-open window:
     * at or after its start and before its end, either of which may be open but
     * not both. Narrowing it again keeps the later start and the earlier end,
     * and the window must start before it ends.
     *
     * @param  ?\DateTimeInterface  $from
     * @param  ?\DateTimeInterface  $to
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function occurredBetween(?\DateTimeInterface $from, ?\DateTimeInterface $to): self
    {
        if ($from === null && $to === null) {
            throw new \InvalidArgumentException('A hold scope\'s window must have a start, an end or both.');
        }

        $start = $from === null ? $this->from : StoredTime::format($from);
        $end   = $to   === null ? $this->to : StoredTime::format($to);
        $start = $this->from !== null && $start !== null && strcmp($this->from, $start) > 0 ? $this->from : $start;
        $end   = $this->to   !== null && $end !== null && strcmp($this->to, $end) < 0 ? $this->to : $end;

        if ($start !== null && $end !== null && strcmp($start, $end) >= 0) {
            throw new \InvalidArgumentException(self::BACKWARD_WINDOW);
        }

        return new self($this->tenants, $this->tenantless, $this->about, $this->categories, $start, $end, $this->importBatch);
    }

    /**
     * The scope keeping only the entries of one import batch, by its id, a
     * lower-case UUID. A scope keeps one batch: narrowing it to another would
     * keep nothing.
     *
     * @param  string  $batchId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function importBatch(string $batchId): self
    {
        if (preg_match(self::UUID_PATTERN, $batchId) !== 1) {
            throw new \InvalidArgumentException('A hold scope\'s import batch must be a lower-case UUID.');
        }

        if ($this->importBatch !== null && $this->importBatch !== $batchId) {
            throw new \InvalidArgumentException('A hold scope\'s import batch, narrowed again, would hold nothing.');
        }

        return new self($this->tenants, $this->tenantless, $this->about, $this->categories, $this->from, $this->to, $batchId);
    }

    /**
     * The scope's canonical form: its version, each list sorted bytewise,
     * references as their type and id by type then id, `null` for a dimension
     * left open, and the window's instants in the package's form.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{v: int, tenants: ?list<array{0: string, 1: string}>, tenantless: bool, about: ?list<array{0: string, 1: string}>, categories: ?list<string>, from: ?string, to: ?string, import_batch: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        $pairs = static fn (?array $references): ?array => $references === null ? null : array_values(array_map(
            static fn (#[\SensitiveParameter] Reference $reference): array => [$reference->type, $reference->id],
            $references,
        ));

        return [
            'v'            => self::VERSION,
            'tenants'      => $pairs($this->tenants),
            'tenantless'   => $this->tenantless,
            'about'        => $pairs($this->about),
            'categories'   => $this->categories,
            'from'         => $this->from,
            'to'           => $this->to,
            'import_batch' => $this->importBatch,
        ];
    }

    /**
     * The lower-case hex SHA-256 of the canonical encoding of the canonical
     * form.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function digest(): string
    {
        return hash('sha256', CanonicalEncoder::encode($this->toArray()));
    }

    /**
     * The scope of a stored canonical form, read strictly: exactly its keys, a
     * scope the builders accept, and the canonical form of that scope, so a
     * value of the wrong type, a list out of order, a reference twice, a limit
     * exceeded or a dimension that keeps nothing is refused, naming the key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     *
     * @internal
     */
    public static function fromArray(#[\SensitiveParameter] array $stored): self
    {
        $missing = array_values(array_diff(self::KEYS, array_map(strval(...), array_keys($stored))));

        if ($missing !== []) {
            throw new \UnexpectedValueException(sprintf(self::MALFORMED, $missing[0]));
        }

        if (count($stored) !== count(self::KEYS)) {
            throw new \UnexpectedValueException('A stored hold scope holds a key it does not define.');
        }

        $instant = static fn (mixed $end): ?\DateTimeInterface => is_string($end) && StoredTime::isInstant($end) ? StoredTime::instant(StoredTime::toStorage($end)) : null;
        $scope   = self::rebuilt($stored, $instant($stored['from']), $instant($stored['to']));

        foreach ($scope->toArray() as $key => $value) {
            if ($value !== $stored[$key]) {
                throw new \UnexpectedValueException(sprintf(self::MALFORMED, $key));
            }
        }

        return $scope;
    }

    /**
     * Whether the scope keeps the entry of the stored row, every dimension
     * ANDed: a row of no tenant only when the scope keeps those, any other only
     * when its tenant pair is one held or every tenant is; its actor's or its
     * subject's pair one held; its category one held; its import batch the one
     * held; and its time within the window.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return bool
     *
     * @internal
     */
    public function matches(#[\SensitiveParameter] array $row): bool
    {
        $batch    = $row['import_batch_id'] ?? null;
        $category = $row['category']        ?? null;

        return $this->holdsPartiesOf($row)
            && in_array($category, $this->categories ?? [$category], true)
            && ($this->importBatch ?? $batch) === $batch
            && $this->holdsTimeOf($row);
    }

    /**
     * Whether the row's parties are held: its tenant pair one held, or every
     * tenant held, and a row of no tenant only when those are; and its actor's
     * or its subject's pair one held, or anyone's activity held.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return bool
     */
    private function holdsPartiesOf(#[\SensitiveParameter] array $row): bool
    {
        $tenantType = $row['tenant_type'] ?? null;
        $tenantId   = $row['tenant_id']   ?? null;
        $tenantless = $tenantType === null && $tenantId === null;
        $tenant     = $tenantless ? $this->tenantless : self::holdsPair($this->tenants, $tenantType, $tenantId);

        $actor   = self::holdsPair($this->about, $row['actor_type'] ?? null, $row['actor_id'] ?? null);
        $subject = self::holdsPair($this->about, $row['subject_type'] ?? null, $row['subject_id'] ?? null);

        return $tenant && ($actor || $subject);
    }

    /**
     * Whether the row's time is within the window: at or after its start and
     * before its end. A scope with no window holds any time, and a row whose
     * time cannot be read is held by any window.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return bool
     */
    private function holdsTimeOf(#[\SensitiveParameter] array $row): bool
    {
        $stored = $row['occurred_at'] ?? null;

        if (($this->from === null && $this->to === null) || !is_string($stored)) {
            return true;
        }

        try {
            $occurred = StoredTime::fromStorage($stored);
        } catch (\UnexpectedValueException) {
            return true;
        }

        return ($this->from === null || strcmp($occurred, $this->from) >= 0) && ($this->to === null || strcmp($occurred, $this->to) < 0);
    }

    /**
     * The references, each exact pair once, sorted by type then id bytewise: at
     * least one, and refused beyond the limit.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @param  int  $limit
     * @param  string  $what
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function references(#[\SensitiveParameter] array $references, int $limit, string $what): array
    {
        $unique = [];

        foreach ($references as $reference) {
            // A part holds no control character, so the NUL keeps the pair
            // apart and sorts it first
            $unique[$reference->type . "\0" . $reference->id] = $reference;
        }

        if ($unique === []) {
            throw new \InvalidArgumentException(sprintf('A hold scope\'s %s must name at least one; an empty list never means everything.', $what));
        }

        if (count($unique) > $limit) {
            throw new \InvalidArgumentException(sprintf('A hold scope holds at most %d %s.', $limit, $what));
        }

        ksort($unique, SORT_STRING);

        return array_values($unique);
    }

    /**
     * The categories, each held to the definitions' grammar, each once, sorted
     * bytewise: at least one, and refused beyond the limit.
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
                throw new \InvalidArgumentException('A hold scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');
            }
        }

        $unique = array_values(array_unique($categories));

        if ($unique === []) {
            throw new \InvalidArgumentException('A hold scope\'s categories must name at least one; an empty list never means everything.');
        }

        if (count($unique) > self::MAX_CATEGORIES) {
            throw new \InvalidArgumentException(sprintf('A hold scope holds at most %d categories.', self::MAX_CATEGORIES));
        }

        sort($unique, SORT_STRING);

        return $unique;
    }

    /**
     * Whether the references hold the pair: every pair when there is no list,
     * and otherwise a type and an id, both text, equal to one of them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @param  mixed  $type
     * @param  mixed  $id
     * @return bool
     */
    private static function holdsPair(#[\SensitiveParameter] ?array $references, mixed $type, mixed $id): bool
    {
        return $references === null || array_filter(
            $references,
            static fn (#[\SensitiveParameter] Reference $reference): bool => $reference->type === $type && $reference->id === $id,
        ) !== [];
    }

    /**
     * The scope the builders make of a stored form's values and its window's
     * ends, each value of the wrong type left out, so the canonical form it
     * gives differs from the stored one there; a value the builders refuse is
     * refused, naming its key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  ?\DateTimeInterface  $from
     * @param  ?\DateTimeInterface  $to
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    private static function rebuilt(#[\SensitiveParameter] array $stored, ?\DateTimeInterface $from, ?\DateTimeInterface $to): self
    {
        $tenants    = self::storedReferences($stored['tenants'], 'tenants');
        $about      = self::storedReferences($stored['about'], 'about');
        $categories = array_values(array_filter((array) $stored['categories'], is_string(...)));
        $key        = 'tenants';

        try {
            $scope = match (true) {
                $tenants === null => self::all(),
                $tenants === []   => self::tenantless(),
                default           => self::tenants(...$tenants),
            };

            $scope = $stored['tenantless'] === true ? $scope->withTenantless() : $scope;
            $key   = 'about';
            $scope = $about === null ? $scope : $scope->about(...$about);
            $key   = 'categories';
            $scope = $categories === [] ? $scope : $scope->categories(...$categories);
            $key   = 'to';
            $scope = $from === null && $to === null ? $scope : $scope->occurredBetween($from, $to);
            $key   = 'import_batch';

            return is_string($stored['import_batch']) ? $scope->importBatch($stored['import_batch']) : $scope;
        } catch (\InvalidArgumentException) {
            throw new \UnexpectedValueException(sprintf(self::MALFORMED, $key));
        }
    }

    /**
     * The references of a stored list of type and id pairs, or `null` for
     * none; anything else is refused, naming the key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $stored
     * @param  'about'|'tenants'  $key
     * @return ?list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \UnexpectedValueException
     */
    private static function storedReferences(#[\SensitiveParameter] mixed $stored, string $key): ?array
    {
        if ($stored === null) {
            return null;
        }

        $isPair = static fn (mixed $pair): bool => is_array($pair) && array_map(gettype(...), $pair) === ['string', 'string'];
        $pairs  = is_array($stored) && array_is_list($stored) ? array_filter($stored, $isPair) : [];

        if ($pairs !== $stored) {
            throw new \UnexpectedValueException(sprintf(self::MALFORMED, $key));
        }

        try {
            return array_values(array_map(static fn (array $pair): Reference => Reference::of($pair[0], $pair[1]), $pairs));
        } catch (\InvalidArgumentException) {
            throw new \UnexpectedValueException(sprintf(self::MALFORMED, $key));
        }
    }
}
