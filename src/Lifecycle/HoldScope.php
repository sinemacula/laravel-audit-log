<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The entries a hold keeps, every dimension ANDed; narrowing again only
 * intersects, and an empty list or a scope that keeps nothing is refused.
 *
 * Matching runs in PHP, never SQL, so no `NULL` comparison can make a tenant's
 * hold keep every tenantless entry.
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

    /** @var list<string> The keys of the canonical form. */
    private const array KEYS = ['v', 'tenants', 'tenantless', 'about', 'categories', 'from', 'to', 'import_batch'];

    /** @var string An import batch id: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string Why a stored scope is refused, by key. */
    private const string MALFORMED = 'A stored hold scope\'s `%s` is malformed.';

    /** @var string Why a window that does not start before its end is refused. */
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

        /** The tenants kept, sorted, or `null` for every tenant. */
        #[\SensitiveParameter]
        private ?array $tenants,

        /** Whether the entries with both tenant columns `null` are kept. */
        private bool $tenantless,

        /** The actors or subjects kept, sorted, or `null` for anyone's. */
        #[\SensitiveParameter]
        private ?array $about,

        /** The categories kept, sorted, or `null` for every category. */
        private ?array $categories,

        /** The instant the window starts at, inclusive, or `null` for none. */
        private ?string $from,

        /** The instant the window ends at, exclusive, or `null` for none. */
        private ?string $to,

        /** The import batch whose entries are kept, or `null` for any. */
        private ?string $importBatch,
    ) {}

    /**
     * A scope that keeps every entry.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self(null, true, null, null, null, null, null);
    }

    /**
     * A scope that keeps the entries of exactly these tenants, 1 to 100, and
     * not the tenantless ones.
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
     * A scope that keeps only the entries whose tenant columns are both `null`.
     *
     * @return self
     */
    public static function tenantless(): self
    {
        return new self([], true, null, null, null, null, null);
    }

    /**
     * The scope with the tenantless entries added.
     *
     * @return self
     */
    public function withTenantless(): self
    {
        return new self($this->tenants, true, $this->about, $this->categories, $this->from, $this->to, $this->importBatch);
    }

    /**
     * The scope keeping only the activity of these references, 1 to 100, as
     * actor or subject.
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
     * The scope keeping only these categories, 1 to 50.
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
     * The scope keeping only the entries in the half-open window; either end
     * may be open, not both.
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
     * The scope keeping only the entries of one import batch.
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
     * The canonical form the journal signs, with every list sorted bytewise and
     * `null` for an open dimension.
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
     * The lower-case hex SHA-256 of the canonical form.
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
     * The scope of a stored canonical form, refusing any form that is not
     * exactly canonical.
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
     * Whether the scope keeps the entry of the stored row.
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
     * Whether the row's tenant and its actor or subject are held.
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
     * Whether the row's time is within the window; an unreadable time is held,
     * so a hold never lets go of an entry it cannot place.
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
     * The distinct references sorted by type then id, 1 to the limit.
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
            // Parts hold no control character, so NUL separates and sorts first
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
     * The distinct valid categories sorted bytewise, 1 to the limit.
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
     * Whether the references hold the pair; a `null` list holds every pair.
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
     * The scope the builders make of a stored form, values of the wrong type
     * left out so its canonical form differs.
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
     * The references of a stored list of type and id pairs, or `null` for none.
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
