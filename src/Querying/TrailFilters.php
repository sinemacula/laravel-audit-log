<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\CorrelationId;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * What a read is narrowed to, validated as given; each `with...()` replaces its
 * dimension, and a refusal names the filter, never the value.
 *
 * Lists are deduplicated and sorted so the normalised form, which a read's
 * record fingerprints, is the same however the filters were given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrailFilters
{
    /** @var int Most event codes a filter holds. */
    public const int MAX_CODES = 50;

    /** @var int Most categories a filter holds. */
    public const int MAX_CATEGORIES = 50;

    /** @var int Longest event code prefix, in bytes: one short of the `event` column. */
    public const int MAX_PREFIX_BYTES = 190;

    /** @var string Lower-case dotted segments ending in a dot. */
    private const string PREFIX_PATTERN = '/\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.\z/';

    /** @var list<string> The dimensions a reference filters on. */
    private const array REFERENCES = ['actor', 'subject', 'principal', 'tenant'];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  list<string>  $events
     * @param  ?string  $eventPrefix
     * @param  list<string>  $categories
     * @param  list<string>  $outcomes
     * @param  ?string  $from
     * @param  ?string  $to
     * @param  ?string  $correlationId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $holding
     */
    private function __construct(

        /** The actor the entries name, or `null` for any. */
        public ?Reference $actor = null,

        /** The subject the entries name, or `null` for any. */
        public ?Reference $subject = null,

        /** The principal the entries name, or `null` for any. */
        public ?Reference $principal = null,

        /** The tenant the entries name, or `null` for any. */
        public ?Reference $tenant = null,

        /** The exact codes, sorted, or none for any. */
        public array $events = [],

        /** The code prefix, or `null` for any. */
        public ?string $eventPrefix = null,

        /** The categories, sorted, or none for any. */
        public array $categories = [],

        /** The stored outcomes, sorted, or none for any. */
        public array $outcomes = [],

        /** The inclusive start instant, or `null` for no limit. */
        public ?string $from = null,

        /** The exclusive end instant, or `null` for no limit. */
        public ?string $to = null,

        /** The correlation id the entries carry, or `null` for any. */
        public ?string $correlationId = null,

        /** The owner whose key sealed a fragment of each entry, or `null`. */
        public ?Reference $holding = null,
    ) {}

    /**
     * Filters that narrow nothing.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * The filters narrowed to the reference in the dimension.
     *
     * @param  string  $dimension
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withReference(string $dimension, Reference $reference): self
    {
        if (!in_array($dimension, self::REFERENCES, true)) {
            throw new \InvalidArgumentException('A reference filter must be on the actor, the subject, the principal or the tenant.');
        }

        return new self(...[...$this->fields(), $dimension => $reference]);
    }

    /**
     * The filters narrowed to these exact codes, reserved ones included,
     * replacing any codes or prefix.
     *
     * @param  list<\BackedEnum|string>  $codes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withEvents(array $codes): self
    {
        try {
            $events = array_map(static fn (\BackedEnum|string $code): string => EventCode::forReading($code)->value, $codes);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException('An event filter\'s codes must each be lower-case dotted segments of at most 191 bytes, such as `invoice.approved`.');
        }

        $events = self::sorted($events);

        if ($events === [] || count($events) > self::MAX_CODES) {
            throw new \InvalidArgumentException(sprintf('An event filter must hold from 1 to %d codes.', self::MAX_CODES));
        }

        return new self(...[...$this->fields(), 'events' => $events, 'eventPrefix' => null]);
    }

    /**
     * The filters narrowed to codes under the prefix, replacing any codes or
     * prefix.
     *
     * @param  string  $prefix
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withEventPrefix(string $prefix): self
    {
        if (strlen($prefix) > self::MAX_PREFIX_BYTES || preg_match(self::PREFIX_PATTERN, $prefix) !== 1) {
            $message = sprintf('An event prefix filter must be lower-case dotted segments ending in a dot, such as `invoice.`, of at most %d bytes.', self::MAX_PREFIX_BYTES);

            throw new \InvalidArgumentException($message);
        }

        return new self(...[...$this->fields(), 'events' => [], 'eventPrefix' => $prefix]);
    }

    /**
     * The filters narrowed to these categories.
     *
     * @param  list<string>  $categories
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withCategories(array $categories): self
    {
        foreach ($categories as $category) {
            if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
                throw new \InvalidArgumentException('A category filter\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');
            }
        }

        $categories = self::sorted($categories);

        if ($categories === [] || count($categories) > self::MAX_CATEGORIES) {
            throw new \InvalidArgumentException(sprintf('A category filter must hold from 1 to %d categories.', self::MAX_CATEGORIES));
        }

        return new self(...[...$this->fields(), 'categories' => $categories]);
    }

    /**
     * The filters narrowed to these outcomes.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Enums\Outcome>  $outcomes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withOutcomes(array $outcomes): self
    {
        if ($outcomes === []) {
            throw new \InvalidArgumentException('An outcome filter must hold at least one outcome.');
        }

        $values = self::sorted(array_map(static fn (Outcome $outcome): string => $outcome->value, $outcomes));

        return new self(...[...$this->fields(), 'outcomes' => $values]);
    }

    /**
     * The filters narrowed to `[from, to)`; `null` is unbounded, and both
     * `null` clears the window.
     *
     * @param  ?\DateTimeInterface  $from
     * @param  ?\DateTimeInterface  $to
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withWindow(?\DateTimeInterface $from, ?\DateTimeInterface $to): self
    {
        $start = $from === null ? null : StoredTime::format($from);
        $end   = $to   === null ? null : StoredTime::format($to);

        if ($start !== null && $end !== null && $start >= $end) {
            throw new \InvalidArgumentException('A time window filter must end after it starts.');
        }

        return new self(...[...$this->fields(), 'from' => $start, 'to' => $end]);
    }

    /**
     * The filters narrowed to the correlation id.
     *
     * @param  string  $correlationId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withCorrelation(string $correlationId): self
    {
        if (!CorrelationId::isValid($correlationId)) {
            throw new \InvalidArgumentException('A correlation filter must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.');
        }

        return new self(...[...$this->fields(), 'correlationId' => $correlationId]);
    }

    /**
     * The filters narrowed to entries holding a fragment sealed under any of
     * the owner's keys, erased or not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return self
     */
    public function withHoldingDataOf(#[\SensitiveParameter] Reference $owner): self
    {
        return new self(...[...$this->fields(), 'holding' => $owner]);
    }

    /**
     * The filters' normalised form, keys sorted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{actor: ?array{0: string, 1: string}, categories: list<string>, correlation_id: ?string, event_prefix: ?string, events: list<string>, from: ?string, holding_data_of: ?array{0: string, 1: string}, outcomes: list<string>, principal: ?array{0: string, 1: string}, subject: ?array{0: string, 1: string}, tenant: ?array{0: string, 1: string}, to: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function normalised(): array
    {
        return [
            'actor'           => self::pair($this->actor),
            'categories'      => $this->categories,
            'correlation_id'  => $this->correlationId,
            'event_prefix'    => $this->eventPrefix,
            'events'          => $this->events,
            'from'            => $this->from,
            'holding_data_of' => self::pair($this->holding),
            'outcomes'        => $this->outcomes,
            'principal'       => self::pair($this->principal),
            'subject'         => self::pair($this->subject),
            'tenant'          => self::pair($this->tenant),
            'to'              => $this->to,
        ];
    }

    /**
     * Every field by its constructor name, for a copy that replaces some.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{actor: ?\SineMacula\Laravel\AuditLog\Records\Reference, subject: ?\SineMacula\Laravel\AuditLog\Records\Reference, principal: ?\SineMacula\Laravel\AuditLog\Records\Reference, tenant: ?\SineMacula\Laravel\AuditLog\Records\Reference, events: list<string>, eventPrefix: ?string, categories: list<string>, outcomes: list<string>, from: ?string, to: ?string, correlationId: ?string, holding: ?\SineMacula\Laravel\AuditLog\Records\Reference}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function fields(): array
    {
        return [
            'actor'         => $this->actor,
            'subject'       => $this->subject,
            'principal'     => $this->principal,
            'tenant'        => $this->tenant,
            'events'        => $this->events,
            'eventPrefix'   => $this->eventPrefix,
            'categories'    => $this->categories,
            'outcomes'      => $this->outcomes,
            'from'          => $this->from,
            'to'            => $this->to,
            'correlationId' => $this->correlationId,
            'holding'       => $this->holding,
        ];
    }

    /**
     * The values, each once, sorted bytewise.
     *
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        $unique = array_values(array_unique($values));

        sort($unique, SORT_STRING);

        return $unique;
    }

    /**
     * The reference as its type and id, or `null`.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return ?array{0: string, 1: string}
     */
    private static function pair(?Reference $reference): ?array
    {
        return $reference === null ? null : [$reference->type, $reference->id];
    }
}
