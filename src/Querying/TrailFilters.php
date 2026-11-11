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
 * What a caller narrows a read of the trail to, validated as it is given: who
 * acted, on what, for whom and in which tenant, which codes or which codes
 * under a prefix, which categories and outcomes, when, under which correlation
 * id, and which owner holds an encrypted fragment in each entry.
 *
 * Each dimension is replaced, never merged, by its own `with...()` method, and
 * the exact codes and a prefix are one dimension, so either replaces the other.
 * Lists are kept each value once and sorted, and times in UTC to the
 * microsecond, so the normalised form names the filters however they were
 * given, and a read's record fingerprints that form under a key. Nothing here
 * becomes SQL text: the scope compiler binds every value. A refusal names the
 * filter, never the value given.
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

    /** @var int Longest event code prefix, in bytes: one short of the `event` column, so a code can follow it. */
    public const int MAX_PREFIX_BYTES = 190;

    /** @var string Pattern of an event code prefix: lower-case dotted segments, each a letter, then letters, digits or underscores, ending in a dot. */
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

        /** The exact codes the entries have, sorted, or none for any code. */
        public array $events = [],

        /** The prefix every code the entries have begins with, or `null` for any. */
        public ?string $eventPrefix = null,

        /** The categories the entries are in, sorted, or none for any. */
        public array $categories = [],

        /** The outcomes the entries have, as stored, sorted, or none for any. */
        public array $outcomes = [],

        /** The earliest time an entry occurred, inclusive, as an instant, or `null` for no limit. */
        public ?string $from = null,

        /** The time every entry occurred before, exclusive, as an instant, or `null` for no limit. */
        public ?string $to = null,

        /** The correlation id the entries carry, or `null` for any. */
        public ?string $correlationId = null,

        /** The owner whose key sealed a fragment of each entry, or `null` for any. */
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
     * The filters with the entries narrowed to those naming the reference as
     * their actor, subject, principal or tenant, replacing any earlier one.
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
     * The filters with the entries narrowed to these exact codes, under any
     * prefix, the reserved one included: each held to the code grammar, kept
     * once and sorted, from one to the limit. They replace any earlier codes
     * and any prefix.
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
     * The filters with the entries narrowed to the codes under the prefix: one
     * or more lower-case dotted segments ending in a dot, at most 190 bytes. It
     * replaces any earlier prefix and any exact codes.
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
     * The filters with the entries narrowed to these categories, each held to
     * the definitions' grammar, kept once and sorted, from one to the limit,
     * replacing any earlier ones.
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
     * The filters with the entries narrowed to these outcomes, at least one,
     * each kept once, replacing any earlier ones.
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
     * The filters with the entries narrowed to those that occurred from the
     * first time, inclusive, before the second, exclusive, each in UTC to the
     * microsecond; either may be `null` for no limit, and both `null` clears
     * the window. A window that ends where or before it starts is refused.
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
     * The filters with the entries narrowed to those carrying the correlation
     * id, held to the grammar a record's builder holds it to, replacing any
     * earlier one.
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
     * The filters with the entries narrowed to those holding a fragment sealed
     * under one of the owner's keys, whatever its tenant, category or
     * generation, erased or not, replacing any earlier owner.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return self
     */
    public function withHoldingDataOf(#[\SensitiveParameter] Reference $owner): self
    {
        return new self(...[...$this->fields(), 'holding' => $owner]);
    }

    /**
     * The filters' normalised form, its keys sorted: each reference, the owner
     * holding data included, as its type and id or `null`, each list sorted,
     * each time an instant or `null`.
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
     * Every field of the filters by its constructor's name, for a copy that
     * replaces some of them.
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
