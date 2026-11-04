<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * One line of an import file as it was read and validated, in either format:
 * the source that asserted it and the record's id there, what the line asserts
 * happened, and how many values shaped as encrypted envelopes, or descriptors
 * of artifacts not imported, were removed from it.
 *
 * Its source assertion is what the line asserts, exactly as given and before
 * anything is minimised or encrypted: the code, the occurrence time, the
 * outcome, the references as their type and id, the reason, the correlation id,
 * the properties, the context, the origin and the IP address. The keyed digest
 * of the assertion tells a repeated import of the line from one that conflicts
 * with it; the category and the source's region are not asserted, since a
 * definition decides the one and the import the other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportLine
{
    /** @var int The version of the source assertion's form. */
    public const int ASSERTION_VERSION = 1;

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $number
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  string  $sourceRecordId
     * @param  string  $event
     * @param  string  $occurredAt
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $category
     * @param  ?string  $correlationId
     * @param  ?array<array-key, mixed>  $properties
     * @param  ?array<array-key, mixed>  $context
     * @param  ?string  $origin
     * @param  ?string  $ip
     * @param  int  $dropped
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The line's number in its file, from 1. */
        public int $number,

        /** The source that first asserted the record. */
        public string $sourceId,

        /** That source's region, if it is known. */
        public ?string $sourceRegion,

        /** The record's id at that source. */
        public string $sourceRecordId,

        /** The event code, validated and outside the reserved prefix. */
        public string $event,

        /** When the activity happened, as an instant in the package's form. */
        public string $occurredAt,

        /** How the activity ended. */
        public Outcome $outcome,

        /** Why it failed or was denied, as a machine-readable code, if given. */
        public ?string $reason,

        /** Who acted, if anyone. */
        #[\SensitiveParameter]
        public ?Reference $actor,

        /** What was acted on, if anything. */
        #[\SensitiveParameter]
        public ?Reference $subject,

        /** On whose behalf, if not the actor's. */
        #[\SensitiveParameter]
        public ?Reference $principal,

        /** The tenant the activity happened in, if any. */
        #[\SensitiveParameter]
        public ?Reference $tenant,

        /** The category the line names, used when its code is not registered. */
        public ?string $category,

        /** The correlation id, if given. */
        public ?string $correlationId,

        /** The properties, as given less what was dropped, or `null`. */
        #[\SensitiveParameter]
        public ?array $properties,

        /** The context, as given less what was dropped, or `null`. */
        #[\SensitiveParameter]
        public ?array $context,

        /** Where the activity ran, as one of this package's origins, or `null` when the source does not know. */
        public ?string $origin,

        /** The client's IP address as given, or `null`. */
        #[\SensitiveParameter]
        public ?string $ip,

        /** How many envelope-shaped values and descriptors were removed from the line. */
        public int $dropped = 0,
    ) {}

    /**
     * The line's source assertion: what it asserts, exactly as given and before
     * minimisation or encryption, with each reference as its type and id or
     * `null`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{v: int, event: string, occurred_at: string, outcome: string, actor: ?array{0: string, 1: string}, subject: ?array{0: string, 1: string}, principal: ?array{0: string, 1: string}, tenant: ?array{0: string, 1: string}, reason: ?string, correlation_id: ?string, properties: ?array<array-key, mixed>, context: ?array<array-key, mixed>, origin: ?string, ip: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function assertion(): array
    {
        return [
            'v'              => self::ASSERTION_VERSION,
            'event'          => $this->event,
            'occurred_at'    => $this->occurredAt,
            'outcome'        => $this->outcome->value,
            'actor'          => self::pair($this->actor),
            'subject'        => self::pair($this->subject),
            'principal'      => self::pair($this->principal),
            'tenant'         => self::pair($this->tenant),
            'reason'         => $this->reason,
            'correlation_id' => $this->correlationId,
            'properties'     => $this->properties,
            'context'        => $this->context,
            'origin'         => $this->origin,
            'ip'             => $this->ip,
        ];
    }

    /**
     * The reference as its type and id, or `null` for none.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return ?array{0: string, 1: string}
     */
    private static function pair(#[\SensitiveParameter] ?Reference $reference): ?array
    {
        return $reference === null ? null : [$reference->type, $reference->id];
    }
}
