<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * One validated line of an import file, in either format.
 *
 * Its source assertion excludes the category and region, which a definition and
 * the import decide rather than the line.
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

        /** The line number, from 1. */
        public int $number,

        /** The source that first asserted the record. */
        public string $sourceId,

        /** That source's region, if it is known. */
        public ?string $sourceRegion,

        /** The record's id at that source. */
        public string $sourceRecordId,

        /** The event code, outside the reserved prefix. */
        public string $event,

        /** When the activity happened, in the package's instant form. */
        public string $occurredAt,

        /** How the activity ended. */
        public Outcome $outcome,

        /** The machine-readable reason of a failure or denial, if given. */
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

        /** The properties less what was dropped, or `null`. */
        #[\SensitiveParameter]
        public ?array $properties,

        /** The context less what was dropped, or `null`. */
        #[\SensitiveParameter]
        public ?array $context,

        /** One of this package's origins, or `null` when the source does not know. */
        public ?string $origin,

        /** The client's IP address as given, or `null`. */
        #[\SensitiveParameter]
        public ?string $ip,

        /** Envelope-shaped values and descriptors removed from the line. */
        public int $dropped = 0,
    ) {}

    /**
     * What the line asserts, exactly as given and before minimisation or
     * encryption.
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
     * The reference as its type and id.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return ?array{0: string, 1: string}
     */
    private static function pair(#[\SensitiveParameter] ?Reference $reference): ?array
    {
        return $reference === null ? null : [$reference->type, $reference->id];
    }
}
