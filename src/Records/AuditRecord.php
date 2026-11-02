<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * A captured record: everything known about an activity when it was recorded,
 * in the envelope every later stage stores, signs and reads back.
 *
 * It holds only strings, integers, booleans, `null`, lists and maps: enums as
 * their values, references as type and id pairs (both set or both `null`, never
 * an empty string), and the time as ISO-8601 UTC with microseconds. Its id is a
 * UUID version 7, so records captured in one millisecond still sort in the
 * order they were captured. It carries the current record version, the event
 * version and category of its code's definition, and `captured` provenance,
 * which says the application asserted the activity, not that the claim is true;
 * the import fields are `null`.
 *
 * It holds only minimised values: its IP address, context and properties are
 * what `RecordMinimiser` left of the builder's, and the note, the identifier
 * hash and the diagnostics of what was removed sit at `properties._audit`, last
 * and after the caller's keys, written there by that minimiser.
 *
 * The delivery pipeline later finalises it, once, adding the time it was
 * recorded and its integrity fields; nothing here knows of that.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditRecord
{
    /** @var int Longest source id, in characters: the `source_id` column. */
    public const int SOURCE_ID_MAX_CHARACTERS = 64;

    /** @var int Longest source region, in characters: the `source_region` column. */
    public const int SOURCE_REGION_MAX_CHARACTERS = 32;

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  int  $recordVersion
     * @param  string  $event
     * @param  int  $eventVersion
     * @param  string  $category
     * @param  string  $outcome
     * @param  ?string  $reason
     * @param  ?string  $actorType
     * @param  ?string  $actorId
     * @param  ?string  $subjectType
     * @param  ?string  $subjectId
     * @param  ?string  $principalType
     * @param  ?string  $principalId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @param  ?string  $credentialId
     * @param  ?string  $guard
     * @param  ?string  $sessionId
     * @param  ?string  $requestId
     * @param  ?string  $traceId
     * @param  ?string  $correlationId
     * @param  ?string  $origin
     * @param  string  $provenance
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  ?string  $sourceRecordId
     * @param  ?string  $importBatchId
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?array<array-key, mixed>  $context
     * @param  ?array<array-key, mixed>  $properties
     * @param  string  $occurredAt
     */
    private function __construct(

        /** The record's id: a UUID version 7, generated at capture. */
        public string $id,

        /** The version of the envelope the record is in. */
        public int $recordVersion,

        /** The event code naming what happened. */
        public string $event,

        /** The version of the code's payload contract, from its definition. */
        public int $eventVersion,

        /** The code's category, from its definition. */
        public string $category,

        /** How the activity ended: `success`, `failure` or `denied`. */
        public string $outcome,

        /** Why it failed or was denied, as a machine-readable code, if given. */
        public ?string $reason,

        /** The actor's type; `null` exactly when the actor's id is. */
        public ?string $actorType,

        /** The actor's id; `null` exactly when the actor's type is. */
        public ?string $actorId,

        /** The subject's type; `null` exactly when the subject's id is. */
        public ?string $subjectType,

        /** The subject's id; `null` exactly when the subject's type is. */
        public ?string $subjectId,

        /** The principal's type; `null` exactly when the principal's id is. */
        public ?string $principalType,

        /** The principal's id; `null` exactly when the principal's type is. */
        public ?string $principalId,

        /** The tenant's type; `null` exactly when the tenant's id is. */
        public ?string $tenantType,

        /** The tenant's id; `null` exactly when the tenant's type is. */
        public ?string $tenantId,

        /** Identifier of the credential the activity used, if any; never a secret. */
        #[\SensitiveParameter]
        public ?string $credentialId,

        /** The authentication guard the activity ran under, if known. */
        public ?string $guard,

        /** An application-owned, non-secret reference to the session, if known. */
        public ?string $sessionId,

        /** The request's id, if known. */
        public ?string $requestId,

        /** The W3C trace id of a trusted `traceparent`, if known. */
        public ?string $traceId,

        /** Namespaced id tying the record to other activity, if any. */
        public ?string $correlationId,

        /** Where the activity ran: `http`, `console` or `queue`; never `null` for a captured record. */
        public ?string $origin,

        /** Who asserts the record: `captured` for every record built here. */
        public string $provenance,

        /** The source the record was captured on. */
        public string $sourceId,

        /** The source's region, if configured. */
        public ?string $sourceRegion,

        /** The record's id at its original source; `null` for a captured record. */
        public ?string $sourceRecordId,

        /** The import batch the record came in; `null` for a captured record. */
        public ?string $importBatchId,

        /** The client's IP address in the configured mode, if known and kept. */
        public ?string $ip,

        /** The client's user agent, cleaned and capped, if known. */
        public ?string $userAgent,

        /** The context, minimised, as a map; `null` when there is none. */
        public ?array $context,

        /** The properties, minimised, as a map, with the package's metadata last; `null` when there are none. */
        public ?array $properties,

        /** When the activity happened, as ISO-8601 UTC with microseconds. */
        public string $occurredAt,
    ) {}

    /**
     * The captured record of the pending record, which this uses up: built
     * once, with what minimising left of its IP address, context and
     * properties, the event version and category of its code's definition, the
     * instant the activity happened, and the source it was captured on. The
     * origin must have been filled.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Minimised  $minimised
     * @param  int  $eventVersion
     * @param  string  $category
     * @param  \DateTimeInterface  $occurredAt
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public static function fromPending(
        #[\SensitiveParameter]
        PendingRecord $pending,
        Minimised $minimised,
        int $eventVersion,
        string $category,
        \DateTimeInterface $occurredAt,
        string $sourceId,
        ?string $sourceRegion = null,
    ): self {
        $snapshot = $pending->consume();
        $origin   = self::originOf($snapshot);

        assert($snapshot->code instanceof EventCode);

        self::checkSource($sourceId, $sourceRegion);

        [$actorType, $actorId]         = self::pair($snapshot->actor);
        [$subjectType, $subjectId]     = self::pair($snapshot->subject);
        [$principalType, $principalId] = self::pair($snapshot->principal);
        [$tenantType, $tenantId]       = self::pair($snapshot->tenant);

        return new self(
            id: Str::uuid7($occurredAt)->toString(),
            recordVersion: RecordVersion::CURRENT,
            event: $snapshot->code->value,
            eventVersion: $eventVersion,
            category: $category,
            outcome: $snapshot->outcome->value,
            reason: $snapshot->reason,
            actorType: $actorType,
            actorId: $actorId,
            subjectType: $subjectType,
            subjectId: $subjectId,
            principalType: $principalType,
            principalId: $principalId,
            tenantType: $tenantType,
            tenantId: $tenantId,
            credentialId: $snapshot->credentialId,
            guard: $snapshot->guard,
            sessionId: $snapshot->sessionId,
            requestId: $snapshot->requestId,
            traceId: $snapshot->traceId,
            correlationId: $snapshot->correlationId,
            origin: $origin,
            provenance: Provenance::CAPTURED->value,
            sourceId: $sourceId,
            sourceRegion: $sourceRegion,
            sourceRecordId: null,
            importBatchId: null,
            ip: $minimised->ip,
            userAgent: $snapshot->userAgent,
            context: $minimised->context,
            properties: $minimised->properties,
            occurredAt: self::utc($occurredAt),
        );
    }

    /**
     * The record as its envelope: every field under its stored key, in the
     * order of the entries table.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{id: string, record_version: int, event: string, event_version: int, category: string, outcome: string, reason: ?string, actor_type: ?string, actor_id: ?string, subject_type: ?string, subject_id: ?string, principal_type: ?string, principal_id: ?string, tenant_type: ?string, tenant_id: ?string, credential_id: ?string, guard: ?string, session_id: ?string, request_id: ?string, trace_id: ?string, correlation_id: ?string, origin: ?string, provenance: string, source_id: string, source_region: ?string, source_record_id: ?string, import_batch_id: ?string, ip: ?string, user_agent: ?string, context: ?array<array-key, mixed>, properties: ?array<array-key, mixed>, occurred_at: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'id'               => $this->id,
            'record_version'   => $this->recordVersion,
            'event'            => $this->event,
            'event_version'    => $this->eventVersion,
            'category'         => $this->category,
            'outcome'          => $this->outcome,
            'reason'           => $this->reason,
            'actor_type'       => $this->actorType,
            'actor_id'         => $this->actorId,
            'subject_type'     => $this->subjectType,
            'subject_id'       => $this->subjectId,
            'principal_type'   => $this->principalType,
            'principal_id'     => $this->principalId,
            'tenant_type'      => $this->tenantType,
            'tenant_id'        => $this->tenantId,
            'credential_id'    => $this->credentialId,
            'guard'            => $this->guard,
            'session_id'       => $this->sessionId,
            'request_id'       => $this->requestId,
            'trace_id'         => $this->traceId,
            'correlation_id'   => $this->correlationId,
            'origin'           => $this->origin,
            'provenance'       => $this->provenance,
            'source_id'        => $this->sourceId,
            'source_region'    => $this->sourceRegion,
            'source_record_id' => $this->sourceRecordId,
            'import_batch_id'  => $this->importBatchId,
            'ip'               => $this->ip,
            'user_agent'       => $this->userAgent,
            'context'          => $this->context,
            'properties'       => $this->properties,
            'occurred_at'      => $this->occurredAt,
        ];
    }

    /**
     * The snapshot's origin, which every captured record has.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return string
     *
     * @throws \LogicException
     */
    private static function originOf(#[\SensitiveParameter] PendingSnapshot $snapshot): string
    {
        return $snapshot->origin->value ?? throw new \LogicException('A captured record needs an origin; the origin contributor fills it before the record is built.');
    }

    /**
     * Refuse a source id, or a region when one is given, that is empty, longer
     * than its column, or not already clean text.
     *
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkSource(string $sourceId, ?string $sourceRegion): void
    {
        if (!self::fits($sourceId, self::SOURCE_ID_MAX_CHARACTERS)) {
            throw new \InvalidArgumentException(sprintf('A source id must be from 1 to %d characters, with no control characters.', self::SOURCE_ID_MAX_CHARACTERS));
        }

        if ($sourceRegion !== null && !self::fits($sourceRegion, self::SOURCE_REGION_MAX_CHARACTERS)) {
            throw new \InvalidArgumentException(sprintf('A source region must be from 1 to %d characters, with no control characters.', self::SOURCE_REGION_MAX_CHARACTERS));
        }
    }

    /**
     * Whether the value is from 1 to the most characters given, and already
     * clean text.
     *
     * @param  string  $value
     * @param  int  $maxCharacters
     * @return bool
     */
    private static function fits(string $value, int $maxCharacters): bool
    {
        return $value !== '' && mb_strlen($value, 'UTF-8') <= $maxCharacters && TextSanitizer::isClean($value);
    }

    /**
     * The reference's type and id, or two `null`s when there is none, so a pair
     * is always both set or both absent.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return array{0: ?string, 1: ?string}
     */
    private static function pair(?Reference $reference): array
    {
        return $reference === null ? [null, null] : [$reference->type, $reference->id];
    }

    /**
     * The instant as ISO-8601 in UTC with microseconds.
     *
     * @param  \DateTimeInterface  $instant
     * @return string
     */
    private static function utc(\DateTimeInterface $instant): string
    {
        return \DateTimeImmutable::createFromInterface($instant)
            ->setTimezone(new \DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s.u\Z');
    }
}
