<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
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
 * the import fields and the source digest are `null`.
 *
 * An imported record is this installation's acceptance of another source's
 * assertion, with `imported` provenance: its id is a UUID version 7 of the time
 * it was imported, so imported ids sort near their recording, while the time
 * the activity happened is kept as the source gave it. It names the source that
 * asserted it, the record's id there, the batch it came in and the keyed digest
 * of the assertion, has no artifact, and may have no origin, when the source
 * did not know it. It carries no credential, guard, session, request, trace or
 * user agent: an import carries no ambient context.
 *
 * It holds only minimised values: its IP address, context and properties are
 * what `RecordMinimiser` left of the builder's, and the note, the identifier
 * hash, an artifact's manifest descriptor and the diagnostics of what was
 * removed sit at `properties._audit`, last and after the caller's keys, written
 * there by that minimiser.
 *
 * A record with an artifact carries its attachment: a bulk operation's sealed
 * subjects, a disclosure's evidence or an export's manifest. The attachment is
 * carried, not signed, and is never in the envelope: the record is bound to it
 * by the descriptor it signs at `properties._audit.manifest`, which names the
 * attachment's id, kind, digest and count, so a record with the descriptor is
 * built only with the attachment it describes, and a record without one only
 * with none. The rule holds for an attachment described from a stored entry's
 * descriptor too, so a record rebuilt to be read keeps it.
 *
 * The delivery pipeline later finalises it, once, adding the time it was
 * recorded and its integrity fields; nothing here knows of that. A record kept
 * in the outbox or a spill line is rebuilt from its envelope only by the codec,
 * after its signature verifies, with every field as it was signed: its id,
 * times and provenance are kept, and it is never minimised again.
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

    /** @var string A lower-case UUID: a record's id. */
    private const string ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string The key the package's metadata sits under, last in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The key the manifest descriptor sits under in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

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
     * @param  ?string  $sourceDigest
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?array<array-key, mixed>  $context
     * @param  ?array<array-key, mixed>  $properties
     * @param  string  $occurredAt
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
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

        /** Who asserts the record: `captured`, or `imported` for a record another source asserted. */
        public string $provenance,

        /** The source the record was captured on, or, for an imported record, the source that asserted it. */
        public string $sourceId,

        /** The source's region, if configured. */
        public ?string $sourceRegion,

        /** The record's id at its original source; `null` for a captured record. */
        public ?string $sourceRecordId,

        /** The import batch the record came in; `null` for a captured record. */
        public ?string $importBatchId,

        /** The keyed digest of an imported record's source assertion; `null` on every captured record. */
        public ?string $sourceDigest,

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

        /** The artifact's attachment, carried and bound by the signed descriptor; `null` for a record with no artifact. */
        #[\SensitiveParameter]
        public ?Attachment $attachment = null,
    ) {}

    /**
     * The record an envelope holds, with every field kept as given: its id, its
     * times, its provenance and its import fields included. Only the codec
     * calls it, having verified the envelope, so it never minimises, sanitises
     * or checks a value beyond its type; a field missing, or of another type,
     * is refused. A bundle's attachment comes with it, and must be the one its
     * signed descriptor describes; a record with a descriptor and no
     * attachment, or with an attachment and no descriptor, is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function fromEnvelope(#[\SensitiveParameter] array $fields, #[\SensitiveParameter] ?Attachment $attachment = null): self
    {
        $properties = self::arrayOf($fields, 'properties');

        if (!self::isBound($properties, $attachment)) {
            throw new \InvalidArgumentException('A record\'s manifest and its attachment must describe the same artifact.');
        }

        return new self(
            id: self::stringOf($fields, 'id'),
            recordVersion: self::integerOf($fields, 'record_version'),
            event: self::stringOf($fields, 'event'),
            eventVersion: self::integerOf($fields, 'event_version'),
            category: self::stringOf($fields, 'category'),
            outcome: self::stringOf($fields, 'outcome'),
            reason: self::nullableOf($fields, 'reason'),
            actorType: self::nullableOf($fields, 'actor_type'),
            actorId: self::nullableOf($fields, 'actor_id'),
            subjectType: self::nullableOf($fields, 'subject_type'),
            subjectId: self::nullableOf($fields, 'subject_id'),
            principalType: self::nullableOf($fields, 'principal_type'),
            principalId: self::nullableOf($fields, 'principal_id'),
            tenantType: self::nullableOf($fields, 'tenant_type'),
            tenantId: self::nullableOf($fields, 'tenant_id'),
            credentialId: self::nullableOf($fields, 'credential_id'),
            guard: self::nullableOf($fields, 'guard'),
            sessionId: self::nullableOf($fields, 'session_id'),
            requestId: self::nullableOf($fields, 'request_id'),
            traceId: self::nullableOf($fields, 'trace_id'),
            correlationId: self::nullableOf($fields, 'correlation_id'),
            origin: self::nullableOf($fields, 'origin'),
            provenance: self::stringOf($fields, 'provenance'),
            sourceId: self::stringOf($fields, 'source_id'),
            sourceRegion: self::nullableOf($fields, 'source_region'),
            sourceRecordId: self::nullableOf($fields, 'source_record_id'),
            importBatchId: self::nullableOf($fields, 'import_batch_id'),
            sourceDigest: self::nullableOf($fields, 'source_digest'),
            ip: self::nullableOf($fields, 'ip'),
            userAgent: self::nullableOf($fields, 'user_agent'),
            context: self::arrayOf($fields, 'context'),
            properties: $properties,
            occurredAt: self::stringOf($fields, 'occurred_at'),
            attachment: $attachment,
        );
    }

    /**
     * The captured record of the pending record, which this uses up: built
     * once, as the entry of the id the pipeline minted before minimising, with
     * what minimising left of its IP address, context and properties, the event
     * version and category of its code's definition, the instant the activity
     * happened, and the source it was captured on. The id must be a lower-case
     * UUID, and the pending record's own when the package gave it one, since
     * every value was sealed for that entry. The origin must have been filled.
     * A builder with a manifest gives a record that takes the attachment of
     * that manifest, which its minimised properties describe, and any other
     * record takes none.
     *
     * Its parameters are the record's parts, each from its own stage of the
     * pipeline, so none groups naturally with another.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Minimised  $minimised
     * @param  string  $id
     * @param  int  $eventVersion
     * @param  string  $category
     * @param  \DateTimeInterface  $occurredAt
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     *
     * @SuppressWarnings("php:S107")
     */
    public static function fromPending(
        #[\SensitiveParameter]
        PendingRecord $pending,
        Minimised $minimised,
        string $id,
        int $eventVersion,
        string $category,
        \DateTimeInterface $occurredAt,
        string $sourceId,
        ?string $sourceRegion = null,
        #[\SensitiveParameter]
        ?Attachment $attachment = null,
    ): self {
        $snapshot = $pending->consume();
        $origin   = self::originOf($snapshot);

        assert($snapshot->code instanceof EventCode);

        self::checkId($snapshot, $id);
        self::checkSource($sourceId, $sourceRegion);
        self::checkAttachment($snapshot, $minimised, $attachment);

        [$actorType, $actorId]         = self::pair($snapshot->actor);
        [$subjectType, $subjectId]     = self::pair($snapshot->subject);
        [$principalType, $principalId] = self::pair($snapshot->principal);
        [$tenantType, $tenantId]       = self::pair($snapshot->tenant);

        return new self(
            id: $id,
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
            sourceDigest: null,
            ip: $minimised->ip,
            userAgent: $snapshot->userAgent,
            context: $minimised->context,
            properties: $minimised->properties,
            occurredAt: self::utc($occurredAt),
            attachment: $attachment,
        );
    }

    /**
     * The imported record of the pending record, which this uses up: built
     * once, with `imported` provenance, from the references, outcome, reason,
     * correlation id and what minimising left of the IP address, context and
     * properties of the pending record, the event version and category of its
     * code's definition, and the source fields given. Its id is the one the
     * import minted before minimising, a lower-case UUID version 7 of the time
     * it is imported, since every value was sealed for that entry; the time the
     * activity happened is kept as given, which must be an instant in the
     * package's form, and its origin, if the source knew it, must be one this
     * package names. It carries no credential, guard, session, request, trace
     * or user agent, and no artifact: a pending record with a manifest is
     * refused.
     *
     * Its parameters are the record's parts, each from its own stage of the
     * import, so none groups naturally with another.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Minimised  $minimised
     * @param  int  $eventVersion
     * @param  string  $category
     * @param  string  $occurredAt
     * @param  ?string  $origin
     * @param  \SineMacula\Laravel\AuditLog\Records\ImportedSource  $source
     * @param  string  $id
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     *
     * @SuppressWarnings("php:S107")
     */
    public static function fromImport(
        #[\SensitiveParameter]
        PendingRecord $pending,
        Minimised $minimised,
        int $eventVersion,
        string $category,
        string $occurredAt,
        ?string $origin,
        ImportedSource $source,
        string $id,
    ): self {
        $snapshot = $pending->consume();

        assert($snapshot->code instanceof EventCode);

        self::checkId($snapshot, $id);
        self::checkImport($snapshot, $minimised, $occurredAt, $origin);

        [$actorType, $actorId]         = self::pair($snapshot->actor);
        [$subjectType, $subjectId]     = self::pair($snapshot->subject);
        [$principalType, $principalId] = self::pair($snapshot->principal);
        [$tenantType, $tenantId]       = self::pair($snapshot->tenant);

        return new self(
            id: $id,
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
            credentialId: null,
            guard: null,
            sessionId: null,
            requestId: null,
            traceId: null,
            correlationId: $snapshot->correlationId,
            origin: $origin,
            provenance: Provenance::IMPORTED->value,
            sourceId: $source->sourceId,
            sourceRegion: $source->sourceRegion,
            sourceRecordId: $source->sourceRecordId,
            importBatchId: $source->importBatchId,
            sourceDigest: $source->sourceDigest,
            ip: $minimised->ip,
            userAgent: null,
            context: $minimised->context,
            properties: $minimised->properties,
            occurredAt: $occurredAt,
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
     * @return array{id: string, record_version: int, event: string, event_version: int, category: string, outcome: string, reason: ?string, actor_type: ?string, actor_id: ?string, subject_type: ?string, subject_id: ?string, principal_type: ?string, principal_id: ?string, tenant_type: ?string, tenant_id: ?string, credential_id: ?string, guard: ?string, session_id: ?string, request_id: ?string, trace_id: ?string, correlation_id: ?string, origin: ?string, provenance: string, source_id: string, source_region: ?string, source_record_id: ?string, import_batch_id: ?string, source_digest: ?string, ip: ?string, user_agent: ?string, context: ?array<array-key, mixed>, properties: ?array<array-key, mixed>, occurred_at: string}
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
            'source_digest'    => $this->sourceDigest,
            'ip'               => $this->ip,
            'user_agent'       => $this->userAgent,
            'context'          => $this->context,
            'properties'       => $this->properties,
            'occurred_at'      => $this->occurredAt,
        ];
    }

    /**
     * Refuse an attachment that is not the snapshot's own manifest sealed, or
     * that the minimised properties do not describe, and a snapshot with a
     * manifest without one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Minimised  $minimised
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkAttachment(#[\SensitiveParameter] PendingSnapshot $snapshot, Minimised $minimised, #[\SensitiveParameter] ?Attachment $attachment): void
    {
        if ($snapshot->manifest?->id !== $attachment?->id || !self::isBound($minimised->properties, $attachment)) {
            throw new \LogicException('A record with an artifact is built with the attachment of its own manifest, and any other record with none.');
        }
    }

    /**
     * Refuse an id that is not a lower-case UUID, and one other than the id the
     * package gave the snapshot, when it gave one, since the record's values
     * were sealed for the entry the id names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  string  $id
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function checkId(#[\SensitiveParameter] PendingSnapshot $snapshot, string $id): void
    {
        if (preg_match(self::ID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException('A record\'s id must be a lower-case UUID.');
        }

        if ($snapshot->id !== null && $snapshot->id !== $id) {
            throw new \LogicException('A record keeps the id the package gave its pending record, the one its values were sealed for.');
        }
    }

    /**
     * Refuse an import of a snapshot with a manifest, or of properties holding
     * a manifest descriptor, since an imported record carries no artifact; a
     * time that is not an instant in the package's form; and an origin this
     * package does not name.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Minimised  $minimised
     * @param  string  $occurredAt
     * @param  ?string  $origin
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function checkImport(#[\SensitiveParameter] PendingSnapshot $snapshot, Minimised $minimised, string $occurredAt, ?string $origin): void
    {
        if ($snapshot->manifest !== null || !self::isBound($minimised->properties, null)) {
            throw new \LogicException('An imported record carries no artifact.');
        }

        if (!StoredTime::isInstant($occurredAt)) {
            throw new \InvalidArgumentException('An imported record\'s occurrence time must be ISO-8601 UTC with microseconds, such as 2026-11-01T12:00:00.123456Z.');
        }

        if ($origin !== null && Origin::tryFrom($origin) === null) {
            throw new \InvalidArgumentException(sprintf('An imported record\'s origin must be one of `%s`, or null.', implode('`, `', array_column(Origin::cases(), 'value'))));
        }
    }

    /**
     * Whether the attachment is the one the properties' signed descriptor
     * describes: none without a descriptor, and with one, exactly the
     * attachment it names.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $properties
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @return bool
     */
    private static function isBound(#[\SensitiveParameter] ?array $properties, #[\SensitiveParameter] ?Attachment $attachment): bool
    {
        $metadata = $properties[self::METADATA_KEY] ?? null;

        if (!is_array($metadata) || !array_key_exists(self::MANIFEST_KEY, $metadata)) {
            return $attachment === null;
        }

        $descriptor = $metadata[self::MANIFEST_KEY];

        return $attachment !== null && is_array($descriptor) && $attachment->describes($descriptor);
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
     * The envelope's field, which must be present; a field holding `null` is
     * present.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private static function fieldOf(#[\SensitiveParameter] array $fields, string $key): mixed
    {
        if (!array_key_exists($key, $fields)) {
            throw new \InvalidArgumentException(sprintf('An envelope has no `%s` field.', $key));
        }

        return $fields[$key];
    }

    /**
     * The envelope's field, which must be a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function stringOf(#[\SensitiveParameter] array $fields, string $key): string
    {
        $value = self::fieldOf($fields, $key);

        return is_string($value) ? $value : throw self::mistyped($key, 'a string');
    }

    /**
     * The envelope's field, which must be a string or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function nullableOf(#[\SensitiveParameter] array $fields, string $key): ?string
    {
        $value = self::fieldOf($fields, $key);

        return $value === null || is_string($value) ? $value : throw self::mistyped($key, 'a string or null');
    }

    /**
     * The envelope's field, which must be an integer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function integerOf(#[\SensitiveParameter] array $fields, string $key): int
    {
        $value = self::fieldOf($fields, $key);

        return is_int($value) ? $value : throw self::mistyped($key, 'an integer');
    }

    /**
     * The envelope's field, which must be an array or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function arrayOf(#[\SensitiveParameter] array $fields, string $key): ?array
    {
        $value = self::fieldOf($fields, $key);

        return $value === null || is_array($value) ? $value : throw self::mistyped($key, 'an array or null');
    }

    /**
     * The refusal of an envelope's field of another type, naming the field and
     * what it must be, never its value.
     *
     * @param  string  $key
     * @param  string  $what
     * @return \InvalidArgumentException
     */
    private static function mistyped(string $key, string $what): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('An envelope\'s `%s` must be %s.', $key, $what));
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
