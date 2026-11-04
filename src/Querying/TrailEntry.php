<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * An entry of the trail as a viewer is shown it, safe to hand on by
 * construction: its references, times, code, outcome and versions as typed
 * values, a reason its record concealed already `null`, and its context and
 * properties as display arrays, in which every encrypted fragment, an owned
 * note included, and an encrypted IP address are what the field reader
 * answered, a value or a marker, never a ciphertext.
 *
 * An artifact the entry carries is shown by its descriptor alone, its kind,
 * count and digest; its members are never loaded. Times are instants in UTC to
 * the microsecond, and `toArray()` gives them in the package's form. Only the
 * stored row is evidence: this is a projection of it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<array-key, mixed>|int|string|null>
 */
final readonly class TrailEntry implements Arrayable
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  string  $event
     * @param  int  $eventVersion
     * @param  int  $recordVersion
     * @param  int  $integrityVersion
     * @param  string  $category
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $credentialId
     * @param  ?string  $guard
     * @param  ?string  $sessionId
     * @param  ?string  $requestId
     * @param  ?string  $traceId
     * @param  ?string  $correlationId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Enums\Origin  $origin
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Provenance  $provenance
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  ?string  $sourceRecordId
     * @param  ?string  $importBatchId
     * @param  ?string  $sourceDigest
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  array<array-key, mixed>  $context
     * @param  array<array-key, mixed>  $properties
     * @param  \Carbon\CarbonImmutable  $occurredAt
     * @param  \Carbon\CarbonImmutable  $recordedAt
     * @param  string  $keyId
     * @param  string  $hmac
     * @param  ?array{kind: string, count: int, digest: string}  $manifest
     *
     * @internal
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The entry's id. */
        public string $id,

        /** The event code naming what happened. */
        public string $event,

        /** The version of the code's payload contract. */
        public int $eventVersion,

        /** The version of the envelope the entry is in. */
        public int $recordVersion,

        /** The integrity version the entry is signed under. */
        public int $integrityVersion,

        /** The code's category. */
        public string $category,

        /** How the activity ended. */
        public Outcome $outcome,

        /** Why it failed or was denied; `null` when none was given or its record concealed it. */
        public ?string $reason,

        /** Who did it, if known. */
        public ?Reference $actor,

        /** What it was done to, if anything. */
        public ?Reference $subject,

        /** On whose behalf it was done, if anyone's. */
        public ?Reference $principal,

        /** The tenant it happened in, if any. */
        public ?Reference $tenant,

        /** Identifier of the credential the activity used, if any; never a secret. */
        #[\SensitiveParameter]
        public ?string $credentialId,

        /** The authentication guard the activity ran under, if known. */
        public ?string $guard,

        /** An application-owned, non-secret reference to the session, if known. */
        public ?string $sessionId,

        /** The request's id, if known. */
        public ?string $requestId,

        /** The W3C trace id, if known. */
        public ?string $traceId,

        /** Namespaced id tying the entry to other activity, if any. */
        public ?string $correlationId,

        /** Where the activity ran, if known. */
        public ?Origin $origin,

        /** Who asserts the entry. */
        public Provenance $provenance,

        /** The source the entry was captured on. */
        public string $sourceId,

        /** The source's region, if configured. */
        public ?string $sourceRegion,

        /** The entry's id at its original source, for an imported entry. */
        public ?string $sourceRecordId,

        /** The import batch the entry came in, for an imported entry. */
        public ?string $importBatchId,

        /** The keyed digest of an imported entry's source assertion; `null` on every captured entry. */
        public ?string $sourceDigest,

        /** The client's IP address as stored, or what the field reader answered for an encrypted one. */
        public ?string $ip,

        /** The client's user agent, if known. */
        public ?string $userAgent,

        /** The context, for display: maps as arrays, every encrypted fragment as the field reader answered it. */
        #[\SensitiveParameter]
        public array $context,

        /** The properties, for display: maps as arrays, every encrypted fragment as the field reader answered it, the manifest descriptor lifted out. */
        #[\SensitiveParameter]
        public array $properties,

        /** When the activity happened, in UTC to the microsecond. */
        public CarbonImmutable $occurredAt,

        /** When the entry was recorded, in UTC to the microsecond. */
        public CarbonImmutable $recordedAt,

        /** The id of the key the entry was signed with. */
        public string $keyId,

        /** The entry's HMAC, lower-case hex. */
        public string $hmac,

        /** The descriptor of the artifact the entry carries, its kind, count and digest, or `null` for none. */
        public ?array $manifest,
    ) {}

    /**
     * The entry with snake-case keys: references as `type` and `id` pairs,
     * enums as their values and times as instants in the package's form.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<string, array<array-key, mixed>|int|string|null>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'id'                => $this->id,
            'event'             => $this->event,
            'event_version'     => $this->eventVersion,
            'record_version'    => $this->recordVersion,
            'integrity_version' => $this->integrityVersion,
            'category'          => $this->category,
            'outcome'           => $this->outcome->value,
            'reason'            => $this->reason,
            'actor'             => $this->actor?->toArray(),
            'subject'           => $this->subject?->toArray(),
            'principal'         => $this->principal?->toArray(),
            'tenant'            => $this->tenant?->toArray(),
            'credential_id'     => $this->credentialId,
            'guard'             => $this->guard,
            'session_id'        => $this->sessionId,
            'request_id'        => $this->requestId,
            'trace_id'          => $this->traceId,
            'correlation_id'    => $this->correlationId,
            'origin'            => $this->origin?->value,
            'provenance'        => $this->provenance->value,
            'source_id'         => $this->sourceId,
            'source_region'     => $this->sourceRegion,
            'source_record_id'  => $this->sourceRecordId,
            'import_batch_id'   => $this->importBatchId,
            'source_digest'     => $this->sourceDigest,
            'ip'                => $this->ip,
            'user_agent'        => $this->userAgent,
            'context'           => $this->context,
            'properties'        => $this->properties,
            'occurred_at'       => StoredTime::format($this->occurredAt),
            'recorded_at'       => StoredTime::format($this->recordedAt),
            'key_id'            => $this->keyId,
            'hmac'              => $this->hmac,
            'manifest'          => $this->manifest,
        ];
    }
}
