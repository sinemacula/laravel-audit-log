<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\ArtifactInspector;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Reads a stored entry's columns into the entry a viewer is shown, refusing a
 * column it cannot hold by name, never by value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EntryColumns
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The shown entry, with the projected properties, context and IP address.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @param  bool  $concealed
     * @param  array<array-key, mixed>  $properties
     * @param  array<array-key, mixed>  $context
     * @param  ?string  $ip
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public static function entry(
        #[\SensitiveParameter] StoredEntry $stored,
        bool $concealed,
        #[\SensitiveParameter] array $properties,
        #[\SensitiveParameter] array $context,
        #[\SensitiveParameter] ?string $ip,
    ): TrailEntry {
        $envelope = $stored->envelope;

        return new TrailEntry(
            id: $stored->id(),
            event: self::text($envelope, 'event'),
            eventVersion: self::integer($envelope, 'event_version'),
            recordVersion: self::integer($envelope, 'record_version'),
            integrityVersion: self::integer($envelope, 'integrity_version'),
            category: self::text($envelope, 'category'),
            outcome: Outcome::tryFrom(self::text($envelope, 'outcome')) ?? throw self::malformed('outcome'),
            reason: $concealed ? null : self::nullable($envelope, 'reason'),
            actor: self::reference($envelope, 'actor'),
            subject: self::reference($envelope, 'subject'),
            principal: self::reference($envelope, 'principal'),
            tenant: self::reference($envelope, 'tenant'),
            credentialId: self::nullable($envelope, 'credential_id'),
            guard: self::nullable($envelope, 'guard'),
            sessionId: self::nullable($envelope, 'session_id'),
            requestId: self::nullable($envelope, 'request_id'),
            traceId: self::nullable($envelope, 'trace_id'),
            correlationId: self::nullable($envelope, 'correlation_id'),
            origin: self::origin($envelope),
            provenance: Provenance::tryFrom(self::text($envelope, 'provenance')) ?? throw self::malformed('provenance'),
            sourceId: self::text($envelope, 'source_id'),
            sourceRegion: self::nullable($envelope, 'source_region'),
            sourceRecordId: self::nullable($envelope, 'source_record_id'),
            importBatchId: self::nullable($envelope, 'import_batch_id'),
            sourceDigest: self::nullable($envelope, 'source_digest'),
            ip: $ip,
            userAgent: self::nullable($envelope, 'user_agent'),
            context: $context,
            properties: $properties,
            occurredAt: StoredTime::instant(StoredTime::toStorage($stored->occurredAt())),
            recordedAt: StoredTime::instant(StoredTime::toStorage($stored->recordedAt())),
            keyId: $stored->keyId(),
            hmac: $stored->hmac(),
            manifest: self::manifest($stored),
        );
    }

    /**
     * The entry's manifest descriptor when it is exactly one, or `null`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @return ?array{kind: string, count: int, digest: string}
     */
    public static function manifest(#[\SensitiveParameter] StoredEntry $stored): ?array
    {
        $descriptor = $stored->descriptor();

        if ($descriptor === null || !ArtifactInspector::isDescriptor($descriptor)) {
            return null;
        }

        return ['kind' => $descriptor['kind'], 'count' => $descriptor['count'], 'digest' => $descriptor['digest']];
    }

    /**
     * The reference of the pair of columns, or `null` unless both are stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  'actor'|'principal'|'subject'|'tenant'  $pair
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function reference(#[\SensitiveParameter] array $envelope, string $pair): ?Reference
    {
        $type = self::nullable($envelope, $pair . '_type');
        $id   = self::nullable($envelope, $pair . '_id');

        return $type === null || $id === null ? null : Reference::of($type, $id);
    }

    /**
     * The entry's origin, or `null` when none is stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @return ?\SineMacula\Laravel\AuditLog\Records\Enums\Origin
     *
     * @throws \UnexpectedValueException
     */
    public static function origin(#[\SensitiveParameter] array $envelope): ?Origin
    {
        $origin = self::nullable($envelope, 'origin');

        return $origin === null ? null : Origin::tryFrom($origin) ?? throw self::malformed('origin');
    }

    /**
     * The column the row codec read as a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return string
     */
    public static function text(#[\SensitiveParameter] array $envelope, string $column): string
    {
        $value = $envelope[$column];

        // The codec reads these columns as a string or refuses the row
        assert(is_string($value));

        return $value;
    }

    /**
     * The column the row codec read as a string or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return ?string
     */
    public static function nullable(#[\SensitiveParameter] array $envelope, string $column): ?string
    {
        $value = $envelope[$column];

        // The codec reads these columns as a string or null, or refuses the row
        assert($value === null || is_string($value));

        return $value;
    }

    /**
     * The column the row codec read as an integer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return int
     */
    public static function integer(#[\SensitiveParameter] array $envelope, string $column): int
    {
        $value = $envelope[$column];

        // The codec reads these columns as an integer or refuses the row
        assert(is_int($value));

        return $value;
    }

    /**
     * The refusal of a column the shown entry cannot hold.
     *
     * @param  string  $column
     * @return \UnexpectedValueException
     */
    public static function malformed(string $column): \UnexpectedValueException
    {
        return new \UnexpectedValueException(sprintf('A stored entry\'s `%s` cannot be shown.', $column));
    }
}
