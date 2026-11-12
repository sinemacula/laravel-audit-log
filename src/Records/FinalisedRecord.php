<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * A captured record once finalised with its recorded time and integrity fields,
 * made once so every retry reuses it byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FinalisedRecord
{
    /** @var int Greatest integrity version: the smallint column. */
    public const int MAX_INTEGRITY_VERSION = 32767;

    /** @var string The `key_id` column's ids. */
    private const string KEY_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\z/';

    /** @var string HMAC-SHA256 as lower-case hex. */
    private const string HMAC_PATTERN = '/\A[0-9a-f]{64}\z/';

    /** @var string A UUID as every engine returns it. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @param  ?array{context: array<array-key, mixed>|\stdClass|null, properties: array<array-key, mixed>|\stdClass|null}  $decodedColumns
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        /** The captured record. */
        public AuditRecord $record,

        /** When it was finalised, ISO-8601 UTC with microseconds; never before it occurred. */
        public string $recordedAt,

        /** The integrity version it is signed under. */
        public int $integrityVersion,

        /** The id of the key that signed it. */
        public string $keyId,

        /** HMAC-SHA256, lower-case hex, over every other column. */
        public string $hmac,

        /** The JSON columns as decoded, since an array cannot tell `{}` from `[]`; `null` if finalised here. */
        private ?array $decodedColumns = null,
    ) {
        self::checkTime($record, $recordedAt);
        self::checkIntegrity($integrityVersion, $keyId, $hmac);
        self::checkIds($record);
        self::checkSourceDigest($record->sourceDigest);
    }

    /**
     * The finalised record a verified envelope holds, keeping its JSON columns
     * as they were decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @param  array<array-key, mixed>|\stdClass|null  $context
     * @param  array<array-key, mixed>|\stdClass|null  $properties
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function decoded(
        #[\SensitiveParameter]
        AuditRecord $record,
        string $recordedAt,
        int $integrityVersion,
        string $keyId,
        string $hmac,
        #[\SensitiveParameter]
        array|\stdClass|null $context,
        #[\SensitiveParameter]
        array|\stdClass|null $properties,
    ): self {
        return new self($record, $recordedAt, $integrityVersion, $keyId, $hmac, self::copyOf(['context' => $context, 'properties' => $properties]));
    }

    /**
     * The finalised record as its envelope, in the order of the entries table,
     * with a copy of any decoded JSON columns.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{id: string, record_version: int, event: string, event_version: int, category: string, outcome: string, reason: ?string, actor_type: ?string, actor_id: ?string, subject_type: ?string, subject_id: ?string, principal_type: ?string, principal_id: ?string, tenant_type: ?string, tenant_id: ?string, credential_id: ?string, guard: ?string, session_id: ?string, request_id: ?string, trace_id: ?string, correlation_id: ?string, origin: ?string, provenance: string, source_id: string, source_region: ?string, source_record_id: ?string, import_batch_id: ?string, source_digest: ?string, ip: ?string, user_agent: ?string, context: array<array-key, mixed>|\stdClass|null, properties: array<array-key, mixed>|\stdClass|null, occurred_at: string, recorded_at: string, integrity_version: int, key_id: string, hmac: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            ...$this->record->toArray(),
            ...self::copyOf($this->decodedColumns ?? []),
            'recorded_at'       => $this->recordedAt,
            'integrity_version' => $this->integrityVersion,
            'key_id'            => $this->keyId,
            'hmac'              => $this->hmac,
        ];
    }

    /**
     * A deep copy of a decoded JSON value, since objects are shared by
     * reference and a destination must not change what was signed.
     *
     * @template TValue
     *
     * @param  TValue  $value
     * @return TValue
     */
    private static function copyOf(#[\SensitiveParameter] mixed $value): mixed
    {
        if (is_array($value)) {
            // Each member is copied to its own type, so the array keeps its own
            // @phpstan-ignore return.type
            return array_map(self::copyOf(...), $value);
        }

        if (!$value instanceof \stdClass) {
            return $value;
        }

        $copy = new \stdClass;

        foreach (get_object_vars($value) as $key => $member) {
            $copy->{$key} = self::copyOf($member);
        }

        // A copy of a plain object is a plain object
        // @phpstan-ignore return.type
        return $copy;
    }

    /**
     * Refuse a time not in the package's form or before the activity occurred;
     * the fixed form makes string order instant order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkTime(AuditRecord $record, string $recordedAt): void
    {
        if (!StoredTime::isInstant($recordedAt)) {
            throw new \InvalidArgumentException('A finalised record\'s time must be ISO-8601 UTC with microseconds.');
        }

        if (strcmp($recordedAt, $record->occurredAt) < 0) {
            throw new \InvalidArgumentException('A finalised record cannot be recorded before the activity occurred.');
        }
    }

    /**
     * Refuse an integrity version, key id or HMAC that its column cannot hold.
     *
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkIntegrity(int $integrityVersion, string $keyId, string $hmac): void
    {
        if ($integrityVersion < 1 || $integrityVersion > self::MAX_INTEGRITY_VERSION) {
            throw new \InvalidArgumentException(sprintf('An integrity version must be from 1 to %d.', self::MAX_INTEGRITY_VERSION));
        }

        if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
            throw new \InvalidArgumentException('A key id must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if (preg_match(self::HMAC_PATTERN, $hmac) !== 1) {
            throw new \InvalidArgumentException('An HMAC must be 64 lower-case hexadecimal characters.');
        }
    }

    /**
     * Refuse a record whose id or import batch id is not a lower-case UUID.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkIds(AuditRecord $record): void
    {
        self::checkUuid('id', $record->id);

        if ($record->importBatchId === null) {
            return;
        }

        self::checkUuid('import_batch_id', $record->importBatchId);
    }

    /**
     * Refuse a source digest that is not 64 lower-case hex.
     *
     * @param  ?string  $sourceDigest
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkSourceDigest(?string $sourceDigest): void
    {
        if ($sourceDigest === null || preg_match(self::HMAC_PATTERN, $sourceDigest) === 1) {
            return;
        }

        throw new \InvalidArgumentException('A finalised record\'s `source_digest` must be 64 lower-case hexadecimal characters.');
    }

    /**
     * Refuse a value that is not a lower-case UUID: PostgreSQL's `uuid` refuses
     * other forms and returns lower case, so another would never verify.
     *
     * @param  'id'|'import_batch_id'  $column
     * @param  string  $value
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkUuid(string $column, string $value): void
    {
        if (preg_match(self::UUID_PATTERN, $value) !== 1) {
            throw new \InvalidArgumentException(sprintf('A finalised record\'s `%s` must be a lower-case UUID, the form every engine stores and returns.', $column));
        }
    }
}
