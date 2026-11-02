<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * A captured record once finalised: the record, when it was recorded, and the
 * integrity fields it is signed with, produced once so that every retry reuses
 * it byte for byte.
 *
 * Signing and storage read it, in the envelope of the entries table; it is
 * never rebuilt from a stored row, which is evidence to verify, not a record to
 * write again. It is never recorded before the activity occurred, and its id,
 * and its import batch id when it has one, are lower-case UUIDs, the one form
 * every engine stores and returns, so a record signed on one engine verifies on
 * every other.
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
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     *
     * @throws \InvalidArgumentException
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
    ) {
        self::checkTime($record, $recordedAt);
        self::checkIntegrity($integrityVersion, $keyId, $hmac);
        self::checkIds($record);
    }

    /**
     * The finalised record as its envelope: the captured record's fields, then
     * when it was recorded and its integrity fields, each under its stored key,
     * in the order of the entries table.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{id: string, record_version: int, event: string, event_version: int, category: string, outcome: string, reason: ?string, actor_type: ?string, actor_id: ?string, subject_type: ?string, subject_id: ?string, principal_type: ?string, principal_id: ?string, tenant_type: ?string, tenant_id: ?string, credential_id: ?string, guard: ?string, session_id: ?string, request_id: ?string, trace_id: ?string, correlation_id: ?string, origin: ?string, provenance: string, source_id: string, source_region: ?string, source_record_id: ?string, import_batch_id: ?string, ip: ?string, user_agent: ?string, context: ?array<array-key, mixed>, properties: ?array<array-key, mixed>, occurred_at: string, recorded_at: string, integrity_version: int, key_id: string, hmac: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            ...$this->record->toArray(),
            'recorded_at'       => $this->recordedAt,
            'integrity_version' => $this->integrityVersion,
            'key_id'            => $this->keyId,
            'hmac'              => $this->hmac,
        ];
    }

    /**
     * Refuse a time that is not in the package's form, or that is before the
     * activity occurred; both are in the same fixed form, so comparing them as
     * strings orders them as instants.
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
     * Refuse a record whose id, or whose import batch id when it has one, is
     * not a lower-case UUID.
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
     * Refuse a UUID column whose value is not a lower-case UUID: PostgreSQL's
     * `uuid` columns refuse any other form and return lower case, so a record
     * signed over another form would be stored on one engine and refused on
     * another, or stored and never verify.
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
