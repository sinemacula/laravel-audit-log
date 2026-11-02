<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Signs a captured record once, as it is finalised, and verifies a stored row
 * against its signature, under integrity version 1.
 *
 * The signature is HMAC-SHA256, under the secret of the ring's signing key,
 * over the canonical encoding of every column but `hmac`, so the time the
 * record was recorded, the integrity version and the key id are covered too.
 * Verification works on the decoded stored row, exactly as it was read: it
 * never normalises or repairs it, every signed column is required (a missing
 * one is never read as `null`), and columns beyond version 1's are ignored. It
 * answers `false` only when the signature does not match; a row it cannot
 * judge, because its key is not in the ring, its version is not supported or
 * the row is malformed, is refused with an exception, never reported as
 * tampered or as intact.
 *
 * The captured-content digest is SHA-256 over the canonical encoding of the
 * captured columns alone, leaving out when the record was recorded and how it
 * was signed, so the same record finalised twice has one digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordSigner
{
    /** @var int The integrity version every new row is signed under. */
    public const int VERSION = 1;

    /** @var list<int> The integrity versions this release verifies. */
    public const array SUPPORTED_VERSIONS = [1];

    /** @var list<string> The captured record's columns, as `AuditRecord::toArray()` keys them, in table order. */
    public const array CAPTURED_COLUMNS = [
        'id',
        'record_version',
        'event',
        'event_version',
        'category',
        'outcome',
        'reason',
        'actor_type',
        'actor_id',
        'subject_type',
        'subject_id',
        'principal_type',
        'principal_id',
        'tenant_type',
        'tenant_id',
        'credential_id',
        'guard',
        'session_id',
        'request_id',
        'trace_id',
        'correlation_id',
        'origin',
        'provenance',
        'source_id',
        'source_region',
        'source_record_id',
        'import_batch_id',
        'ip',
        'user_agent',
        'context',
        'properties',
        'occurred_at',
    ];

    /** @var list<string> Every column but `hmac`, in table order: the signature covers each of them. */
    public const array SIGNED_COLUMNS = [...self::CAPTURED_COLUMNS, 'recorded_at', 'integrity_version', 'key_id'];

    /** @var string The column holding the signature. */
    private const string HMAC_COLUMN = 'hmac';

    /** @var string HMAC-SHA256 as lower-case hex. */
    private const string HMAC_PATTERN = '/\A[0-9a-f]{64}\z/';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose signing key signs and whose keys verify. */
        private KeyRing $keys,
    ) {}

    /**
     * The record finalised at the time given: signed under the ring's signing
     * key and the current integrity version.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function sign(AuditRecord $record, string $recordedAt): FinalisedRecord
    {
        $key = $this->keys->signingKey();

        $envelope = [
            ...$record->toArray(),
            'recorded_at'       => $recordedAt,
            'integrity_version' => self::VERSION,
            'key_id'            => $key->id,
        ];

        $hmac = hash_hmac('sha256', CanonicalEncoder::encode($envelope), $key->secret());

        return new FinalisedRecord($record, $recordedAt, self::VERSION, $key->id, $hmac);
    }

    /**
     * Whether the decoded stored row's signature matches its signed columns.
     * `false` means only that the signature does not match; a row whose key the
     * ring does not hold, whose integrity version is not supported, or that is
     * malformed is refused instead.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return bool
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function verifies(array $row): bool
    {
        $signed = self::columns($row, [...self::SIGNED_COLUMNS, self::HMAC_COLUMN]);
        $hmac   = self::storedHmac($signed[self::HMAC_COLUMN]);

        unset($signed[self::HMAC_COLUMN]);

        self::checkVersion($signed['integrity_version']);

        $key = $this->keys->key(self::storedKeyId($signed['key_id']));

        return hash_equals(hash_hmac('sha256', CanonicalEncoder::encode($signed), $key->secret()), $hmac);
    }

    /**
     * The captured-content digest of the decoded stored row: SHA-256, in hex,
     * over the canonical encoding of its captured columns, each required.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function capturedDigest(array $row): string
    {
        return hash('sha256', CanonicalEncoder::encode(self::columns($row, self::CAPTURED_COLUMNS)));
    }

    /**
     * The row's values of the columns, each required: a column holding `null`
     * is present, and a missing one is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @param  list<string>  $columns
     * @return array<string, mixed>
     *
     * @throws \UnexpectedValueException
     */
    private static function columns(array $row, array $columns): array
    {
        $values = [];

        foreach ($columns as $column) {
            if (!array_key_exists($column, $row)) {
                throw new \UnexpectedValueException(sprintf('A stored entry has no `%s` column; every column is required to verify it.', $column));
            }

            $values[$column] = $row[$column];
        }

        return $values;
    }

    /**
     * Refuse an integrity version this release does not verify, naming it, or
     * naming its type when it is not an integer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $version
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function checkVersion(mixed $version): void
    {
        if (in_array($version, self::SUPPORTED_VERSIONS, true)) {
            return;
        }

        throw new \UnexpectedValueException(sprintf('Integrity version %s is not supported by this release.', is_int($version) ? $version : get_debug_type($version)));
    }

    /**
     * The stored signature, refused unless it is HMAC-SHA256 as lower-case hex.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $hmac
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedHmac(mixed $hmac): string
    {
        if (!is_string($hmac) || preg_match(self::HMAC_PATTERN, $hmac) !== 1) {
            throw new \UnexpectedValueException('A stored entry\'s `hmac` must be 64 lower-case hexadecimal characters.');
        }

        return $hmac;
    }

    /**
     * The stored key id, refused unless it is a string; whether the ring holds
     * it is the ring's to say.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $keyId
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedKeyId(mixed $keyId): string
    {
        return is_string($keyId) ? $keyId : throw new \UnexpectedValueException('A stored entry\'s `key_id` must be a string.');
    }
}
