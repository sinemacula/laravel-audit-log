<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The one conversion between a finalised record and its outbox or spill
 * envelope, which is held to its schema and verified before it is rebuilt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnvelopeCodec
{
    /** @var int Largest envelope, in bytes: two 16 MiB budgets for the JSON columns and 64 KiB for the others. */
    public const int MAX_BYTES = 33619968;

    /** @var int Largest input decoded, in bytes: six times the envelope's bound, because a spill line writes a `%` as six bytes. */
    public const int MAX_ENCODED_BYTES = 201719808;

    /** @var int The version of the bundle schema a record with an attachment is encoded in. */
    public const int BUNDLE_VERSION = 1;

    /** @var list<int> The bundle schema versions this release decodes. */
    public const array SUPPORTED_BUNDLE_VERSIONS = [1];

    /** @var int The depth an envelope is decoded to: one more than the row codec reads a JSON column with, for the envelope's own object. */
    private const int DEPTH = 513;

    /** @var list<string> A bundle's keys, exactly, sorted as the canonical encoding writes them. */
    private const array BUNDLE_KEYS = ['attachment', 'bundle_version', 'record'];

    /** @var array<'integer'|'string', non-empty-list<string>> A bundle's attachment's fields, by what each holds. */
    private const array ATTACHMENT_SCHEMA = [
        'string'  => ['id', 'entry_id', 'kind', 'digest', 'members'],
        'integer' => ['member_count'],
    ];

    /** @var array<int, array<'instant'|'integer'|'json'|'nullable'|'string', non-empty-list<string>>> Each record version's columns, every signed one and `hmac`, by what each holds. */
    private const array SCHEMAS = [
        1 => [
            'string'   => ['id', 'event', 'category', 'outcome', 'provenance', 'source_id', 'key_id', 'hmac'],
            'integer'  => ['record_version', 'event_version', 'integrity_version'],
            'instant'  => ['occurred_at', 'recorded_at'],
            'json'     => ['context', 'properties'],
            'nullable' => [
                'reason', 'actor_type', 'actor_id', 'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type',
                'tenant_id', 'credential_id', 'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'origin',
                'source_region', 'source_record_id', 'import_batch_id', 'source_digest', 'ip', 'user_agent',
            ],
        ],
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     */
    public function __construct(

        /** The signer that verifies an envelope before it is rebuilt. */
        private RecordSigner $signer,
    ) {}

    /**
     * The finalised record's envelope before encoding: its columns, or its
     * bundle when it has an attachment.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    public static function envelopeOf(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        return self::shapeOf($record->record, $record->toArray());
    }

    /**
     * The envelope of a record never finalised, before encoding, with
     * `unsigned` set.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    public static function unsignedEnvelopeOf(#[\SensitiveParameter] AuditRecord $record): array
    {
        return ['unsigned' => true, ...self::shapeOf($record, $record->toArray())];
    }

    /**
     * The canonical encoding of the record's envelope, refused as oversize
     * beyond the bound.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    public function encode(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        $envelope = CanonicalEncoder::encode(self::envelopeOf($record));

        if (strlen($envelope) > self::MAX_BYTES) {
            throw new EnvelopeRejectedException(EnvelopeFailure::OVERSIZE, $record->record->id);
        }

        return $envelope;
    }

    /**
     * The finalised record the envelope holds, once held to its schema,
     * verified and, when one is expected, of the expected id.
     *
     * @param  string  $json
     * @param  ?string  $expectedId
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    public function decode(#[\SensitiveParameter] string $json, ?string $expectedId = null): FinalisedRecord
    {
        if (strlen($json) > self::MAX_ENCODED_BYTES) {
            throw new EnvelopeRejectedException(EnvelopeFailure::OVERSIZE);
        }

        $fields = self::fieldsOf($json);
        $bundle = self::isBundle($fields);
        $id     = self::idOf($fields, $bundle);

        if (($fields['unsigned'] ?? null) === true) {
            throw new EnvelopeRejectedException(EnvelopeFailure::UNSIGNED, $id);
        }

        $columns = $bundle ? self::recordOf($fields, $id) : $fields;

        self::checkSchema($columns, self::schemaOf($columns, $id), $id);

        $this->verify($columns, $id);

        if ($bundle) {
            self::checkAttachment($fields['attachment'], $id);
        }

        if ($expectedId !== null && $expectedId !== $id) {
            throw new EnvelopeRejectedException(EnvelopeFailure::ID_MISMATCH, $id);
        }

        return $bundle ? self::rebuildBundle($json, $columns, $id) : self::rebuildRecord($json, $columns, $id);
    }

    /**
     * The record's envelope of the columns: those columns, or the bundle of
     * them and its attachment.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  array<string, mixed>  $columns
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    private static function shapeOf(#[\SensitiveParameter] AuditRecord $record, #[\SensitiveParameter] array $columns): array
    {
        if ($record->attachment === null) {
            return $columns;
        }

        return ['attachment' => $record->attachment->envelopeFor($record->id), 'bundle_version' => self::BUNDLE_VERSION, 'record' => $columns];
    }

    /**
     * The envelope's fields, refused unless a JSON object; a failed parse never
     * throws, so the input is never kept.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $json
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function fieldsOf(#[\SensitiveParameter] string $json): array
    {
        $decoded = json_decode($json, false, self::DEPTH);

        if (!$decoded instanceof \stdClass) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED);
        }

        return get_object_vars($decoded);
    }

    /**
     * Whether the envelope names a bundle version at its top.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return bool
     */
    private static function isBundle(#[\SensitiveParameter] array $fields): bool
    {
        return array_key_exists('bundle_version', $fields);
    }

    /**
     * The envelope's id, a bundle's from its record, or `null` when absent or
     * not a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  bool  $bundle
     * @return ?string
     */
    private static function idOf(#[\SensitiveParameter] array $fields, bool $bundle): ?string
    {
        $record = $fields['record'] ?? null;

        $id = match (true) {
            !$bundle                     => $fields['id'] ?? null,
            $record instanceof \stdClass => $record->id   ?? null,
            default                      => null,
        };

        return is_string($id) ? $id : null;
    }

    /**
     * The bundle's record columns, once it has exactly its three keys, a
     * supported version and an object record.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function recordOf(#[\SensitiveParameter] array $fields, ?string $id): array
    {
        $keys = array_keys($fields);

        sort($keys, SORT_STRING);

        if ($keys !== self::BUNDLE_KEYS || !is_int($fields['bundle_version'])) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        if (!in_array($fields['bundle_version'], self::SUPPORTED_BUNDLE_VERSIONS, true)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::UNSUPPORTED_VERSION, $id);
        }

        if (!$fields['record'] instanceof \stdClass) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        return get_object_vars($fields['record']);
    }

    /**
     * The schema of the envelope's record version, refusing a record or
     * integrity version that is missing, mistyped or unsupported.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return array<'instant'|'integer'|'json'|'nullable'|'string', non-empty-list<string>>
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function schemaOf(#[\SensitiveParameter] array $fields, ?string $id): array
    {
        $recordVersion    = $fields['record_version']    ?? null;
        $integrityVersion = $fields['integrity_version'] ?? null;

        if (!is_int($recordVersion) || !is_int($integrityVersion)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        if (!in_array($recordVersion, RecordVersion::SUPPORTED, true) || !in_array($integrityVersion, RecordSigner::SUPPORTED_VERSIONS, true)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::UNSUPPORTED_VERSION, $id);
        }

        return self::SCHEMAS[$recordVersion];
    }

    /**
     * Refuse as malformed fields with a column missing, added or of another
     * kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  array<'instant'|'integer'|'json'|'nullable'|'string', non-empty-list<string>>  $schema
     * @param  ?string  $id
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function checkSchema(#[\SensitiveParameter] array $fields, array $schema, ?string $id): void
    {
        if (count($fields) !== count(array_merge(...array_values($schema)))) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        foreach ($schema as $kind => $columns) {
            foreach ($columns as $column) {
                if (!array_key_exists($column, $fields) || !self::isOfKind($kind, $fields[$column])) {
                    throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
                }
            }
        }
    }

    /**
     * Whether the value is of the schema kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'instant'|'integer'|'json'|'nullable'|'string'  $kind
     * @param  mixed  $value
     * @return bool
     */
    private static function isOfKind(string $kind, #[\SensitiveParameter] mixed $value): bool
    {
        return match ($kind) {
            'string'   => is_string($value),
            'nullable' => $value === null || is_string($value),
            'integer'  => is_int($value),
            'instant'  => is_string($value) && StoredTime::isInstant($value),
            'json'     => self::isJsonColumn($value),
        };
    }

    /**
     * Whether the value is a JSON column's object, list or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true \stdClass|list<mixed>|null $value
     */
    private static function isJsonColumn(#[\SensitiveParameter] mixed $value): bool
    {
        return $value === null || $value instanceof \stdClass || (is_array($value) && array_is_list($value));
    }

    /**
     * Refuse an envelope whose key is unknown, whose values have no canonical
     * form, or whose signature does not match.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private function verify(#[\SensitiveParameter] array $fields, ?string $id): void
    {
        try {
            $verifies = $this->signer->verifies($fields);
        } catch (UnknownKeyException) {
            throw new EnvelopeRejectedException(EnvelopeFailure::UNKNOWN_KEY, $id);
        } catch (\UnexpectedValueException) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        if (!$verifies) {
            throw new EnvelopeRejectedException(EnvelopeFailure::SIGNATURE_MISMATCH, $id);
        }
    }

    /**
     * Refuse as malformed a bundle's attachment that breaks its schema or names
     * another entry.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $attachment
     * @param  ?string  $id
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function checkAttachment(#[\SensitiveParameter] mixed $attachment, ?string $id): void
    {
        if (!$attachment instanceof \stdClass) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        $fields = get_object_vars($attachment);

        self::checkSchema($fields, self::ATTACHMENT_SCHEMA, $id);

        if ($fields['entry_id'] !== $id) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }
    }

    /**
     * The finalised record of the verified plain envelope; one whose properties
     * hold a manifest descriptor is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $json
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function rebuildRecord(#[\SensitiveParameter] string $json, #[\SensitiveParameter] array $fields, ?string $id): FinalisedRecord
    {
        $assoc = json_decode($json, true, self::DEPTH);

        if (!is_array($assoc)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        return self::finalised(static fn (): AuditRecord => AuditRecord::fromEnvelope($assoc), $fields, $id);
    }

    /**
     * The finalised record of the verified bundle, rebuilt with the attachment
     * its signed descriptor describes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $json
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function rebuildBundle(#[\SensitiveParameter] string $json, #[\SensitiveParameter] array $fields, ?string $id): FinalisedRecord
    {
        $bundle = json_decode($json, true, self::DEPTH);

        assert(is_array($bundle) && is_array($bundle['record']) && is_array($bundle['attachment']));

        return self::finalised(static fn (): AuditRecord => AuditRecord::fromEnvelope($bundle['record'], Attachment::fromEnvelope($bundle['attachment'])), $fields, $id);
    }

    /**
     * The finalised record the closure rebuilds, its finalisation as signed and
     * its JSON columns as decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  array<array-key, mixed>  $fields
     * @param  ?string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function finalised(#[\SensitiveParameter] \Closure $record, #[\SensitiveParameter] array $fields, ?string $id): FinalisedRecord
    {
        ['recorded_at' => $recordedAt, 'integrity_version' => $integrityVersion, 'key_id' => $keyId, 'hmac' => $hmac, 'context' => $context, 'properties' => $properties] = $fields;

        if (!is_string($recordedAt) || !is_int($integrityVersion) || !is_string($keyId) || !is_string($hmac)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        if (!self::isJsonColumn($context) || !self::isJsonColumn($properties)) {
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }

        try {
            return FinalisedRecord::decoded($record(), $recordedAt, $integrityVersion, $keyId, $hmac, $context, $properties);
        } catch (\InvalidArgumentException) {
            // Its message names only the field; the refusal says no more
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }
    }
}
