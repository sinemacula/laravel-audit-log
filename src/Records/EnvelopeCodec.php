<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The one conversion between a finalised record and the envelope it is kept in
 * outside the entries table, in the outbox or a spill line: the canonical
 * encoding of its 36 columns, and the finalised record a verified envelope
 * holds, rebuilt without loss.
 *
 * Decoding reads the envelope's record version and holds it to that version's
 * schema, exactly its columns, each of its kind, before it verifies the
 * signature, and only an envelope that verifies is rebuilt. Each refusal is a
 * distinct `EnvelopeFailure`, checked in a fixed order: an input too large to
 * parse, one that is not a JSON object, an envelope that says it is unsigned, a
 * version missing or not an integer, a version this release does not read, a
 * column missing, added or of another kind, a key the ring does not hold, a
 * signature that does not match or a value with no canonical form, an id other
 * than the one expected, and a record its constructor refuses.
 *
 * A rebuilt record keeps its id, its times, its provenance and its JSON columns
 * as they were decoded, objects as objects, so it encodes to the same bytes and
 * carries the same signature. The codec never minimises, sanitises or finalises
 * a record again: the envelope is evidence of a record already captured and
 * signed.
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

    /** @var int The depth an envelope is decoded to: one more than the row codec reads a JSON column with, for the envelope's own object. */
    private const int DEPTH = 513;

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
                'source_region', 'source_record_id', 'import_batch_id', 'ip', 'user_agent',
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
     * The finalised record's envelope: the canonical encoding of its columns,
     * refused as oversize beyond the bound.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    public function encode(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        $envelope = CanonicalEncoder::encode($record->toArray());

        if (strlen($envelope) > self::MAX_BYTES) {
            throw new EnvelopeRejectedException(EnvelopeFailure::OVERSIZE, $record->record->id);
        }

        return $envelope;
    }

    /**
     * The finalised record the envelope holds, once it is held to its version's
     * schema and its signature verifies, and, when an id is expected, once its
     * id is that id; otherwise the refusal naming the first failure.
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
        $id     = self::idOf($fields);

        if (($fields['unsigned'] ?? null) === true) {
            throw new EnvelopeRejectedException(EnvelopeFailure::UNSIGNED, $id);
        }

        self::checkSchema($fields, self::schemaOf($fields, $id), $id);

        $this->verify($fields, $id);

        if ($expectedId !== null && $expectedId !== $id) {
            throw new EnvelopeRejectedException(EnvelopeFailure::ID_MISMATCH, $id);
        }

        return self::rebuild($json, $fields, $id);
    }

    /**
     * The envelope's columns, decoded with objects as `stdClass` and every
     * number as JSON reads it, refused as malformed unless it is a JSON object.
     * A parse that fails gives `null`, never an exception, so neither the input
     * nor the parser's message is kept anywhere.
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
     * The envelope's id as it was read, or `null` when it has none or it is not
     * a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return ?string
     */
    private static function idOf(#[\SensitiveParameter] array $fields): ?string
    {
        $id = $fields['id'] ?? null;

        return is_string($id) ? $id : null;
    }

    /**
     * The schema of the envelope's record version: refused as malformed when
     * either version is missing or not an integer, and as unsupported when
     * either is one this release does not read.
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
     * Refuse as malformed an envelope that has a column the schema does not
     * name, lacks one it names, or holds a value of another kind.
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
     * Whether the value is of the kind: a string, a string or `null`, an
     * integer, an instant in the package's form, or a JSON column's object,
     * list or `null`.
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
            'json'     => $value === null || $value instanceof \stdClass || (is_array($value) && array_is_list($value)),
        };
    }

    /**
     * Refuse an envelope whose signature cannot be checked, because its key is
     * not in the ring or a value has no canonical form, or does not match.
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
     * The finalised record of the verified envelope: the record rebuilt from
     * its array view, its finalisation as signed, and its JSON columns as
     * decoded; refused as malformed when a constructor refuses a value.
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
    private static function rebuild(#[\SensitiveParameter] string $json, #[\SensitiveParameter] array $fields, ?string $id): FinalisedRecord
    {
        $assoc = json_decode($json, true, self::DEPTH);

        ['recorded_at' => $recordedAt, 'integrity_version' => $integrityVersion, 'key_id' => $keyId, 'hmac' => $hmac, 'context' => $context, 'properties' => $properties] = $fields;

        try {
            return FinalisedRecord::decoded(AuditRecord::fromEnvelope($assoc), $recordedAt, $integrityVersion, $keyId, $hmac, $context, $properties);
        } catch (\InvalidArgumentException) {
            // Its message names only the column; the refusal says no more
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }
    }
}
