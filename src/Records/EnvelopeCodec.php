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
 * encoding of its 36 columns, or of the bundle a record with an attachment is
 * kept as, and the finalised record a verified envelope holds, rebuilt without
 * loss.
 *
 * An envelope takes one of two shapes. A record without an attachment is its
 * columns. A record with one is a bundle of three keys: `bundle_version`, the
 * bundle schema's version; `record`, its columns; and `attachment`, its id,
 * entry id, kind, member count, digest and sealed members. The attachment is of
 * any kind, a bulk operation's subjects, a disclosure's evidence or an export's
 * manifest, in the one schema; its kind and the count that kind allows are the
 * attachment's own rules. A record that was never finalised is kept in either
 * shape with `unsigned` set beside it. The envelope's bound applies to the
 * whole of it, the attachment included. An attachment described from a stored
 * entry carries no members and is refused as a programming error, never
 * encoded.
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
 * A bundle is read the same way, after its own checks: exactly its three keys,
 * then a bundle version this release reads. Its record is verified as any
 * other, then its attachment is held to its schema and must name that record as
 * its entry. The attachment is not signed: it is bound by the descriptor the
 * record signs at `properties._audit.manifest`, so a bundle whose attachment
 * the descriptor does not describe is malformed, as is one of a kind the
 * release does not know or a count its kind refuses, and so is a plain envelope
 * whose properties hold a descriptor, which never becomes a record that lost
 * its members. Every refusal of a bundle names the id of its record.
 *
 * A rebuilt record keeps its id, its times, its provenance and its JSON columns
 * as they were decoded, objects as objects, so it encodes to the same bytes and
 * carries the same signature. The codec never minimises, sanitises or finalises
 * a record again: the envelope is evidence of a record already captured and
 * signed. A bundle's record nests one level deeper than a plain envelope's
 * columns and is decoded to the same depth, which captured values, bounded far
 * shallower, never approach.
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
     * The finalised record's envelope, before it is encoded: its columns, or,
     * for a record with an attachment, the bundle of its columns and its
     * attachment.
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
     * The envelope of a record that was never finalised, before it is encoded:
     * either shape, its columns or its bundle, with `unsigned` set beside it
     * and no integrity field.
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
     * The finalised record's envelope: the canonical encoding of its columns,
     * or of its bundle, refused as oversize beyond the bound, which applies to
     * the whole bundle.
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
     * The finalised record the envelope holds, once it is held to its version's
     * schema and its signature verifies, a bundle's attachment once it is held
     * to its own and names the record, and, when an id is expected, once its id
     * is that id; otherwise the refusal naming the first failure.
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
     * The record's envelope of the columns given: those columns, or, when the
     * record carries an attachment, the bundle of them and the attachment,
     * which names the record as its entry.
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
     * Whether the envelope is a bundle: one that names a bundle version at its
     * top, whatever else it holds.
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
     * The envelope's id as it was read, a bundle's from its record, or `null`
     * when it has none or it is not a string.
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
     * The bundle's record columns, once the bundle has exactly its three keys
     * and a version this release reads: refused as malformed for another key or
     * a missing one, a version that is not an integer or a record that is not
     * an object, and as unsupported for a version it does not read.
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
     * Refuse as malformed an envelope's record, or a bundle's attachment, that
     * has a field the schema does not name, lacks one it names, or holds a
     * value of another kind.
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
     * Refuse as malformed a bundle's attachment that is not an object, has a
     * field its schema does not name, lacks one it names, holds a value of
     * another kind, or names an entry other than the bundle's record.
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
     * The finalised record of the verified plain envelope, which takes no
     * attachment, so one whose properties hold a manifest descriptor is refused
     * as malformed.
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

        return self::finalised(static fn (): AuditRecord => AuditRecord::fromEnvelope($assoc), $fields, $id);
    }

    /**
     * The finalised record of the verified bundle, rebuilt with its attachment,
     * which must be of a known kind with a count that kind allows, and the one
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
     * The finalised record of the record the closure rebuilds: its finalisation
     * as signed, and its JSON columns as decoded; refused as malformed when a
     * constructor refuses a value.
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

        try {
            return FinalisedRecord::decoded($record(), $recordedAt, $integrityVersion, $keyId, $hmac, $context, $properties);
        } catch (\InvalidArgumentException) {
            // Its message names only the field; the refusal says no more
            throw new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id);
        }
    }
}
