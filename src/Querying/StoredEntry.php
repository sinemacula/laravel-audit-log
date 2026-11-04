<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * A row of the entries table exactly as the row codec decodes it: every column
 * in table order, its JSON as `stdClass` objects so `{}` and maps with numeric
 * keys survive, and its integrity fields, the integrity version, key id and
 * HMAC, included. It is evidence: nothing here trims, folds, conceals or
 * decrypts a value, and its line is the canonical encoding the entry was signed
 * over, byte for byte what the NDJSON formatter writes for the same finalised
 * record.
 *
 * A finalised record rebuilt from it serves a projection, an OCSF or a CEF
 * line, alone: a record with an artifact carries an attachment described from
 * its signed descriptor, with no members, which can never be stored, queued or
 * spilled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoredEntry
{
    /** @var string The key the package's metadata sits under in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The key the manifest descriptor sits under in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     */
    private function __construct(

        /** The decoded row: every column of the entries table, in table order, as the row codec read it. */
        #[\SensitiveParameter]
        public array $envelope,
    ) {}

    /**
     * The entry a stored row holds, decoded by the row codec with every column
     * required and each read as its kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromRow(#[\SensitiveParameter] array $row, RowCodec $codec): self
    {
        return new self($codec->decode($row));
    }

    /**
     * The entry's id.
     *
     * @return string
     */
    public function id(): string
    {
        return $this->text('id');
    }

    /**
     * The entry's HMAC, lower-case hex, as stored.
     *
     * @return string
     */
    public function hmac(): string
    {
        return $this->text('hmac');
    }

    /**
     * The id of the key the entry was signed with.
     *
     * @return string
     */
    public function keyId(): string
    {
        return $this->text('key_id');
    }

    /**
     * When the activity occurred, as an instant in the package's form.
     *
     * @return string
     */
    public function occurredAt(): string
    {
        return $this->text('occurred_at');
    }

    /**
     * When the entry was recorded, as an instant in the package's form.
     *
     * @return string
     */
    public function recordedAt(): string
    {
        return $this->text('recorded_at');
    }

    /**
     * The entry's place in the order of a page: when its activity occurred,
     * then its id.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \InvalidArgumentException
     */
    public function occurredPosition(): Position
    {
        return new Position($this->occurredAt(), $this->id());
    }

    /**
     * The entry's place in the order of an export: when it was recorded, then
     * its id.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \InvalidArgumentException
     */
    public function recordedPosition(): Position
    {
        return new Position($this->recordedAt(), $this->id());
    }

    /**
     * The manifest descriptor the entry signed at `_audit.manifest`, as stored,
     * with its maps as arrays, or `null` when its properties hold none. A value
     * there that is not a map is given as an empty array, which no descriptor
     * check accepts.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return ?array<array-key, mixed>
     */
    public function descriptor(): ?array
    {
        $properties = $this->envelope['properties'];
        $metadata   = $properties instanceof \stdClass ? ($properties->{self::METADATA_KEY} ?? null) : null;

        if (!$metadata instanceof \stdClass || !property_exists($metadata, self::MANIFEST_KEY)) {
            return null;
        }

        $descriptor = self::associative($metadata->{self::MANIFEST_KEY});

        return is_array($descriptor) ? $descriptor : [];
    }

    /**
     * The entry as one line of newline-delimited JSON, without its line feed:
     * its envelope in the canonical encoding it was signed over.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function line(): string
    {
        return CanonicalEncoder::encode($this->envelope);
    }

    /**
     * The finalised record the entry holds, for a projection alone: the record
     * rebuilt from the envelope with its maps as arrays and, when it signed a
     * descriptor, an attachment described from it with no members; its
     * finalisation as stored, and its JSON columns as they were decoded, so the
     * record's envelope is the entry's. A column the record cannot hold, or a
     * descriptor that is not exactly one, is refused.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function finalised(): FinalisedRecord
    {
        $context    = $this->json('context');
        $properties = $this->json('properties');
        $descriptor = $this->descriptor();

        $fields = ['context' => self::associative($context), 'properties' => self::associative($properties)] + $this->envelope;
        $record = AuditRecord::fromEnvelope($fields, $descriptor === null ? null : Attachment::described($descriptor));

        return FinalisedRecord::decoded($record, $this->recordedAt(), $this->integer('integrity_version'), $this->keyId(), $this->hmac(), $context, $properties);
    }

    /**
     * The value with every `stdClass` within it, itself included, as an
     * associative array of its members, and everything else as it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function associative(#[\SensitiveParameter] mixed $value): mixed
    {
        if ($value instanceof \stdClass) {
            $value = get_object_vars($value);
        }

        return is_array($value) ? array_map(self::associative(...), $value) : $value;
    }

    /**
     * The JSON column's decoded value, which a record can hold only as an
     * object, a list or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'context'|'properties'  $column
     * @return array<array-key, mixed>|\stdClass|null
     *
     * @throws \UnexpectedValueException
     */
    private function json(string $column): array|\stdClass|null
    {
        $value = $this->envelope[$column];

        if ($value === null || $value instanceof \stdClass || is_array($value)) {
            return $value;
        }

        throw new \UnexpectedValueException(sprintf('A stored entry\'s `%s` is not an object, a list or null.', $column));
    }

    /**
     * The column the row codec read as a string, or a time it read into the
     * package's form.
     *
     * @param  'hmac'|'id'|'key_id'|'occurred_at'|'recorded_at'  $column
     * @return string
     */
    private function text(string $column): string
    {
        $value = $this->envelope[$column];

        // The codec reads each of these columns as a string or refuses the row
        assert(is_string($value));

        return $value;
    }

    /**
     * The column the row codec read as an integer.
     *
     * @param  'integrity_version'  $column
     * @return int
     */
    private function integer(string $column): int
    {
        $value = $this->envelope[$column];

        // The codec reads each of these columns as an integer or refuses the
        // row
        assert(is_int($value));

        return $value;
    }
}
