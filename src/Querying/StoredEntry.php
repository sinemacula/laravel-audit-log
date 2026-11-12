<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * A row of the entries table exactly as the row codec decodes it, kept as
 * evidence: JSON stays `stdClass` so `{}` and numeric-keyed maps survive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoredEntry
{
    /** @var string The package's metadata key in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The manifest descriptor's key in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     */
    private function __construct(

        /** Every column of the decoded row, in table order. */
        #[\SensitiveParameter]
        public array $envelope,
    ) {}

    /**
     * The entry a stored row holds.
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
     * The entry's place in a page's order.
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
     * The entry's place in an export's order.
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
     * The signed descriptor at `_audit.manifest`, or `null` for none; a non-map
     * is an empty array, which no descriptor check accepts.
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
     * The entry's NDJSON line, without its line feed, as it was signed.
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
     * The finalised record, for a projection alone: its attachment has no
     * members, so it can never be stored, queued or spilled.
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
     * The value with every `stdClass` in it as an associative array.
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
     * The JSON column's decoded object, list or `null`.
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
     * The column the row codec read as a string.
     *
     * @param  'hmac'|'id'|'key_id'|'occurred_at'|'recorded_at'  $column
     * @return string
     */
    private function text(string $column): string
    {
        $value = $this->envelope[$column];

        // The codec reads these columns as a string or refuses the row
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

        // The codec reads these columns as an integer or refuses the row
        assert(is_int($value));

        return $value;
    }
}
