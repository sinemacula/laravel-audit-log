<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Converts a finalised record to its entries and artifacts rows, and a stored
 * row back to its envelope, never a record, since a stored row is evidence.
 *
 * Times are written in UTC as `Y-m-d H:i:s.u`, since the grammar's own date
 * format drops microseconds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RowCodec
{
    /** @var array<string, 'integer'|'json'|'nullable'|'string'|'time'> Each column of the entries table and what it holds, in table order. */
    public const array COLUMNS = [
        'id'                => 'string',
        'record_version'    => 'integer',
        'event'             => 'string',
        'event_version'     => 'integer',
        'category'          => 'string',
        'outcome'           => 'string',
        'reason'            => 'nullable',
        'actor_type'        => 'nullable',
        'actor_id'          => 'nullable',
        'subject_type'      => 'nullable',
        'subject_id'        => 'nullable',
        'principal_type'    => 'nullable',
        'principal_id'      => 'nullable',
        'tenant_type'       => 'nullable',
        'tenant_id'         => 'nullable',
        'credential_id'     => 'nullable',
        'guard'             => 'nullable',
        'session_id'        => 'nullable',
        'request_id'        => 'nullable',
        'trace_id'          => 'nullable',
        'correlation_id'    => 'nullable',
        'origin'            => 'nullable',
        'provenance'        => 'string',
        'source_id'         => 'string',
        'source_region'     => 'nullable',
        'source_record_id'  => 'nullable',
        'import_batch_id'   => 'nullable',
        'source_digest'     => 'nullable',
        'ip'                => 'nullable',
        'user_agent'        => 'nullable',
        'context'           => 'json',
        'properties'        => 'json',
        'occurred_at'       => 'time',
        'recorded_at'       => 'time',
        'integrity_version' => 'integer',
        'key_id'            => 'string',
        'hmac'              => 'string',
    ];

    /** @var int The flags every JSON column is written with. */
    private const int JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    /**
     * The record as its insert row, in table order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, int|string|null>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public function encode(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        $row = $record->toArray();

        $row['context']     = self::encodeJson($row['context']);
        $row['properties']  = self::encodeJson($row['properties']);
        $row['occurred_at'] = StoredTime::toStorage($row['occurred_at']);
        $row['recorded_at'] = StoredTime::toStorage($row['recorded_at']);

        return $row;
    }

    /**
     * The record's sealed attachment as its artifacts row, with the record's id
     * as its entry and the record's recorded time.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string, created_at: string}
     *
     * @throws \LogicException
     */
    public function encodeAttachment(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        $attachment = $record->record->attachment ?? throw new \LogicException('Only a bulk record has an attachment to store.');

        return [
            ...$attachment->envelopeFor($record->record->id),
            'created_at' => StoredTime::toStorage($record->recordedAt),
        ];
    }

    /**
     * The envelope a stored row holds, every column required; keys beyond the
     * table's columns are dropped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return array<string, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public function decode(#[\SensitiveParameter] array $row): array
    {
        $envelope = [];

        foreach (self::COLUMNS as $column => $kind) {
            if (!array_key_exists($column, $row)) {
                throw new \UnexpectedValueException(sprintf('A stored entry has no `%s` column.', $column));
            }

            $envelope[$column] = self::decodeValue($column, $kind, $row[$column]);
        }

        return $envelope;
    }

    /**
     * The JSON column as written, so a decoded record's `{}` and numeric-keyed
     * maps stay objects.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|\stdClass|null  $value
     * @return ?string
     *
     * @throws \JsonException
     */
    private static function encodeJson(#[\SensitiveParameter] array|\stdClass|null $value): ?string
    {
        return $value === null ? null : json_encode($value, self::JSON_FLAGS);
    }

    /**
     * The stored value read as its column's kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  'integer'|'json'|'nullable'|'string'|'time'  $kind
     * @param  mixed  $value
     * @return mixed
     *
     * @throws \UnexpectedValueException
     */
    private static function decodeValue(string $column, string $kind, #[\SensitiveParameter] mixed $value): mixed
    {
        return match ($kind) {
            'string'   => is_string($value) ? $value : throw self::malformed($column, 'a string'),
            'nullable' => $value === null || is_string($value) ? $value : throw self::malformed($column, 'a string or null'),
            'integer'  => IntegerSetting::parse($value) ?? throw self::malformed($column, 'an integer'),
            'json'     => self::decodeJson($column, $value),
            'time'     => self::decodeTime($column, $value),
        };
    }

    /**
     * The stored JSON with objects as `stdClass` and numbers never stringified,
     * so an out-of-range integer decodes as a float verification refuses.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return mixed
     *
     * @throws \UnexpectedValueException
     */
    private static function decodeJson(string $column, #[\SensitiveParameter] mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw self::malformed($column, 'JSON or null');
        }

        try {
            return json_decode($value, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw self::malformed($column, 'JSON or null', $exception);
        }
    }

    /**
     * The stored time in the package's form.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function decodeTime(string $column, #[\SensitiveParameter] mixed $value): string
    {
        if (!is_string($value)) {
            throw self::malformed($column, 'a stored time');
        }

        try {
            return StoredTime::fromStorage($value);
        } catch (\UnexpectedValueException $exception) {
            throw self::malformed($column, 'a stored time', $exception);
        }
    }

    /**
     * The refusal of a column whose stored value is not what it must hold.
     *
     * @param  string  $column
     * @param  string  $what
     * @param  ?\Throwable  $previous
     * @return \UnexpectedValueException
     */
    private static function malformed(string $column, string $what, #[\SensitiveParameter] ?\Throwable $previous = null): \UnexpectedValueException
    {
        return new \UnexpectedValueException(sprintf('A stored entry\'s `%s` is not %s.', $column, $what), 0, $previous);
    }
}
