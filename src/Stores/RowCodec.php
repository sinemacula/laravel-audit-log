<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The one conversion between a finalised record and a row of the entries table:
 * the record encoded for its insert, and a stored row decoded back to the
 * envelope it holds.
 *
 * A row is written with its JSON in fixed flags, its integers as they are, and
 * its times in UTC as `Y-m-d H:i:s.u`, written out explicitly because the
 * grammar's own date format drops microseconds. A row is read back with every
 * column required: an integer the engine returns as a digit string reads as the
 * integer, JSON decodes to `stdClass` objects so `{}` and numeric keys survive,
 * and a JSON number is never turned into a string, so a fraction or an integer
 * beyond PHP's range decodes as a float that verification refuses. Decoding
 * returns the envelope, never a record: a stored row is evidence. The codec
 * never trims, folds case or normalises a value.
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
     * The record as the row its insert writes, in table order: strings and
     * integers as they are, JSON columns encoded with the fixed flags or left
     * `null`, and times in UTC as `Y-m-d H:i:s.u`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, int|string|null>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public function encode(FinalisedRecord $record): array
    {
        $row = $record->toArray();

        $row['context']     = self::encodeJson($row['context']);
        $row['properties']  = self::encodeJson($row['properties']);
        $row['occurred_at'] = StoredTime::toStorage($row['occurred_at']);
        $row['recorded_at'] = StoredTime::toStorage($row['recorded_at']);

        return $row;
    }

    /**
     * The envelope a stored row holds, in table order: every column required,
     * each read as its kind; keys the row has beyond the table's columns are
     * dropped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @return array<string, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public function decode(array $row): array
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
     * The JSON column's value as the insert writes it: `null` stays `null`, and
     * an array is encoded with the fixed flags.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $value
     * @return ?string
     *
     * @throws \JsonException
     */
    private static function encodeJson(?array $value): ?string
    {
        return $value === null ? null : json_encode($value, self::JSON_FLAGS);
    }

    /**
     * The stored value of the column read as its kind, or a refusal naming the
     * column and what it must hold.
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
    private static function decodeValue(string $column, string $kind, mixed $value): mixed
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
     * The stored JSON decoded with objects as `stdClass` and every number as
     * JSON reads it, or `null` for a `null` column.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return mixed
     *
     * @throws \UnexpectedValueException
     */
    private static function decodeJson(string $column, mixed $value): mixed
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
    private static function decodeTime(string $column, mixed $value): string
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
    private static function malformed(string $column, string $what, ?\Throwable $previous = null): \UnexpectedValueException
    {
        return new \UnexpectedValueException(sprintf('A stored entry\'s `%s` is not %s.', $column, $what), 0, $previous);
    }
}
