<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Casts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Reads a stored time as an instant in UTC with its microseconds, whatever the
 * application's time zone, and writes an instant back in the stored form.
 *
 * Laravel's `datetime` cast parses a stored time in the application's time zone
 * and formats one with the grammar's format, which drops microseconds; this
 * cast reads and writes only through `StoredTime`, so a time reads back as the
 * instant that was stored, to the microsecond.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<\Carbon\CarbonImmutable, \DateTimeInterface>
 */
final readonly class UtcInstant implements CastsAttributes
{
    /**
     * The stored time as an instant in UTC, its microseconds kept; `null` stays
     * `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function get(Model $model, string $key, mixed $value, array $attributes): ?CarbonImmutable
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new \UnexpectedValueException('A stored time must be `Y-m-d H:i:s` with up to six fractional digits.');
        }

        return StoredTime::instant($value);
    }

    /**
     * The instant as the database stores it, in UTC with microseconds; `null`
     * stays `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!$value instanceof \DateTimeInterface) {
            throw new \InvalidArgumentException(sprintf('`%s` must be set to an instant or null.', $key));
        }

        return StoredTime::toStorage(StoredTime::format($value));
    }
}
