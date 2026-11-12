<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Readers a segment's verification applies to what it was given, never a
 * statement; a stored value of another type is read as none, never trusted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SegmentRows
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The findings of the seal's member rows; a set of another size fails both
     * checks, as it can never give the recorded digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  int  $count
     * @param  list<array{0: string, 1: string}>  $pairs
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    public static function membership(SealEnvelope $seal, int $count, array $pairs): array
    {
        if ($count !== $seal->memberCount) {
            return [[Finding::MEMBER_COUNT, $seal->id], [Finding::MEMBERS_DIGEST, $seal->id]];
        }

        try {
            $matches = SealEnvelope::membersDigest($pairs) === $seal->membersDigest;
        } catch (\InvalidArgumentException) {
            $matches = false;
        }

        return $matches ? [] : [[Finding::MEMBERS_DIGEST, $seal->id]];
    }

    /**
     * The finding of the seal's link to the seal before, which must name its id
     * and its recomputed digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $previous
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    public static function chain(SealEnvelope $seal, ?SegmentReport $previous): array
    {
        if ($previous === null) {
            return [];
        }

        $broken = $seal->previousId !== $previous->sealId
            || $previous->digest === null
            || $seal->previousDigest !== $previous->digest;

        return $broken ? [[Finding::CHAIN_BROKEN, $seal->id]] : [];
    }

    /**
     * Whether the seal breaks the genesis rule: only the first links to none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return bool
     */
    public static function breaksGenesis(SealEnvelope $seal): bool
    {
        if ($seal->sequence === 1) {
            return $seal->previousId !== null || $seal->previousDigest !== null;
        }

        return $seal->previousId === null || $seal->previousDigest === null;
    }

    /**
     * The receipt kept beside the seal, or `null` when there is none or it is
     * not a JSON object of string keys and scalars or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $stored
     * @return ?array<string, scalar|null>
     */
    public static function receiptOf(mixed $stored): ?array
    {
        $decoded = is_string($stored) ? json_decode($stored) : null;
        $fields  = $decoded instanceof \stdClass ? get_object_vars($decoded) : [];
        $receipt = array_filter($fields, static fn (mixed $value, int|string $key): bool => is_string($key) && ($value === null || is_scalar($value)), ARRAY_FILTER_USE_BOTH);

        /** @var array<string, scalar|null> $receipt */
        return $decoded instanceof \stdClass && count($receipt) === count($fields) ? $receipt : null;
    }

    /**
     * The stored seal's sequence, read from an integer or its decimal string,
     * or 0 when it is neither.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @return int
     */
    public static function sequenceOf(array $seal): int
    {
        return IntegerSetting::parse($seal['sequence'] ?? null) ?? 0;
    }

    /**
     * The earlier, bytewise, of the id kept so far and the id given.
     *
     * @param  ?string  $kept
     * @param  string  $id
     * @return string
     */
    public static function earliest(?string $kept, string $id): string
    {
        return $kept === null || strcmp($id, $kept) < 0 ? $id : $kept;
    }

    /**
     * The stored value when it is a string, and `null` otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function textOf(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
