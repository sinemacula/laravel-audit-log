<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * How the verification of a segment reads what it was given: the findings of a
 * seal's set of members and of its link to the seal before, the genesis rule,
 * the receipt kept beside a seal, a stored seal's sequence, the earlier of two
 * ids and a stored value as text.
 *
 * Each reads only what it is given and never a statement, so a stored value of
 * another type is read as none rather than trusted.
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
     * The findings of the set of members: the rows must be as many as the seal
     * counts, and their pairs must give the members digest. A seal with more or
     * fewer rows fails both, since a set of another size never gives the digest
     * the seal recorded.
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
     * The finding of the seal's link to the seal before, when the run has one:
     * the link must name its id and its recomputed digest, so a link to a seal
     * that cannot be read, which has none, is broken.
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
     * Whether the seal breaks the genesis rule: the first seal links to none,
     * and every later one links to the seal before by both its id and its
     * digest.
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
