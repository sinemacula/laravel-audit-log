<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * What verification established about a segment, the entries one seal covers,
 * in order of severity: a segment reports the most severe its checks found.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IntegrityStatus: string
{
    // Every check of the segment passed
    case VALID = 'valid';

    // Entries of the segment are missing, and a valid prune record for the
    // exact seal accounts for them
    case PRUNED = 'pruned';

    // Entries are missing with no prune record, or entries older than the
    // allowed age are still unsealed
    case INCOMPLETE = 'incomplete';

    // A check could not be made: a seal, a prune record or an entry is
    // malformed, of an unknown version, or under a key the ring does not hold
    case UNVERIFIABLE = 'unverifiable';

    // The log was altered: a digest, a signature, the chain, the members or the
    // anchor disagrees with what was sealed
    case TAMPERED = 'tampered';

    /**
     * How severe the status is, from 0 for `valid` to 4 for `tampered`.
     *
     * @return int
     */
    public function severity(): int
    {
        return match ($this) {
            self::VALID        => 0,
            self::PRUNED       => 1,
            self::INCOMPLETE   => 2,
            self::UNVERIFIABLE => 3,
            self::TAMPERED     => 4,
        };
    }

    /**
     * Whether the status fails a verification.
     *
     * @return bool
     */
    public function isFailure(): bool
    {
        return match ($this) {
            self::INCOMPLETE,
            self::UNVERIFIABLE,
            self::TAMPERED => true,
            default        => false,
        };
    }
}
