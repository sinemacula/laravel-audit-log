<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * A segment's anchoring as verification found it. A receipt that does not
 * confirm leaves a seal `unanchored`: only the anchor can contradict it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AnchorStatus: string
{
    // The anchor confirms the seal's receipt
    case ANCHORED = 'anchored';

    // The seal has no receipt the anchor confirms, or no anchor is configured
    case UNANCHORED = 'unanchored';

    // The anchor failed when it was asked, so the seal could not be confirmed
    case UNAVAILABLE = 'unavailable';

    // The anchor holds another digest for the seal, or a head the local log
    // does not reach
    case CONTRADICTED = 'contradicted';

    /**
     * Whether the status confirms the seal.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this === self::ANCHORED;
    }
}
