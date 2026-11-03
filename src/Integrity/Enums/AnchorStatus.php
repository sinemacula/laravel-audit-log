<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * What verification established about a segment's anchoring, apart from its
 * integrity: the anchor confirms the seal, the seal has not been confirmed, the
 * anchor could not be asked, or the anchor holds something else.
 *
 * A receipt kept beside a seal is only a cache, so one that does not confirm
 * leaves the seal `unanchored`, never `contradicted`: only what the anchor
 * itself returns can contradict the local log. With no anchor configured, every
 * segment is `unanchored`, which is then informational.
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
     * Whether the status confirms the seal: only `anchored` does.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this === self::ANCHORED;
    }
}
