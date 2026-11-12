<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The newest seal an anchor holds for the log, checked against the local seal
 * at its sequence to find a truncated or rewritten log.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AnchoredHead
{
    /**
     * Constructor.
     *
     * @param  int  $sequence
     * @param  string  $digest
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The sequence of the newest seal the anchor holds, at least 1. */
        public int $sequence,

        /** That seal's digest, 64 lower-case hex. */
        public string $digest,
    ) {
        if ($sequence < 1) {
            throw new \InvalidArgumentException('An anchored head\'s sequence must be at least 1.');
        }

        if (preg_match(SealEnvelope::DIGEST_PATTERN, $digest) !== 1) {
            throw new \InvalidArgumentException('An anchored head\'s digest must be 64 lower-case hexadecimal characters.');
        }
    }
}
