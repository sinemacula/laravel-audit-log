<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * What one sealing attempt did, and where the next batch reads on from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealBatch
{
    /** @var bool Whether the selection read fewer rows than it may, so nothing is left after them to read. */
    public bool $exhausted;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  ?string  $digest
     * @param  int  $read
     * @param  int  $skipped
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealCursor  $last
     * @param  int  $limit
     */
    public function __construct(

        /** The seal the attempt wrote, or `null` when it found nothing to seal. */
        public ?SealEnvelope $seal,

        /** The digest of the seal written, or `null` with no seal. */
        public ?string $digest,

        /** The rows the selection read. */
        public int $read,

        /** The candidates left out because their id, HMAC or time is malformed. */
        public int $skipped,

        /** The last row read, skipped or not, or `null` when none was. */
        public ?SealCursor $last,

        // The most rows the selection could read.
        int $limit,
    ) {
        $this->exhausted = $read < $limit;
    }
}
