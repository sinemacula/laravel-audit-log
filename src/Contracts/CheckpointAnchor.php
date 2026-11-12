<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * Checkpoint anchor contract: keeps each seal's summary outside the
 * application's writable trust boundary, so a rewritten or truncated log
 * disagrees with it.
 *
 * Anchoring is idempotent, a receipt is a cache and never the authority, and an
 * implementation keeps no state.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CheckpointAnchor
{
    /**
     * The anchor's stable name, 1 to 64 characters; a seal anchored under
     * another name is anchored again.
     *
     * @return string
     */
    public function name(): string;

    /**
     * Keep the summary and return its receipt, a small map of strings to
     * scalars or `null`; the same summary gives the same receipt. Any exception
     * but a conflict means the anchor is unavailable, so a later run retries.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array<string, scalar|null>
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    public function anchor(SealSummary $seal): array;

    /**
     * Whether the receipt still proves the anchor holds exactly the summary; it
     * throws only when the anchor cannot be read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     */
    public function confirms(SealSummary $seal, array $receipt): bool;

    /**
     * Whether the anchor reports its head through `latest()`, without which a
     * strict verification fails.
     *
     * @return bool
     */
    public function supportsDiscovery(): bool;

    /**
     * The newest seal the anchor holds, or `null` when none; asked only under
     * discovery, it throws rather than answer `null` for a history it could not
     * read.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    public function latest(): ?AnchoredHead;
}
