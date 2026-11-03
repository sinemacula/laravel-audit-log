<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * Checkpoint anchor contract: where each seal's summary is kept as evidence
 * outside the application's writable trust boundary, so a log rewritten or
 * truncated by someone who can write to the database still disagrees with what
 * the anchor holds.
 *
 * The package binds the anchor `audit-log.integrity.anchor.driver` names, and
 * by default `Integrity\Anchors\NullAnchor`, which anchors nothing; an
 * application rebinds the contract to keep the summaries somewhere it trusts
 * more. Anchoring is idempotent: the same summary gives the same receipt, and
 * another digest for a sequence the anchor already holds is a conflict, never a
 * replacement. The receipt is kept beside the seal as a cache, never as the
 * authority, so verification asks the anchor whether it still confirms it, and
 * asks for the anchor's head independently of every receipt. An implementation
 * must keep no state between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CheckpointAnchor
{
    /**
     * The anchor's stable name, 1 to 64 characters, which is kept beside each
     * seal it anchors: a seal anchored under another name is anchored again, so
     * an anchor whose name says where it keeps the summaries is anchored afresh
     * when it moves.
     *
     * @return string
     */
    public function name(): string;

    /**
     * Keep the summary and return its receipt, a map of string keys to scalars
     * or `null`, small enough to keep beside the seal. Anchoring the same
     * summary again returns the same receipt and changes nothing; a summary
     * whose sequence the anchor already holds under another digest is an
     * `AnchorConflictException`, and any other exception means the anchor is
     * unavailable, so a later run tries again.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array<string, scalar|null>
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    public function anchor(SealSummary $seal): array;

    /**
     * Whether the receipt still proves that the anchor holds exactly the
     * summary: `false` when the anchor no longer holds it, or the receipt names
     * another summary or is not one of this anchor's. It throws only when the
     * anchor cannot be read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     */
    public function confirms(SealSummary $seal, array $receipt): bool;

    /**
     * Whether the anchor can report its head through `latest()`. Without it a
     * truncated tail cannot be found, so a strict verification fails.
     *
     * @return bool
     */
    public function supportsDiscovery(): bool;

    /**
     * The newest seal the anchor holds for the log, `null` when it holds none.
     * It is asked only when `supportsDiscovery()` is `true`, and throws when it
     * cannot tell, never answering `null` for a history it could not read; an
     * anchor that holds two digests for its newest sequence throws an
     * `AnchorConflictException`.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    public function latest(): ?AnchoredHead;
}
