<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Anchors;

use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * The anchor bound when none is configured: it anchors and confirms nothing, so
 * every seal is reported unanchored. The package never asks it to anchor.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullAnchor implements CheckpointAnchor
{
    /**
     * The anchor's name, `null`, the driver that configures it.
     *
     * @return string
     */
    #[\Override]
    public function name(): string
    {
        return 'null';
    }

    /**
     * Refuse to anchor: the package never asks this anchor to.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array<string, scalar|null>
     *
     * @throws \LogicException
     */
    #[\Override]
    public function anchor(SealSummary $seal): array
    {
        throw new \LogicException('The null anchor anchors nothing; bind a CheckpointAnchor to anchor seals.');
    }

    /**
     * Whether the receipt proves the summary: never, since nothing is held.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     */
    #[\Override]
    public function confirms(SealSummary $seal, array $receipt): bool
    {
        return false;
    }

    /**
     * Whether the anchor can report its head: it cannot.
     *
     * @return bool
     */
    #[\Override]
    public function supportsDiscovery(): bool
    {
        return false;
    }

    /**
     * The newest seal the anchor holds: none.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     */
    #[\Override]
    public function latest(): ?AnchoredHead
    {
        return null;
    }
}
