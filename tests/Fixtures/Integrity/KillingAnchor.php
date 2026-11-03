<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * An anchor that hands every call to another and ends the process by `SIGKILL`
 * around an anchoring: before the call reaches the anchor, or after the anchor
 * has kept the summary and before its receipt is returned. Nothing runs after
 * the kill, so the process dies at exactly that boundary; it is for the
 * children of the crash tests only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KillingAnchor implements CheckpointAnchor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  bool  $killBefore
     * @param  bool  $killAfter
     */
    public function __construct(

        /** The anchor every call is handed to. */
        private CheckpointAnchor $anchor,

        /** Whether the process dies before an anchoring reaches the anchor. */
        private bool $killBefore = false,

        /** Whether the process dies after the anchor has kept a summary, before its receipt is returned. */
        private bool $killAfter = false,
    ) {}

    /**
     * The anchor's name.
     *
     * @return string
     */
    #[\Override]
    public function name(): string
    {
        return $this->anchor->name();
    }

    /**
     * Hand the summary to the anchor, dying before or after it as constructed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array<string, scalar|null>
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    #[\Override]
    public function anchor(SealSummary $seal): array
    {
        if ($this->killBefore) {
            self::killThisProcess();
        }

        $receipt = $this->anchor->anchor($seal);

        if ($this->killAfter) {
            self::killThisProcess();
        }

        return $receipt;
    }

    /**
     * Whether the anchor confirms the receipt.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     */
    #[\Override]
    public function confirms(SealSummary $seal, array $receipt): bool
    {
        return $this->anchor->confirms($seal, $receipt);
    }

    /**
     * Whether the anchor can report its head.
     *
     * @return bool
     */
    #[\Override]
    public function supportsDiscovery(): bool
    {
        return $this->anchor->supportsDiscovery();
    }

    /**
     * The anchor's head.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    #[\Override]
    public function latest(): ?AnchoredHead
    {
        return $this->anchor->latest();
    }

    /**
     * End this process by `SIGKILL`, which nothing can handle or delay.
     *
     * @return never
     */
    private static function killThisProcess(): never
    {
        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
