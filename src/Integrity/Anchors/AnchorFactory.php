<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Anchors;

use Illuminate\Contracts\Filesystem\Factory;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;

/**
 * Makes the anchor the settings configure: the null anchor when no driver is
 * configured, and a disk anchor on the configured disk, under the configured
 * path, for the log every seal names, for `disk`.
 *
 * The settings are read on every call, so a changed setting takes effect on the
 * next anchor made, and a malformed one fails closed before any disk is
 * resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AnchorFactory
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings  $anchors
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $seals
     * @param  \Illuminate\Contracts\Filesystem\Factory  $filesystems
     */
    public function __construct(

        /** The anchor settings: the driver, the disk and the path. */
        private AnchorSettings $anchors,

        /** The sealing settings, for the log id. */
        private SealSettings $seals,

        /** The filesystems the disk is resolved from. */
        private Factory $filesystems,
    ) {}

    /**
     * The anchor the settings configure.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor
     *
     * @throws \InvalidArgumentException
     */
    public function make(): CheckpointAnchor
    {
        return match ($this->anchors->driver()) {
            AnchorDriver::NONE => new NullAnchor,
            AnchorDriver::DISK => $this->diskAnchor(),
        };
    }

    /**
     * A disk anchor on the configured disk, under the configured path, for the
     * configured log, every setting read before the disk is resolved.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     *
     * @throws \InvalidArgumentException
     */
    private function diskAnchor(): DiskAnchor
    {
        $disk  = $this->anchors->disk();
        $path  = $this->anchors->path();
        $logId = $this->seals->logId();

        return new DiskAnchor($this->filesystems->disk($disk), $disk, $path, $logId);
    }
}
