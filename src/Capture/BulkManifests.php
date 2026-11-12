<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Records\Manifest;

/**
 * Builds bulk operations' manifests within the configured bounds, refusing a
 * store that keeps no attachment before any subject is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BulkManifests
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities  $capabilities
     * @param  \SineMacula\Laravel\AuditLog\Capture\CaptureSettings  $settings
     */
    public function __construct(

        /** What the bound store can keep. */
        private StoreCapabilities $capabilities,

        /** The capture settings, holding the manifest's bounds. */
        private CaptureSettings $settings,
    ) {}

    /**
     * The manifest of the subjects, each a model or a reference, kept once.
     *
     * @param  iterable<\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    public function of(#[\SensitiveParameter] iterable $subjects): Manifest
    {
        $this->capabilities->assertAcceptsAttachments();

        return Manifest::of($subjects, $this->settings->bulkMaxMembers(), $this->settings->bulkMaxBytes());
    }
}
