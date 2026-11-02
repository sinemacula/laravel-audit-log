<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Fills where the activity ran from the innermost execution frame: its origin
 * and, for a command or a job with a name, that name in the context. Outside
 * any frame the origin is console, with no name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OriginContributor implements ContextContributor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     */
    public function __construct(

        /** What the current code is running in. */
        private ExecutionFrames $frames,
    ) {}

    /**
     * Fill the origin, and the name of the command or job.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        $contribution->fillOrigin($this->frames->origin());

        $frame = $this->frames->current();

        if ($frame?->name === null) {
            return;
        }

        $contribution->fillContext([$frame->kind === FrameKind::JOB ? 'job' : 'command' => $frame->name]);
    }
}
