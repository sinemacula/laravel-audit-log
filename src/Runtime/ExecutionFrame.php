<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Http\Request;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;

/**
 * One level of what the current code runs in, matched to its end by its owner's
 * identity; holding the owner keeps that identity from being reused.
 *
 * A job's frame keeps the actor it carried and the users the guards held at its
 * start, since a sync job overwrites Context and Laravel's guards outlive a
 * job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExecutionFrame
{
    /** @var ?string The command or job's name; `null` when it has none. */
    public ?string $name;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind  $kind
     * @param  object  $owner
     * @param  ?string  $name
     * @param  ?\Illuminate\Http\Request  $request
     * @param  ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot  $carried
     * @param  array<string, object>  $leftovers
     */
    private function __construct(

        /** What the frame stands for. */
        public FrameKind $kind,

        /** The object that owns the frame, matched by identity when it ends. */
        public object $owner,

        // Not promoted: an empty name is kept as none.
        ?string $name = null,

        /** The request a frame of a request stands for. */
        public ?Request $request = null,

        /** The actor the job carried from whoever dispatched it, if any. */
        public ?ActorSnapshot $carried = null,

        /** The users the guards held, by guard, when a job on a worker started: none of them is this job's. */
        public array $leftovers = [],
    ) {
        $this->name = $name === '' ? null : $name;
    }

    /**
     * The frame of an HTTP request, which owns itself.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function request(Request $request): self
    {
        return new self(FrameKind::HTTP, $request, request: $request);
    }

    /**
     * The frame of an Artisan command, owned by its input, which its start and
     * finish events share.
     *
     * @param  object  $input
     * @param  string  $name
     * @return self
     */
    public static function command(object $input, string $name): self
    {
        return new self(FrameKind::COMMAND, $input, $name);
    }

    /**
     * The frame of a queued job, owned by the job, with the actor it carried
     * and the users left on the guards when it started.
     *
     * @param  object  $job
     * @param  ?string  $name
     * @param  ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot  $carried
     * @param  array<string, object>  $leftovers
     * @return self
     */
    public static function job(object $job, ?string $name, ?ActorSnapshot $carried = null, array $leftovers = []): self
    {
        return new self(FrameKind::JOB, $job, $name, carried: $carried, leftovers: $leftovers);
    }
}
