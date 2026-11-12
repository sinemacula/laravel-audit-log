<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Http\Request;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;

/**
 * The stack of what the current code runs in, innermost last; the innermost
 * frame decides a record's origin, and console outside any frame.
 *
 * A request replaces the stack and is never popped, so terminating callbacks
 * keep it. Leaving is idempotent, since a failed job fires both `JobFailed` and
 * `JobExceptionOccurred`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExecutionFrames
{
    /** @var list<\SineMacula\Laravel\AuditLog\Runtime\ExecutionFrame> The frames, innermost last. */
    private array $frames = [];

    /**
     * Enter a request, which replaces the whole stack.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function enterRequest(Request $request): void
    {
        $this->frames = [ExecutionFrame::request($request)];
    }

    /**
     * Enter a command, owned by its input.
     *
     * @param  object  $input
     * @param  string  $name
     * @return void
     */
    public function enterCommand(object $input, string $name): void
    {
        $this->frames[] = ExecutionFrame::command($input, $name);
    }

    /**
     * Enter a job, which owns its frame, with the actor it carried and the
     * users left on the guards when it started.
     *
     * @param  object  $job
     * @param  ?string  $name
     * @param  ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot  $carried
     * @param  array<string, object>  $leftovers
     * @return void
     */
    public function enterJob(object $job, ?string $name, ?ActorSnapshot $carried = null, array $leftovers = []): void
    {
        $this->frames[] = ExecutionFrame::job($job, $name, $carried, $leftovers);
    }

    /**
     * Leave the innermost command or job frame the owner holds, with every
     * frame inside it; an owner holding none changes nothing.
     *
     * @param  object  $owner
     * @return void
     */
    public function leave(object $owner): void
    {
        foreach (array_reverse($this->frames, true) as $index => $frame) {
            if ($frame->kind !== FrameKind::HTTP && $frame->owner === $owner) {
                $this->frames = array_slice($this->frames, 0, $index);

                return;
            }
        }
    }

    /**
     * The innermost frame, or `null` outside any frame.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ExecutionFrame
     */
    public function current(): ?ExecutionFrame
    {
        return $this->frames[count($this->frames) - 1] ?? null;
    }

    /**
     * The innermost frame's origin, or console outside any frame.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Enums\Origin
     */
    public function origin(): Origin
    {
        return $this->current()?->kind->origin() ?? Origin::CONSOLE;
    }

    /**
     * The request whose frame is innermost, or `null`, so a command or job
     * inside a request has no client or route.
     *
     * @return ?\Illuminate\Http\Request
     */
    public function request(): ?Request
    {
        return $this->current()->request ?? null;
    }

    /**
     * The request anywhere on the stack, for identity only, so a nested command
     * keeps the request's trusted id; `null` outside any.
     *
     * @return ?\Illuminate\Http\Request
     */
    public function inboundRequest(): ?Request
    {
        foreach ($this->frames as $frame) {
            if ($frame->request !== null) {
                return $frame->request;
            }
        }

        return null;
    }

    /**
     * The actor the innermost job carried, or `null`; a sync job that has ended
     * leaves its own in Context and not here.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     */
    public function carriedActor(): ?ActorSnapshot
    {
        foreach (array_reverse($this->frames) as $frame) {
            if ($frame->kind === FrameKind::JOB) {
                return $frame->carried;
            }
        }

        return null;
    }

    /**
     * Whether the guard has held this very user since before a job on the stack
     * started, making it an earlier job's.
     *
     * @param  string  $guard
     * @param  object  $user
     * @return bool
     */
    public function isLeftover(string $guard, object $user): bool
    {
        foreach ($this->frames as $frame) {
            if (($frame->leftovers[$guard] ?? null) === $user) {
                return true;
            }
        }

        return false;
    }
}
