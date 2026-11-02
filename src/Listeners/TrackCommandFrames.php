<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Enters an execution frame when an Artisan command starts and leaves it when
 * the command finishes, which it does when the command throws too.
 *
 * The frame is owned by the command's input, the one object both events share.
 * The frames are reached through the current container on every event, since a
 * dispatcher built with the booted application outlives the request a command
 * runs in under Octane. Only the package's own state changes: neither Context
 * nor the guards are touched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrackCommandFrames
{
    /**
     * Handle the `CommandStarting` and `CommandFinished` events.
     *
     * @param  \Illuminate\Console\Events\CommandFinished|\Illuminate\Console\Events\CommandStarting  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(CommandFinished|CommandStarting $event): void
    {
        $frames = Container::getInstance()->make(ExecutionFrames::class);

        if ($event instanceof CommandStarting) {
            $frames->enterCommand($event->input, $event->command);

            return;
        }

        $frames->leave($event->input);
    }
}
