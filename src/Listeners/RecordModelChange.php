<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Capture\ModelChangeDescriber;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Records a watched model's change from the Eloquent event that announced it,
 * for the exact watched class only, never a subclass.
 *
 * Resolves everything per event, since under Octane the container that built
 * the listener is the worker's, not the request's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordModelChange
{
    /**
     * Record the creation of the model, when its class is watched.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function created(#[\SensitiveParameter] Model $model): void
    {
        $this->capture(ModelEvent::CREATED, $model);
    }

    /**
     * Record the update, or the restore it is, when the class is watched.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function updated(#[\SensitiveParameter] Model $model): void
    {
        $this->capture(ModelEvent::UPDATED, $model);
    }

    /**
     * Record the deletion of the model, when its class is watched and it is not
     * being deleted for good.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function deleted(#[\SensitiveParameter] Model $model): void
    {
        $this->capture(ModelEvent::DELETED, $model);
    }

    /**
     * Record the force deletion of the model, when its class is watched.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function forceDeleted(#[\SensitiveParameter] Model $model): void
    {
        $this->capture(ModelEvent::FORCE_DELETED, $model);
    }

    /**
     * Capture the change through the watch of the model's exact class, if any.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $change
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    private function capture(ModelEvent $change, #[\SensitiveParameter] Model $model): void
    {
        $container = Container::getInstance();
        $watch     = $container->make(ModelWatcher::class)->watchFor($model::class);

        if ($watch === null) {
            return;
        }

        $describe = static fn (#[\SensitiveParameter] PendingRecord $record): ?PendingRecord => ModelChangeDescriber::describe($watch, $change, $model, $record);

        $container->make(CaptureCoordinator::class)->captured($model, self::class, $describe, once: false, mayDefer: true);
    }
}
