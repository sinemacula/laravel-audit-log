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
 * Records a watched model's change from the Eloquent event that announced it: a
 * creation, an update (or the restore it is), a deletion or a force deletion.
 *
 * Only a model whose exact class is watched is captured; any other, a subclass
 * of a watched class included, is left alone at once. Each event is captured on
 * its own, so two saves are two records, each described when its event fires
 * and delivered once the model's connection commits. The capture contains its
 * own failures, naming the model's class and this listener, so the change
 * itself goes on.
 *
 * It holds nothing: the watches and the capture come from the application
 * serving the change when it is handled, not from the container that built the
 * listener, which under Octane is the application the worker booted rather than
 * the request's sandbox.
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
     * Record the update of the model, or the restore it is, when its class is
     * watched.
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
     * Capture the change of the model through the watch of its exact class, or
     * do nothing when its class is not watched.
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
