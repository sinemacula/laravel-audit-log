<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;

/**
 * Routes every object event the application dispatches to the capture of mapped
 * events, so an event reaches the mapping of its own class or of a parent class
 * or interface through one wildcard listener.
 *
 * Only an object event, whose one payload entry is an object of the class the
 * event is named after, is captured; a string event and any other payload are
 * left alone at once. The capture contains its own failures, so the code that
 * dispatched the event and the listeners after this one go on.
 *
 * It holds nothing: the capture comes from the application serving the event
 * when it is handled, not from the container that built the listener, which
 * under Octane is the application the worker booted rather than the request's
 * sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CaptureMappedEvent
{
    /**
     * Handle any dispatched event, by its name and payload.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $event
     * @param  array<array-key, mixed>  $payload
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function handle(string $event, #[\SensitiveParameter] array $payload): void
    {
        if (count($payload) !== 1) {
            return;
        }

        $object = reset($payload);

        if (!is_object($object) || $object::class !== $event) {
            return;
        }

        Container::getInstance()->make(CaptureCoordinator::class)->mapped($object);
    }
}
