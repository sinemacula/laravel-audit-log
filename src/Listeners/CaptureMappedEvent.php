<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;

/**
 * Routes every object event to the capture of mapped events through one
 * wildcard listener, so a parent class or interface mapping matches too.
 *
 * Resolves the capture per event, since under Octane the container that built
 * the listener is the worker's, not the request's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CaptureMappedEvent
{
    /**
     * Capture the event when its one payload entry is an object of the class it
     * is named after.
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
