<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * The model classes watched at boot, each exactly, and the listeners recording
 * their changes. A watch is checked whole before anything is registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ModelWatcher
{
    /** @var array<class-string<\Illuminate\Database\Eloquent\Model>, \SineMacula\Laravel\AuditLog\Capture\ModelWatch> Each watch by the exact class it is of. */
    private array $watches = [];

    /** @var bool Whether the application has booted, after which nothing more is watched. */
    private bool $frozen = false;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue  $catalogue
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(

        /** The catalogue the definitions of the changes are registered in. */
        private readonly EventCatalogue $catalogue,

        /** The dispatcher the listeners are registered with. */
        private readonly Dispatcher $events,
    ) {}

    /**
     * Watch the model class under the segment; a field given alone is retained,
     * and one given as a key is handled as its value says.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $class
     * @param  string  $as
     * @param  array<array-key, mixed>  $fields
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function watch(string $class, string $as, array $fields): void
    {
        if ($this->frozen) {
            self::refuse('Models are watched while the application boots, and it has already booted.');
        }

        $watch    = ModelWatch::of($class, $as, $fields);
        $existing = $this->watches[$watch->class] ?? null;

        if ($existing !== null && $existing->equals($watch)) {
            return;
        }

        if ($existing !== null) {
            self::refuse(sprintf('`%s` is already watched differently; a model has one watch.', $watch->class));
        }

        $this->refuseTakenSegment($watch);

        $definitions = $watch->definitions();

        foreach ($definitions as $definition) {
            $this->refuseConflicting($definition);
        }

        foreach ($definitions as $definition) {
            $this->catalogue->define($definition);
        }

        $this->watches[$watch->class] = $watch;

        $this->listenFor($watch->class);
    }

    /**
     * The watch of exactly the class, or `null`; a parent's never applies.
     *
     * @param  string  $class
     * @return ?\SineMacula\Laravel\AuditLog\Capture\ModelWatch
     */
    public function watchFor(string $class): ?ModelWatch
    {
        return $this->watches[$class] ?? null;
    }

    /**
     * Refuse any further watch; freezing again changes nothing.
     *
     * @return void
     */
    public function freeze(): void
    {
        $this->frozen = true;
    }

    /**
     * Whether the watcher refuses any further watch.
     *
     * @return bool
     */
    public function isFrozen(): bool
    {
        return $this->frozen;
    }

    /**
     * Refuse a watch under a segment another class's changes are stored under.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseTakenSegment(ModelWatch $watch): void
    {
        foreach ($this->watches as $class => $existing) {
            if ($existing->as !== $watch->as) {
                continue;
            }

            self::refuse(sprintf('The segment `%s` already names the changes of `%s`; each watched model has its own.', $watch->as, $class));
        }
    }

    /**
     * Refuse a definition for a code the catalogue holds a different one for.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function refuseConflicting(EventDefinition $definition): void
    {
        $code = EventCode::of($definition->code);

        if (!$this->catalogue->isRegistered($code) || $this->catalogue->definitionFor($code)->equals($definition)) {
            return;
        }

        self::refuse(sprintf('The event code `%s` is already defined differently; a code has one definition.', $definition->code));
    }

    /**
     * Listen for each Eloquent event of exactly the class.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @return void
     */
    private function listenFor(string $class): void
    {
        foreach (ModelEvent::cases() as $change) {
            $name = $change->eloquentEvent();

            if ($name === null) {
                continue;
            }

            $this->events->listen('eloquent.' . $name . ': ' . $class, [RecordModelChange::class, $name]);
        }
    }

    /**
     * Refuse the watch.
     *
     * @param  string  $message
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuse(string $message): never
    {
        throw new \LogicException($message);
    }
}
