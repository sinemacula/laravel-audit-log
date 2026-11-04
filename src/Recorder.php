<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\MachineCode;

/**
 * The package's way in: records an activity, or gives a builder that records
 * one, captures an event through its mapper, and takes the definitions,
 * contributors, event mappers and watched models an application registers while
 * it boots.
 *
 * A recorded activity runs one pipeline: its definition is found, its timing is
 * checked, the contributors fill its gaps in order, what they leave is
 * minimised, a bulk operation's manifest is sealed, the record is built from
 * that with the clock's time and the configured source, and it is delivered,
 * after commit unless the builder chose otherwise. A refusal before the record
 * is built, a minimiser's failure among them, stores nothing and leaves the
 * builder usable, and a failed write follows the failure policy. The pipeline
 * runs with the definitions and contributors this recorder was made with.
 *
 * An event is captured through the mapper registered for its class, or for the
 * one parent class or interface of it that is mapped: the first mapping
 * listens, through one wildcard listener, for every event the application
 * dispatches, and an application that maps nothing pays nothing. A captured
 * record is written at once, and a capture never throws into the code that
 * dispatched its event but for a failure fatal to an open transaction. A
 * watched model's changes are captured from its own Eloquent events, and a bulk
 * operation is one explicit record carrying the manifest of what it affected,
 * refused up front while the bound store keeps no attachment.
 *
 * The recorder is also the way into the read path: `trail()` gives a fresh
 * trail, resolved from the current container on each call, which reads nothing
 * until a viewer is named and a terminal call made, and which every read
 * authorises through the bound access policy and records before anything it
 * found is returned. `lifecycle()` likewise gives a fresh way into the log's
 * lifecycle, its holds, prunes, imports, erasures, reinstatements and rewraps,
 * on each call.
 *
 * A singleton that outlives requests under Octane, so it holds only frozen
 * registration data, its definitions and contributors. The event mappers and
 * the model watcher, which every capture reads from the container, are resolved
 * from it for each registration, so the recorder never holds the dispatcher a
 * watch listens with, nor anything that holds a request; both are frozen once
 * the application has booted. Runtime state, the clock, the store, the
 * finaliser and the capture's own state are all resolved from the current
 * container on every capture.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Recorder
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue  $catalogue
     * @param  \SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry  $contributors
     */
    public function __construct(

        /** The definitions registered while the application booted. */
        private EventCatalogue $catalogue,

        /** The contributors registered while the application booted, by class name. */
        private ContributorRegistry $contributors,
    ) {}

    /**
     * Record an activity in one call, written after commit, and return the
     * captured record. A reason goes with a failure or a denial, and is refused
     * with a success.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \BackedEnum|string  $code
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $subject
     * @param  array<array-key, mixed>  $properties
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  \BackedEnum|string|null  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     */
    public function record(
        \BackedEnum|string $code,
        Model|Reference|null $subject = null,
        #[\SensitiveParameter]
        array $properties = [],
        Outcome $outcome = Outcome::SUCCESS,
        \BackedEnum|string|null $reason = null,
    ): AuditRecord {
        if ($reason !== null && $outcome === Outcome::SUCCESS) {
            throw new \InvalidArgumentException('A reason goes with a failure or a denial, not a success.');
        }

        $pending = $this->event($code);

        if ($subject !== null) {
            $pending->on($subject);
        }

        if ($properties !== []) {
            $pending->withProperties($properties);
        }

        $ended = match ($outcome) {
            Outcome::SUCCESS => $pending,
            Outcome::FAILURE => $pending->failed($reason),
            Outcome::DENIED  => $pending->denied($reason),
        };

        return $ended->record();
    }

    /**
     * A builder for an activity, which writes nothing until its `record()`.
     *
     * @param  \BackedEnum|string  $code
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function event(\BackedEnum|string $code): PendingRecord
    {
        return (new PendingRecord($this->write(...)))->event($code);
    }

    /**
     * A builder for a completed disclosure, which writes nothing until its
     * `record()`: the outcome is a success, the purpose goes in the properties
     * and the channel in the context, both as machine-readable codes. A
     * registered definition of the code must retain `purpose`, and an attempt
     * that was denied or failed has a code of its own, through `event()`.
     *
     * @param  \BackedEnum|string  $code
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  \BackedEnum|string  $purpose
     * @param  \BackedEnum|string  $channel
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function accessed(\BackedEnum|string $code, Model|Reference $subject, \BackedEnum|string $purpose, \BackedEnum|string $channel): PendingRecord
    {
        $pending = $this->event($code)->on($subject);

        $this->refuseUnretainedPurpose(EventCode::of($code));

        $pending->withProperties(['purpose' => MachineCode::of($purpose, 'A purpose')]);
        $pending->fillContext(['channel' => MachineCode::of($channel, 'A channel')]);

        return $pending->succeeded();
    }

    /**
     * Register a definition, or every case of an enum implementing
     * `DefinesAuditEvents`, given by its class name, while the application
     * boots.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition|string  $definition
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function define(EventDefinition|string $definition): void
    {
        $this->catalogue->define($definition);
    }

    /**
     * Register a contributor by its class name, while the application boots.
     * Contributors run after the package's defaults, in the order they are
     * registered.
     *
     * @param  string  $contributor
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function contribute(string $contributor): void
    {
        $this->contributors->add($contributor);
    }

    /**
     * Register the mapper for an event class or interface, while the
     * application boots, leaving the subtypes excepted unmapped. The first
     * mapping listens for every event the application dispatches, once.
     *
     * @param  string  $classOrInterface
     * @param  string  $mapper
     * @param  list<string>  $except
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function map(string $classOrInterface, string $mapper, array $except = []): void
    {
        $container = Container::getInstance();
        $mappers   = $container->make(MapperRegistry::class);
        $first     = !$mappers->hasMappings();

        $mappers->map($classOrInterface, $mapper, $except);

        if (!$first) {
            return;
        }

        $container->make(Dispatcher::class)->listen('*', CaptureMappedEvent::class);
    }

    /**
     * Capture the event through the mapper registered for it, and return the
     * record written, or `null` when nothing was: no mapping applies, the event
     * has been captured already or is being mapped now, its mapper skipped it,
     * or the capture failed, which is reported and dispatched as
     * `AuditCaptureFailed`. Nothing is thrown but a failure fatal to an open
     * transaction.
     *
     * @param  object  $event
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function capture(#[\SensitiveParameter] object $event): ?AuditRecord
    {
        return Container::getInstance()->make(CaptureCoordinator::class)->mapped($event);
    }

    /**
     * Watch exactly the model class under the segment, while the application
     * boots, keeping the fields: a name given alone is retained, and a name
     * given as a key is handled as its value says.
     *
     * @param  string  $model
     * @param  string  $as
     * @param  array<int|string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling|string>  $fields
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function watch(string $model, string $as, array $fields): void
    {
        Container::getInstance()->make(ModelWatcher::class)->watch($model, $as, $fields);
    }

    /**
     * A builder for a bulk operation on the subjects, which writes nothing
     * until its `record()` and is written after commit by default, like any
     * explicit record. It carries the manifest of the subjects, each once,
     * which is sealed when it is recorded; a manifest over its configured
     * bounds is refused, never truncated, and so is any bulk operation while
     * the bound store keeps no attachment.
     *
     * @param  \BackedEnum|string  $code
     * @param  iterable<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    public function bulk(\BackedEnum|string $code, #[\SensitiveParameter] iterable $subjects): PendingRecord
    {
        $container = Container::getInstance();

        $container->make(StoreCapabilities::class)->assertAcceptsAttachments();

        $settings = $container->make(CaptureSettings::class);
        $manifest = Manifest::of($subjects, $settings->bulkMaxMembers(), $settings->bulkMaxBytes());

        return $this->event($code)->withManifest($manifest);
    }

    /**
     * A fresh trail of every entry, resolved from the current container, with
     * no filter and no viewer: nothing is read until `visibleTo()` names the
     * viewer and a terminal call reads for them.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function trail(): AuditTrail
    {
        return Container::getInstance()->make(AuditTrail::class);
    }

    /**
     * A fresh way into the log's lifecycle, resolved from the current
     * container: holds, prunes, imports, erasures, reinstatements, rewraps and
     * their reconciliation, each a privileged operation the caller must have
     * authorised, since the package authorises none of them.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lifecycle(): AuditLifecycle
    {
        return Container::getInstance()->make(AuditLifecycle::class);
    }

    /**
     * Refuse a disclosure code whose registered definition would not keep the
     * purpose.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseUnretainedPurpose(EventCode $code): void
    {
        if (!$this->catalogue->isRegistered($code) || $this->catalogue->definitionFor($code)->handlingFor(['purpose']) === FieldHandling::RETAIN) {
            return;
        }

        throw new \LogicException(sprintf('The disclosure code `%s` must retain `purpose` in its definition.', $code->value));
    }

    /**
     * Write the builder's record through the pipeline of the definitions and
     * contributors this recorder was made with, never one the container holds,
     * so a recorder made with its own keeps them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function write(#[\SensitiveParameter] PendingRecord $pending): AuditRecord
    {
        return (new RecordPipeline($this->catalogue, $this->contributors))->write($pending);
    }
}
