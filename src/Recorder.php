<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Support\MachineCode;

/**
 * The package's way in: records an activity, or gives a builder that records
 * one, and takes the definitions and contributors an application registers
 * while it boots.
 *
 * A recorded activity runs one pipeline: its definition is found, its timing is
 * checked, the contributors fill its gaps in order, what they leave is
 * minimised, the record is built from that with the clock's time and the
 * configured source, and it is delivered, after commit unless the builder chose
 * otherwise. A refusal before the record is built, a minimiser's failure among
 * them, stores nothing and leaves the builder usable, and a failed write
 * propagates.
 *
 * A singleton that outlives requests under Octane, so it holds only frozen
 * registration data: contributors, runtime state, the clock, the store and the
 * finaliser are all resolved from the current container on every capture.
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
     * The pipeline a builder's `record()` runs: nothing is consumed until the
     * definition and the timing have been accepted and the record minimised, so
     * a refusal of any of them leaves the builder usable. Minimising takes a
     * snapshot of its own, because the first predates what the contributors
     * filled; that first one stays for the definition, the timing and the
     * connection, which they cannot change.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function write(#[\SensitiveParameter] PendingRecord $pending): AuditRecord
    {
        $container = Container::getInstance();
        $snapshot  = $pending->snapshot();

        assert($snapshot->code instanceof EventCode);

        $definition = $this->catalogue->definitionFor($snapshot->code, $container->make(DefinitionSettings::class)->requiresRegistered());
        $delivery   = $container->make(RecordDelivery::class);
        $timing     = $snapshot->timing ?? Timing::AFTER_COMMIT;

        $delivery->check($timing, $snapshot->connection);

        $contribution = new Contribution($pending);

        foreach ($this->contributors->classes() as $contributor) {
            $container->make($contributor)->contribute($contribution);
        }

        $minimised  = $container->make(RecordMinimiser::class)->minimise($pending->snapshot(), $definition);
        $source     = $container->make(SourceSettings::class);
        $occurredAt = $container->make(Clock::class)->now();
        $record     = AuditRecord::fromPending($pending, $minimised, $definition->version, $definition->category, $occurredAt, $source->id(), $source->region());

        $delivery->deliver($record, $timing, $snapshot->connection);

        return $record;
    }
}
