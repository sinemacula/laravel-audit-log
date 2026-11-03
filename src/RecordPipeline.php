<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Container\Container;
use Illuminate\Contracts\Encryption\StringEncrypter;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;

/**
 * The pipeline a recorded activity runs, whether the application records it or
 * it is captured from an event: its definition is found, its timing is checked,
 * the contributors fill its gaps in order, what they leave is minimised, a bulk
 * operation's manifest is sealed, the record is built from that with the
 * clock's time and the configured source, and it is delivered.
 *
 * Nothing is consumed until the definition and the timing have been accepted,
 * the record minimised and any manifest sealed, so a refusal of any of them, a
 * minimiser's or an encrypter's failure among them, stores nothing and leaves
 * the builder usable, and a failed write follows the failure policy.
 *
 * A record captured from an event comes with its capture's signal: without a
 * timing of its own it is written immediately rather than after commit, it is
 * never fail-closed or transactional, and its failure is signalled rather than
 * thrown, without the failure mode being read. Nothing is recorded explicitly
 * while an event mapper runs: a mapper returns its builder and the capture
 * writes it. A capture of another event the mapper sets off, which comes with
 * its own signal, is written as any capture is, so a watched model it saves or
 * a Gate check it denies is never lost.
 *
 * It writes with the definitions and contributors it was made with, and
 * resolves everything else from the current container on every write, so it
 * holds only frozen registration data and outlives requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordPipeline
{
    /** @var string Why an explicit write is refused while an event mapper runs. */
    private const string WRITE_WHILE_MAPPING = 'A record is never written while an event mapper runs; the mapper returns its builder and the capture writes it.';

    /** @var string Why a builder with no code is refused. */
    private const string NO_CODE = 'A pending record needs an event code before it is recorded; set one with `event()`.';

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
     * Write the builder's record and return it. Minimising takes a snapshot
     * of its own, because the first predates what the contributors filled;
     * that first one stays for the definition, the timing, the connection and
     * the manifest, which they cannot change. An explicit record without a
     * timing is written after commit, and a captured one immediately. An
     * explicit record is refused while an event mapper runs; a captured one,
     * which its signal tells apart, is not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
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
    public function write(#[\SensitiveParameter] PendingRecord $pending, #[\SensitiveParameter] ?CaptureSignal $capture = null): AuditRecord
    {
        $container = Container::getInstance();

        if ($capture === null && $container->make(CapturedEvents::class)->isMapping()) {
            self::refuse(self::WRITE_WHILE_MAPPING);
        }

        $snapshot = $pending->snapshot();

        if ($snapshot->code === null) {
            self::refuse(self::NO_CODE);
        }

        $definition = $this->catalogue->definitionFor($snapshot->code, $container->make(DefinitionSettings::class)->requiresRegistered());
        $delivery   = $container->make(RecordDelivery::class);
        $timing     = $snapshot->timing ?? ($capture === null ? Timing::AFTER_COMMIT : Timing::IMMEDIATE);

        $delivery->check($timing, $snapshot->connection, $snapshot->failClosed, $capture);

        $contribution = new Contribution($pending);

        foreach ($this->contributors->classes() as $contributor) {
            $container->make($contributor)->contribute($contribution);
        }

        $minimised  = $container->make(RecordMinimiser::class)->minimise($pending->snapshot(), $definition);
        $attachment = $snapshot->manifest === null ? null : Attachment::sealed($snapshot->manifest, $container->make(StringEncrypter::class));
        $source     = $container->make(SourceSettings::class);
        $occurredAt = $container->make(Clock::class)->now();
        $record     = AuditRecord::fromPending($pending, $minimised, $definition->version, $definition->category, $occurredAt, $source->id(), $source->region(), $attachment);

        $delivery->deliver($record, $timing, $snapshot->connection, $snapshot->failClosed, $capture);

        return $record;
    }

    /**
     * Refuse the write, before anything is consumed.
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
