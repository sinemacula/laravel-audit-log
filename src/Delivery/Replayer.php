<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * Replays what a failed write left behind: the signed records in a spill file,
 * and the failed rows of the outbox.
 *
 * A spill line is replayed only when it verifies. A record is never signed,
 * finalised or minimised again, so it reaches the store as it was first signed,
 * with its id, its times and its provenance. A line that was altered, one whose
 * key was removed, one in a version this release does not read, a malformed or
 * truncated one and an unsigned one are each skipped and counted apart, and
 * stay in the file: a removed key means the record cannot be verified, so
 * restore the key or leave it quarantined. A record the store refuses is
 * counted by its id and the class of the failure, never its message, and stops
 * no other line.
 *
 * A spilled bundle, a record with its attachment, is replayed whole: the store
 * keeps its entry and its artifact together, and a bundle it holds already is a
 * no-op. The bound store is asked whether it keeps attachments before it is
 * called; one that keeps none is never handed the bundle, which is counted
 * failed and stays in the file. A failed outbox row holding a bundle is drained
 * as any other, so each destination is asked in turn.
 *
 * An outbox replay resets the receipts of the destinations that do not have a
 * record first, then requeues its row, then drains, so a crash between the two
 * leaves the row failed and a rerun is safe, and a destination that has the
 * record keeps its receipt and is not called again. The drain takes every row
 * due, not only those the replay requeued, and its tally is mapped across.
 *
 * A dry run changes nothing and dispatches nothing: it writes no row, no
 * receipt and no entry, and dispatches no event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Replayer
{
    /** @var int The rows each batch of the drain takes. */
    private const int DRAIN_BATCH = 100;

    /** @var string Where an event of the outbox says it happened. */
    private const string OUTBOX = 'outbox';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Delivery\SpillReader  $reader
     * @param  \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Outbox  $outbox
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Receipts  $receipts
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer  $drainer
     * @param  \SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier  $notifier
     */
    public function __construct(

        /** The container the store and the guard are resolved from on every call. */
        private Container $container,

        /** The reader that takes each envelope from a spill file. */
        private SpillReader $reader,

        /** The codec that verifies and rebuilds each envelope. */
        private EnvelopeCodec $codec,

        /** The outbox whose failed rows are requeued. */
        private Outbox $outbox,

        /** The receipts of the destinations that do not have a record. */
        private Receipts $receipts,

        /** The drainer that delivers the requeued rows. */
        private OutboxDrainer $drainer,

        /** The notifier that dispatches `AuditRecorded` for a replayed record. */
        private RecordedNotifier $notifier,
    ) {}

    /**
     * Replay each line of the spill file that holds a record, or, on a dry run,
     * count what would be replayed and change nothing.
     *
     * @param  string  $path
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     *
     * @throws \InvalidArgumentException
     */
    public function spill(string $path, bool $dryRun): ReplayResult
    {
        $result = new ReplayResult;

        foreach ($this->reader->lines($path) as $line) {
            $this->replayLine($line, $dryRun, $result);
        }

        return $result;
    }

    /**
     * Requeue every failed row of the outbox and drain, or, on a dry run, count
     * and list the failed rows and change nothing.
     *
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function outbox(bool $dryRun): ReplayResult
    {
        $result = new ReplayResult;
        $ids    = $this->outbox->failedIds();

        if ($dryRun) {
            foreach ($ids as $id) {
                $result->addWouldReplay(self::OUTBOX, $id);
            }

            return $result;
        }

        $this->receipts->resetFailed($ids);
        $this->outbox->requeueFailed($ids);

        $result->addDrain($this->drainer->drain(self::DRAIN_BATCH, untilEmpty: true));

        return $result;
    }

    /**
     * Count the line the reader or the codec refused; otherwise count the
     * record it holds on a dry run, and replay it on any other.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\SpillLine  $line
     * @param  bool  $dryRun
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return void
     */
    private function replayLine(#[\SensitiveParameter] SpillLine $line, bool $dryRun, ReplayResult $result): void
    {
        $where = 'line ' . $line->number;

        if ($line->failure !== null) {
            $result->addSkipped($where, $line->failure);

            return;
        }

        try {
            $record = $this->codec->decode((string) $line->json);
        } catch (EnvelopeRejectedException $exception) {
            $result->addSkipped($where, $exception->failure, $exception->id);

            return;
        }

        if ($dryRun) {
            $result->addWouldReplay($where, $record->record->id);

            return;
        }

        $this->store($record, $where, $result);
    }

    /**
     * Give the record to the store inside the write guard and dispatch
     * `AuditRecorded`; a failure, a bundle refused by a store that keeps no
     * attachments included, is counted by the record's id and its class alone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  string  $where
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return void
     */
    private function store(#[\SensitiveParameter] FinalisedRecord $record, string $where, ReplayResult $result): void
    {
        $container = $this->container;

        try {
            $container->make(WriteGuard::class)->during(static function () use ($container, $record): void {
                if ($record->record->attachment !== null) {
                    (new StoreCapabilities($container))->assertAcceptsAttachments();
                }

                $container->make(AuditStore::class)->store($record);
            });
        } catch (\Throwable $exception) {
            $result->addFailed($where, $record->record->id, get_debug_type($exception));

            return;
        }

        $this->notifier->notify($record->record->id, $record->record->event, $record->record->category);

        $result->addReplayed($where, $record->record->id);
    }
}
