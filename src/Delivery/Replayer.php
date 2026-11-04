<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
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
 * A pruned record is never resurrected: a line that verifies is checked against
 * the tombstones first, and a record retention has already pruned is counted
 * pruned and never handed to the store, on a dry run too, and the line stays in
 * the file. A failure reading the tombstones is counted as the line's failure.
 * Outside a dry run the check and the store run in one lifecycle transaction,
 * behind the lifecycle lock every prune takes first, so no prune can delete the
 * record between its check and its insert and the insert never brings back an
 * entry pruned a moment before; the installation is confirmed once, before the
 * first line. The outbox replay drains, and the drain checks every row it reads
 * the same way.
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
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones  $tombstones
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

        /** The tombstones that say whether retention has already pruned a record. */
        private PruneTombstones $tombstones,
    ) {}

    /**
     * Replay each line of the spill file that holds a record, or, on a dry run,
     * count what would be replayed and change nothing.
     *
     * @param  string  $path
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \InvalidArgumentException
     */
    public function spill(string $path, bool $dryRun): ReplayResult
    {
        $result = new ReplayResult;

        if (!$dryRun) {
            $this->container->make(MaintenanceTransaction::class)->confirm();
        }

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
     * Count the line the reader or the codec refused, and otherwise replay the
     * record it holds.
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

        $this->replayRecord($record, $where, $dryRun, $result);
    }

    /**
     * Count the record retention has already pruned; otherwise count it on a
     * dry run, and give it to the store on any other, the check made again
     * behind the lifecycle lock.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  string  $where
     * @param  bool  $dryRun
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return void
     */
    private function replayRecord(#[\SensitiveParameter] FinalisedRecord $record, string $where, bool $dryRun, ReplayResult $result): void
    {
        if (!$dryRun) {
            $this->store($record, $where, $result);

            return;
        }

        if ($this->stopsAtTheTombstones($record, $where, $result)) {
            return;
        }

        $result->addWouldReplay($where, $record->record->id);
    }

    /**
     * Whether the record goes no further than the tombstones: retention has
     * already pruned it, and it is counted pruned, or the tombstones could not
     * be read, and it is counted failed by its id and the class of the failure
     * alone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  string  $where
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return bool
     */
    private function stopsAtTheTombstones(#[\SensitiveParameter] FinalisedRecord $record, string $where, ReplayResult $result): bool
    {
        $id = $record->record->id;

        try {
            $pruned = $this->tombstones->isPruned($id);
        } catch (\Throwable $exception) {
            $result->addFailed($where, $id, get_debug_type($exception));

            return true;
        }

        if ($pruned) {
            $result->addPruned($where, $id);
        }

        return $pruned;
    }

    /**
     * In one lifecycle transaction, behind the lock, check the record against
     * the tombstones and, unless retention has pruned it, give it to the store
     * inside the write guard; then count it pruned, or dispatch `AuditRecorded`
     * and count it replayed. A failure, of the tombstones' read or of the
     * store, a bundle refused by a store that keeps no attachments included, is
     * counted by the record's id and its class alone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  string  $where
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return void
     */
    private function store(#[\SensitiveParameter] FinalisedRecord $record, string $where, ReplayResult $result): void
    {
        $container  = $this->container;
        $tombstones = $this->tombstones;
        $id         = $record->record->id;

        $unlessPruned = static function () use ($container, $tombstones, $record): bool {
            if ($tombstones->isPruned($record->record->id)) {
                return false;
            }

            $container->make(WriteGuard::class)->during(static fn () => self::storeIn($container, $record));

            return true;
        };

        try {
            $stored = $container->make(MaintenanceTransaction::class)->run(Str::uuid7()->toString(), $unlessPruned);
        } catch (\Throwable $exception) {
            $result->addFailed($where, $id, get_debug_type($exception));

            return;
        }

        if (!$stored) {
            $result->addPruned($where, $id);

            return;
        }

        $this->notifier->notify($id, $record->record->event, $record->record->category);

        $result->addReplayed($where, $id);
    }

    /**
     * Give the record to the bound store, once a bundle's store is known to
     * keep attachments.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function storeIn(Container $container, #[\SensitiveParameter] FinalisedRecord $record): void
    {
        if ($record->record->attachment !== null) {
            (new StoreCapabilities($container))->assertAcceptsAttachments();
        }

        $container->make(AuditStore::class)->store($record);
    }
}
