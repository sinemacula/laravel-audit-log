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
 * A record is never re-signed, and a pruned record never resurrected: each is
 * checked against the tombstones behind the lifecycle lock, in the transaction
 * that stores it.
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

        /** Resolves the store and the guard on every call. */
        private Container $container,

        /** Takes each envelope from a spill file. */
        private SpillReader $reader,

        /** Verifies and rebuilds each envelope. */
        private EnvelopeCodec $codec,

        /** The outbox whose failed rows are requeued. */
        private Outbox $outbox,

        /** The receipts reset for a replay. */
        private Receipts $receipts,

        /** Delivers the requeued rows. */
        private OutboxDrainer $drainer,

        /** Dispatches `AuditRecorded` for a replayed record. */
        private RecordedNotifier $notifier,

        /** Say whether retention has already pruned a record. */
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
     * Reset undelivered receipts, requeue every failed row, then drain, so a
     * crash in between leaves the row failed and a rerun safe; a dry run only
     * lists the failed rows.
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
     * On a dry run, count the record pruned or would-replay; otherwise store
     * it, which checks the tombstones behind the lifecycle lock.
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
     * Whether the record stops at the tombstones: counted pruned, or failed
     * when they could not be read.
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
     * Check the tombstones and store the record in one lifecycle transaction
     * behind the lock, then count it pruned, or dispatch `AuditRecorded` and
     * count it replayed; a failure counts by id and class alone.
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
     * Give the record to the bound store, refusing a bundle a store without
     * attachments would lose.
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
