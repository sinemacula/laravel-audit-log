<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;

/**
 * What an import, or the close of a batch, did: the operation, whether it
 * committed anything and whether its activity record was written, the batch and
 * the status it reached, the hold placed with its start, and its counts.
 *
 * A dry run commits nothing and names no batch, status or hold: its counts are
 * a plan of what an import would do, never a promise, since another import may
 * store the same records first. Lines past retention on arrival are counted so
 * an operator can see what the next prune would delete unless it is held; the
 * count is `null` when the retention policy failed to answer, which never stops
 * the import. The counts are of lines; nothing of a line's content is carried.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, int>|bool|int|list<string>|string|null>
 */
final readonly class ImportResult implements Arrayable
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $operationId
     * @param  bool  $committed
     * @param  bool  $recorded
     * @param  bool  $dryRun
     * @param  ?string  $batchId
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  ?string  $holdId
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @param  int  $linesRead
     * @param  int  $imported
     * @param  int  $duplicates
     * @param  int  $conflicts
     * @param  int  $rejected
     * @param  array<string, int>  $rejections
     * @param  list<string>  $conflictIds
     * @param  ?int  $pastRetention
     * @param  int  $dropped
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The operation's id. */
        public string $operationId,

        /** Whether the operation committed anything: never for a dry run. */
        public bool $committed,

        /** Whether its activity record was written. */
        public bool $recorded,

        /** Whether it was a dry run. */
        public bool $dryRun,

        /** The batch, or `null` for a dry run. */
        public ?string $batchId,

        /** The status the batch reached, or `null` for a dry run. */
        public ?ImportStatus $status,

        /** The id of the hold placed with the batch's start, or `null` when none was asked for. */
        public ?string $holdId,

        /** The hold placed with this import's start, or `null` when it placed none. */
        public ?Hold $hold,

        /** The lines read, blank lines aside. */
        public int $linesRead,

        /** The lines imported as new rows, or that a dry run would import. */
        public int $imported,

        /** The lines that repeat a record imported already. */
        public int $duplicates,

        /** The lines that conflict with a record imported already. */
        public int $conflicts,

        /** The lines rejected. */
        public int $rejected,

        /** How many lines were rejected for each reason, by its value. */
        public array $rejections,

        /** The first hundred conflicting source record ids, in file order. */
        public array $conflictIds,

        /** The lines whose records were already past their retention when they arrived, or `null` when the policy failed to answer. */
        public ?int $pastRetention,

        /** The envelope-shaped values and descriptors removed from the lines. */
        public int $dropped,
    ) {}

    /**
     * The result of an operation from its tally: committed unless it was a dry
     * run, its record not yet written.
     *
     * @param  string  $operationId
     * @param  bool  $dryRun
     * @param  ?string  $batchId
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return self
     *
     * @internal
     */
    public static function of(string $operationId, bool $dryRun, ?string $batchId, ?ImportStatus $status, ?Hold $hold, ImportTally $tally): self
    {
        return new self(
            operationId: $operationId,
            committed: !$dryRun,
            recorded: false,
            dryRun: $dryRun,
            batchId: $batchId,
            status: $status,
            holdId: $hold?->id,
            hold: $hold,
            linesRead: $tally->linesRead(),
            imported: $tally->imported(),
            duplicates: $tally->duplicates(),
            conflicts: $tally->conflicts(),
            rejected: $tally->rejected(),
            rejections: $tally->rejections(),
            conflictIds: $tally->conflictIds(),
            pastRetention: $tally->pastRetention(),
            dropped: $tally->dropped(),
        );
    }

    /**
     * The result with whether its activity record was written.
     *
     * @param  bool  $recorded
     * @return self
     *
     * @internal
     */
    public function withRecorded(bool $recorded): self
    {
        return new self(
            $this->operationId,
            $this->committed,
            $recorded,
            $this->dryRun,
            $this->batchId,
            $this->status,
            $this->holdId,
            $this->hold,
            $this->linesRead,
            $this->imported,
            $this->duplicates,
            $this->conflicts,
            $this->rejected,
            $this->rejections,
            $this->conflictIds,
            $this->pastRetention,
            $this->dropped,
        );
    }

    /**
     * The result as a map: the operation, whether it committed, was recorded
     * and was a dry run, the batch, its status and hold, and the counts.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{operation_id: string, committed: bool, recorded: bool, dry_run: bool, batch_id: ?string, status: ?string, hold_id: ?string, lines_read: int, imported: int, duplicates: int, conflicts: int, rejected: int, rejections: array<string, int>, conflict_ids: list<string>, past_retention: ?int, dropped: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'   => $this->operationId,
            'committed'      => $this->committed,
            'recorded'       => $this->recorded,
            'dry_run'        => $this->dryRun,
            'batch_id'       => $this->batchId,
            'status'         => $this->status?->value,
            'hold_id'        => $this->holdId,
            'lines_read'     => $this->linesRead,
            'imported'       => $this->imported,
            'duplicates'     => $this->duplicates,
            'conflicts'      => $this->conflicts,
            'rejected'       => $this->rejected,
            'rejections'     => $this->rejections,
            'conflict_ids'   => $this->conflictIds,
            'past_retention' => $this->pastRetention,
            'dropped'        => $this->dropped,
        ];
    }
}
