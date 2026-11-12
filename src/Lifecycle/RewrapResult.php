<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;

/**
 * What a rewrap did, or for a dry run would do; each batch commits alone, so a
 * failed run's batches stand.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int|list<string>|string>
 */
final readonly class RewrapResult implements Arrayable
{
    /** @var int The most skipped keys named by id. */
    public const int MAX_SKIPPED_IDS = 100;

    /** @var bool Whether the run committed: `false` for a dry run, and always otherwise once a result is returned. */
    public bool $committed;

    /** @var \SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus How the run ended: `partial` when it skipped a key. */
    public RewrapStatus $status;

    /** @var list<string> The ids of the keys the run skipped, at most 100, sorted bytewise. */
    public array $skippedKeyIds;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  bool  $dryRun
     * @param  bool  $rotate
     * @param  string  $wrapKeyId
     * @param  int  $rewrapped
     * @param  int  $rotated
     * @param  int  $skipped
     * @param  list<string>  $skippedKeyIds
     * @param  int  $batches
     * @param  bool  $recorded
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The run's id, which every journal row of the run names. */
        public string $operationId,

        /** Whether the run was a dry run, which writes nothing. */
        public bool $dryRun,

        /** Whether the run superseded every live key, so the next write of each unit opens a generation. */
        public bool $rotate,

        /** The id of the wrapping key the run rewrapped onto: the wrapper's current key at its start. */
        public string $wrapKeyId,

        /** How many keys the run rewrapped onto the current wrapping key. */
        public int $rewrapped,

        /** How many live keys the run superseded. */
        public int $rotated,

        /** How many keys the run skipped. */
        public int $skipped,

        // Not promoted: sorted and bounded before it is kept
        array $skippedKeyIds,

        /** How many batches the run committed, or for a dry run would commit. */
        public int $batches,

        /** Whether the run's `audit_log.keys_rewrapped` record was written. */
        public bool $recorded = false,
    ) {
        $sorted = $skippedKeyIds;

        sort($sorted, SORT_STRING);

        $this->committed     = !$dryRun;
        $this->status        = $skipped > 0 ? RewrapStatus::PARTIAL : RewrapStatus::COMPLETE;
        $this->skippedKeyIds = array_slice($sorted, 0, self::MAX_SKIPPED_IDS);
    }

    /**
     * The result with whether its record was written.
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
            $this->dryRun,
            $this->rotate,
            $this->wrapKeyId,
            $this->rewrapped,
            $this->rotated,
            $this->skipped,
            $this->skippedKeyIds,
            $this->batches,
            $recorded,
        );
    }

    /**
     * The result as a map, under snake-case keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{operation_id: string, committed: bool, recorded: bool, dry_run: bool, status: string, rotate: bool, wrap_key_id: string, keys_rewrapped: int, keys_rotated: int, keys_skipped: int, skipped_key_ids: list<string>, batches: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'    => $this->operationId,
            'committed'       => $this->committed,
            'recorded'        => $this->recorded,
            'dry_run'         => $this->dryRun,
            'status'          => $this->status->value,
            'rotate'          => $this->rotate,
            'wrap_key_id'     => $this->wrapKeyId,
            'keys_rewrapped'  => $this->rewrapped,
            'keys_rotated'    => $this->rotated,
            'keys_skipped'    => $this->skipped,
            'skipped_key_ids' => $this->skippedKeyIds,
            'batches'         => $this->batches,
        ];
    }
}
