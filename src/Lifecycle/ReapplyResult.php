<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What erasing again the owners of an erasures file did after a restore: the
 * operation, the file's SHA-256, how many distinct owners it named and how each
 * ended, erased whole, already erased, erased in part or refused, how many
 * lines it rejected, whether every erasure's `audit_log.subject_erased` record
 * was written, and, once the restore is reconciled, the id of the
 * `restore_reconciled` journal row and the anchor's head it names.
 *
 * Each owner's erasure commits on its own, so a result that is not reconciled
 * still reports erasures that stand. The restore is reconciled only when the
 * file was read whole and unchanged, rejected no line, and every owner it names
 * ended erased whole or already erased: an owner erased in part, or refused,
 * leaves keys the restore brought back, and a rejected line an owner unread.
 * The anchor's head is `null` when the anchor cannot report one. The result
 * names no owner.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int|string|null>
 */
final readonly class ReapplyResult implements Arrayable
{
    /** @var bool Whether the restore was journalled reconciled. */
    public bool $reconciled;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  string  $fileSha256
     * @param  int  $owners
     * @param  int  $erased
     * @param  int  $alreadyErased
     * @param  int  $partial
     * @param  int  $refused
     * @param  int  $rejected
     * @param  bool  $recorded
     * @param  ?string  $reconciliationId
     * @param  ?int  $anchoredSequence
     * @param  ?string  $anchoredDigest
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The operation the reconciliation is journalled under. */
        public string $operationId,

        /** The lower-case hex SHA-256 of the erasures file, as read. */
        public string $fileSha256,

        /** How many distinct owners the file named. */
        public int $owners,

        /** How many of them were erased whole. */
        public int $erased,

        /** How many of them were already erased and held no key. */
        public int $alreadyErased,

        /** How many of them were erased in part, keeping blocked keys. */
        public int $partial,

        /** How many of their erasures were refused. */
        public int $refused,

        /** How many lines named no owner and were rejected. */
        public int $rejected,

        /** Whether every erasure's record was written. */
        public bool $recorded,

        /** The id of the `restore_reconciled` journal row, or `null` when the restore is not reconciled. */
        public ?string $reconciliationId = null,

        /** The anchor's head sequence the reconciliation names, or `null`. */
        public ?int $anchoredSequence = null,

        /** The digest of the seal at the anchor's head, or `null`. */
        public ?string $anchoredDigest = null,
    ) {
        $this->reconciled = $reconciliationId !== null;
    }

    /**
     * The result as a map, under snake-case keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{operation_id: string, reconciled: bool, reconciliation_id: ?string, file_sha256: string, owners: int, erased: int, already_erased: int, partial: int, refused: int, rejected: int, recorded: bool, anchored_sequence: ?int, anchored_digest: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'      => $this->operationId,
            'reconciled'        => $this->reconciled,
            'reconciliation_id' => $this->reconciliationId,
            'file_sha256'       => $this->fileSha256,
            'owners'            => $this->owners,
            'erased'            => $this->erased,
            'already_erased'    => $this->alreadyErased,
            'partial'           => $this->partial,
            'refused'           => $this->refused,
            'rejected'          => $this->rejected,
            'recorded'          => $this->recorded,
            'anchored_sequence' => $this->anchoredSequence,
            'anchored_digest'   => $this->anchoredDigest,
        ];
    }
}
