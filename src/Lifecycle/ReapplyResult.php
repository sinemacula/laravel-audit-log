<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What erasing an erasures file's owners again after a restore did; each
 * erasure commits alone and stands even when the restore is not reconciled.
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
