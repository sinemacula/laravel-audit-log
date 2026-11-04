<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;

/**
 * What erasing an owner did: the operation, the id of the erasure's journal
 * row, which the owner's marker shares and every key it destroyed names, how it
 * ended, the owner's keyed fingerprint and the id of the ring key it was taken
 * under, how many keys it destroyed and kept, how many entries the destroyed
 * keys encrypted, every reason a kept key was blocked, whether it accepted
 * outbox rows older than itself, that it committed, and whether its
 * `audit_log.subject_erased` record was written.
 *
 * An owner already erased that holds no key is `already_erased`: nothing was
 * written, so the result names no erasure row. `committed` is always `true` on
 * a result that is returned, since an erasure that is refused or fails throws
 * instead. `recorded` is `false` when the record could not be written after the
 * commit, which never undoes the erasure; `audit-log:reconcile` writes the
 * record later from the journal. The fingerprint is personal data while it can
 * be linked to the owner, and the result names the owner by nothing else.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int|list<string>|string|null>
 */
final readonly class ErasureResult implements Arrayable
{
    /** @var bool Whether the erasure committed: always, once a result is returned. */
    public bool $committed;

    /** @var list<string> Every reason a kept key was blocked, each once, sorted bytewise. */
    public array $blocked;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  ?string  $erasureId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus  $status
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     * @param  int  $keysDestroyed
     * @param  int  $keysKept
     * @param  int  $entriesAffected
     * @param  list<string>  $blocked
     * @param  bool  $pendingAccepted
     * @param  bool  $recorded
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The operation that erased the owner. */
        public string $operationId,

        /** The id of the erasure's journal row, or `null` when nothing was written. */
        public ?string $erasureId,

        /** How the erasure ended. */
        public ErasureStatus $status,

        /** The owner's fingerprint: HMAC-SHA256, lower-case hex, under the ring key named. */
        public string $fingerprint,

        /** The id of the ring key the fingerprint was taken under. */
        public string $fingerprintKey,

        /** How many keys the erasure destroyed. */
        public int $keysDestroyed,

        /** How many keys the erasure kept, each blocked. */
        public int $keysKept,

        /** How many entries the destroyed keys encrypted, each entry once. */
        public int $entriesAffected,

        // Every reason a kept key was blocked, in any order and with repeats.
        array $blocked,

        /** Whether the erasure went ahead over outbox rows created before it started. */
        public bool $pendingAccepted,

        /** Whether the erasure's `audit_log.subject_erased` record was written. */
        public bool $recorded = false,
    ) {
        $unique = array_values(array_unique($blocked));

        sort($unique, SORT_STRING);

        $this->committed = true;
        $this->blocked   = $unique;
    }

    /**
     * The result of an owner already erased that holds no key: nothing written,
     * nothing destroyed.
     *
     * @param  string  $operationId
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     * @return self
     */
    public static function alreadyErased(string $operationId, string $fingerprint, string $fingerprintKey): self
    {
        return new self($operationId, null, ErasureStatus::ALREADY_ERASED, $fingerprint, $fingerprintKey, 0, 0, 0, [], false);
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
            $this->erasureId,
            $this->status,
            $this->fingerprint,
            $this->fingerprintKey,
            $this->keysDestroyed,
            $this->keysKept,
            $this->entriesAffected,
            $this->blocked,
            $this->pendingAccepted,
            $recorded,
        );
    }

    /**
     * The result as a map, under snake-case keys: the operation, whether it
     * committed and was recorded, the erasure row, the status, the owner's
     * fingerprint and its key, the counts, the blocked reasons and whether the
     * outbox was accepted.
     *
     * @return array<string, bool|int|list<string>|string|null>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'      => $this->operationId,
            'committed'         => $this->committed,
            'recorded'          => $this->recorded,
            'erasure_id'        => $this->erasureId,
            'status'            => $this->status->value,
            'owner_fingerprint' => $this->fingerprint,
            'fingerprint_key'   => $this->fingerprintKey,
            'keys_destroyed'    => $this->keysDestroyed,
            'keys_kept'         => $this->keysKept,
            'entries_affected'  => $this->entriesAffected,
            'blocked'           => $this->blocked,
            'pending_accepted'  => $this->pendingAccepted,
        ];
    }
}
