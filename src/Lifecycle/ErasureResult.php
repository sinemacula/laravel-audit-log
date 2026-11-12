<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;

/**
 * What erasing an owner did; the owner is named only by its keyed fingerprint,
 * which is personal data while it can be linked to the owner.
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
    /** @var bool Always `true`: a refused or failed erasure throws. */
    public bool $committed;

    /** @var list<string> The distinct reasons keys were kept, sorted bytewise. */
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

        /** The erasure's journal row id, or `null` when nothing was written. */
        public ?string $erasureId,

        /** How the erasure ended. */
        public ErasureStatus $status,

        /** The owner's HMAC-SHA256 fingerprint in lower-case hex. */
        public string $fingerprint,

        /** The id of the ring key the fingerprint was taken under. */
        public string $fingerprintKey,

        /** Keys destroyed. */
        public int $keysDestroyed,

        /** Keys kept, each blocked. */
        public int $keysKept,

        /** Distinct entries the destroyed keys encrypted. */
        public int $entriesAffected,

        // Not promoted: deduplicated and sorted into $this->blocked.
        array $blocked,

        /** Whether the erasure went ahead over older outbox rows. */
        public bool $pendingAccepted,

        /** Whether the `audit_log.subject_erased` record was written. */
        public bool $recorded = false,
    ) {
        $unique = array_values(array_unique($blocked));

        sort($unique, SORT_STRING);

        $this->committed = true;
        $this->blocked   = $unique;
    }

    /**
     * The result for an owner already erased that holds no key.
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
     * The result as a snake-case map.
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
