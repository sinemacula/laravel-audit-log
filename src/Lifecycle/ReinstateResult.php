<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What reinstating an erased owner did: the operation, the id of the
 * reinstatement's journal row, which its marker shares, the owner's keyed
 * fingerprint and the id of the ring key it was taken under, the generation
 * floor the owner's next key is created above, that it committed, and whether
 * its `audit_log.keys_reinstated` record was written.
 *
 * `committed` is always `true` on a result that is returned, since a
 * reinstatement that did not commit throws instead. `recorded` is `false` when
 * the record could not be written after the commit, which never undoes the
 * reinstatement; `audit-log:reconcile` writes the record later from the
 * journal. The fingerprint is personal data while it can be linked to the
 * owner, and the result names the owner by nothing else.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int|string>
 */
final readonly class ReinstateResult implements Arrayable
{
    /** @var bool Whether the reinstatement committed: always, once a result is returned. */
    public bool $committed;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  string  $reinstatementId
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     * @param  int  $generationFloor
     * @param  bool  $recorded
     */
    public function __construct(

        /** The operation that reinstated the owner. */
        public string $operationId,

        /** The id of the reinstatement's journal row, which the owner's new marker shares. */
        public string $reinstatementId,

        /** The owner's fingerprint: HMAC-SHA256, lower-case hex, under the ring key named. */
        public string $fingerprint,

        /** The id of the ring key the fingerprint was taken under. */
        public string $fingerprintKey,

        /** The generation the owner's next key of any unit is created above. */
        public int $generationFloor,

        /** Whether the reinstatement's `audit_log.keys_reinstated` record was written. */
        public bool $recorded = false,
    ) {
        $this->committed = true;
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
        return new self($this->operationId, $this->reinstatementId, $this->fingerprint, $this->fingerprintKey, $this->generationFloor, $recorded);
    }

    /**
     * The result as a map, under snake-case keys.
     *
     * @return array{operation_id: string, committed: bool, recorded: bool, reinstatement_id: string, owner_fingerprint: string, fingerprint_key: string, generation_floor: int}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'      => $this->operationId,
            'committed'         => $this->committed,
            'recorded'          => $this->recorded,
            'reinstatement_id'  => $this->reinstatementId,
            'owner_fingerprint' => $this->fingerprint,
            'fingerprint_key'   => $this->fingerprintKey,
            'generation_floor'  => $this->generationFloor,
        ];
    }
}
