<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What placing a hold did: the operation that placed it, that it committed,
 * whether its `audit_log.held` record was written, and the hold as the verified
 * journal records it.
 *
 * `committed` is always `true` on a result that is returned, since a hold that
 * did not commit throws instead: the hold's journal row and projection row are
 * in the database. `recorded` is `false` when the record could not be written
 * after the commit, which never undoes the hold; `audit-log:reconcile` writes
 * the record later from the journal.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>|int|string|null>|bool|string>
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 */
final readonly class HoldResult implements Arrayable
{
    /** @var bool Whether the hold committed: always, once a result is returned. */
    public bool $committed;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  bool  $recorded
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     */
    public function __construct(

        /** The operation that placed the hold. */
        public string $operationId,

        /** Whether the hold's `audit_log.held` record was written. */
        public bool $recorded,

        /** The hold placed. */
        public Hold $hold,
    ) {
        $this->committed = true;
    }

    /**
     * The result as a map: the operation, that it committed, whether it was
     * recorded, and the hold as a listing shows it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{operation_id: string, committed: bool, recorded: bool, hold: array{id: string, scope: array{v: int, tenants: ?list<array{0: string, 1: string}>, tenantless: bool, about: ?list<array{0: string, 1: string}>, categories: ?list<string>, from: ?string, to: ?string, import_batch: ?string}, basis: string, review_by: ?string, placed_at: string, operator: array{type: string, id: string}, reason: string, external_reference: ?string, operation_id: string, journal_sequence: int}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id' => $this->operationId,
            'committed'    => $this->committed,
            'recorded'     => $this->recorded,
            'hold'         => $this->hold->toArray(),
        ];
    }
}
