<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What releasing a hold did; `recorded` is `false` when the record failed after
 * the commit, which `audit-log:reconcile` repairs.
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
final readonly class ReleaseResult implements Arrayable
{
    /** @var bool Whether the release committed: always, once a result is returned. */
    public bool $committed;

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  bool  $recorded
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     */
    public function __construct(

        /** The operation that released the hold. */
        public string $operationId,

        /** Whether the release's `audit_log.released` record was written. */
        public bool $recorded,

        /** The hold released, as it was while it was active. */
        public Hold $hold,
    ) {
        $this->committed = true;
    }

    /**
     * The result as a map, with the hold as a listing shows it.
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
