<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What one prune decided for one category and tenant pair, once, for the whole
 * run: the days the policy keeps its entries and must preserve them, and the
 * cut-off an entry must have happened strictly before to be pruned, which is
 * `null` when the pair is kept forever and so admits nothing.
 *
 * The cut-off is an instant in the package's form, so it compares with a stored
 * `occurred_at` as text, byte by byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<int, int|string|null>
 */
final readonly class RetentionDecision implements Arrayable
{
    /**
     * Constructor.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?int  $retainDays
     * @param  ?int  $preserveDays
     * @param  ?string  $cutoff
     */
    public function __construct(

        /** The category the decision is for. */
        public string $category,

        /** The tenant the decision is for, or `null` for tenantless entries. */
        public ?Reference $tenant,

        /** The days the policy keeps the pair's entries, or `null` for forever. */
        public ?int $retainDays,

        /** The days the policy must preserve them, `PHP_INT_MAX` for forever, or `null` for no obligation. */
        public ?int $preserveDays,

        /** The instant an entry must have happened strictly before to be pruned, or `null` when none is. */
        public ?string $cutoff,
    ) {}

    /**
     * Whether an entry of the pair that happened at the instant is past its
     * retention: there is a cut-off and the instant is strictly before it.
     *
     * @param  string  $occurredAt
     * @return bool
     */
    public function admits(string $occurredAt): bool
    {
        return $this->cutoff !== null && strcmp($occurredAt, $this->cutoff) < 0;
    }

    /**
     * The decision as the journal records it: the category, the tenant's type
     * and id, the days kept and preserved, and the cut-off, in that order.
     *
     * @return array{0: string, 1: ?string, 2: ?string, 3: ?int, 4: ?int, 5: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [$this->category, $this->tenant?->type, $this->tenant?->id, $this->retainDays, $this->preserveDays, $this->cutoff];
    }
}
