<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * A finding of a verification run as a whole rather than of one segment. It
 * names ids and counts, never an entry's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RunFinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $firstBadId
     * @param  int  $count
     */
    public function __construct(

        /** The check the run found failing. */
        public Finding $finding,

        /** The id of the first seal or entry it was found at, or `null` when there is none to name. */
        public ?string $firstBadId = null,

        /** How many times the run found it: member rows, entries or seals. */
        public int $count = 1,
    ) {}

    /**
     * The integrity status the finding gives.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus
     */
    public function status(): IntegrityStatus
    {
        return $this->finding->status();
    }

    /**
     * The finding as its line of output.
     *
     * @return array{type: 'finding', finding: string, integrity: string, count: int, first_bad_id: ?string}
     */
    public function toArray(): array
    {
        return [
            'type'         => 'finding',
            'finding'      => $this->finding->value,
            'integrity'    => $this->status()->value,
            'count'        => $this->count,
            'first_bad_id' => $this->firstBadId,
        ];
    }
}
