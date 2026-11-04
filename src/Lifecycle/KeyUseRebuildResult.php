<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What rebuilding the key uses did, or for a dry run would do: how many entries
 * it read, how many of them verified and how many it skipped because their
 * signature did not, and how many missing key uses it added from the verified
 * ones.
 *
 * A rebuild only adds: a key use it did not find in a verified entry is left as
 * it is, and an entry that does not verify adds nothing, since what it says
 * cannot be trusted. A dry run reads as a rebuild does and counts what it would
 * add, writing nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|int>
 */
final readonly class KeyUseRebuildResult implements Arrayable
{
    /**
     * Constructor.
     *
     * @param  int  $entries
     * @param  int  $verified
     * @param  int  $skipped
     * @param  int  $added
     * @param  bool  $dryRun
     */
    public function __construct(

        /** How many entries the rebuild read. */
        public int $entries,

        /** How many of them verified under their signature. */
        public int $verified,

        /** How many of them it skipped: a signature that does not match, a signing key the ring does not hold, or a row it cannot read. */
        public int $skipped,

        /** How many missing key uses it added, or for a dry run would add. */
        public int $added,

        /** Whether the rebuild was a dry run, which writes nothing. */
        public bool $dryRun,
    ) {}

    /**
     * The result as a map, under snake-case keys.
     *
     * @return array{entries: int, verified: int, skipped: int, added: int, dry_run: bool}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'entries'  => $this->entries,
            'verified' => $this->verified,
            'skipped'  => $this->skipped,
            'added'    => $this->added,
            'dry_run'  => $this->dryRun,
        ];
    }
}
