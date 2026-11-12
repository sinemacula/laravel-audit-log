<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What rebuilding the key uses did, or for a dry run would do; a rebuild only
 * adds, and only from entries that verify.
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

        /** How many of them verified. */
        public int $verified,

        /** How many it skipped as unverifiable or unreadable. */
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
