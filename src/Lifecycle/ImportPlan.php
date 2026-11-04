<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * What one chunk of an import does with its lines, once they are classified:
 * the new lines it inserts, each with the digest of its source assertion under
 * the ring's signing key, how many lines are duplicates of a record imported
 * already, and the source record ids of the lines that conflict with one, by
 * their line numbers, so they are listed in file order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportPlan
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  array<int, string>  $digests
     * @param  int  $duplicates
     * @param  array<int, string>  $conflicting
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The new lines, in file order. */
        #[\SensitiveParameter]
        public array $lines,

        /** The digest of each new line's source assertion under the ring's signing key, by its line number. */
        public array $digests,

        /** How many lines are duplicates of a record imported already, or of an earlier line of the chunk. */
        public int $duplicates,

        /** The source record id of every line that conflicts, by its line number. */
        public array $conflicting,
    ) {
        if ($duplicates < 0) {
            throw new \InvalidArgumentException('An import plan\'s duplicates cannot be fewer than none.');
        }

        foreach ($lines as $line) {
            if (!isset($digests[$line->number])) {
                throw new \InvalidArgumentException('Every new line of an import plan has its digest.');
            }
        }
    }

    /**
     * How many lines conflict with a record imported already, or with an
     * earlier line of the chunk.
     *
     * @return int
     */
    public function conflicts(): int
    {
        return count($this->conflicting);
    }

    /**
     * The source record id of every line that conflicts, in file order.
     *
     * @return list<string>
     */
    public function conflictIds(): array
    {
        $conflicting = $this->conflicting;

        ksort($conflicting);

        return array_values($conflicting);
    }

    /**
     * The digest of the new line's source assertion under the ring's signing
     * key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @return string
     *
     * @throws \LogicException
     */
    public function digestOf(#[\SensitiveParameter] ImportLine $line): string
    {
        return $this->digests[$line->number] ?? throw new \LogicException('Only a new line of an import plan has a digest in it.');
    }

    /**
     * The plan with every new line a conflict instead, and nothing inserted:
     * what a chunk whose inserts violated the source's unique index twice is
     * left with.
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withNewLinesAsConflicts(): self
    {
        $conflicting = $this->conflicting;

        foreach ($this->lines as $line) {
            $conflicting[$line->number] = $line->sourceRecordId;
        }

        return new self([], [], $this->duplicates, $conflicting);
    }
}
