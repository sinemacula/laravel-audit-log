<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * What one chunk of an import does with its classified lines.
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

        /** Each new line's source assertion digest, by line number. */
        public array $digests,

        /** Lines repeating a stored record or an earlier line of the chunk. */
        public int $duplicates,

        /** The source record id of every conflicting line, by line number. */
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
     * How many lines conflict.
     *
     * @return int
     */
    public function conflicts(): int
    {
        return count($this->conflicting);
    }

    /**
     * The source record id of every conflicting line, in file order.
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
     * The digest of the new line's source assertion.
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
     * The plan with every new line a conflict, for a chunk whose inserts hit
     * the source's unique index twice.
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
