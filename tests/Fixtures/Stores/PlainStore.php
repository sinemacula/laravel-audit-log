<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that implements the store contract alone, saying nothing of
 * durability or transactions, and keeps every record it is given, so a test can
 * count its calls and read what it received.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainStore implements AuditStore
{
    /** @var list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord> The records received, oldest first. */
    private array $received = [];

    /**
     * Keep the record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $this->received[] = $record;
    }

    /**
     * How many times it was called.
     *
     * @return int
     */
    public function calls(): int
    {
        return count($this->received);
    }

    /**
     * The records received, oldest first.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord>
     */
    public function received(): array
    {
        return $this->received;
    }
}
