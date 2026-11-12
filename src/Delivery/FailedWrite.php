<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;

/**
 * One failed write as the failure handler is given it.
 *
 * The open transactions are read before the attempt, because Laravel forgets an
 * open transaction when its connection is lost.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailedWrite
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  ?\SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @param  \Throwable  $failure
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  string  $store
     * @param  ?string  $connection
     * @param  bool  $hostOpen
     * @param  list<string>  $openTransactions
     */
    public function __construct(

        /** The record as it was captured. */
        #[\SensitiveParameter]
        public AuditRecord $record,

        /** The record as finalised, or `null` when finalising it failed. */
        #[\SensitiveParameter]
        public ?FinalisedRecord $finalised,

        /** What the write failed with, which only the diagnostics read. */
        #[\SensitiveParameter]
        public \Throwable $failure,

        /** The step of the write path that failed. */
        public FailedOperation $operation,

        /** The class of the store or outbox gateway the write failed on. */
        public string $store,

        /** The alias of the connection written on, or `null` when there is none. */
        public ?string $connection,

        /** Whether a transaction was open on that connection before the write was tried. */
        public bool $hostOpen,

        /** Every connection with a transaction open before the write was tried. */
        public array $openTransactions = [],
    ) {}

    /**
     * Every connection a transaction was open on before the write was tried,
     * the one written on included.
     *
     * @return list<string>
     */
    public function openConnections(): array
    {
        if (!$this->hostOpen || $this->connection === null || in_array($this->connection, $this->openTransactions, true)) {
            return $this->openTransactions;
        }

        return [...$this->openTransactions, $this->connection];
    }
}
