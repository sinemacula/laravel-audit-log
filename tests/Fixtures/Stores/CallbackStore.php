<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that hands every record to a callback, which may keep it, read
 * the world around it or throw, and that says of itself whatever the test
 * configures: durable or not, and the connections whose transactions it joins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackStore implements DurableAuditStore
{
    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\FinalisedRecord): void  $callback
     * @param  bool  $durable
     * @param  list<string>  $participatesOn
     */
    public function __construct(

        /** What every store call runs, with the record. */
        #[\SensitiveParameter]
        private \Closure $callback,

        /** Whether it says a return is durable. */
        private bool $durable = true,

        /** The connections whose transactions it says it joins. */
        private array $participatesOn = [],
    ) {}

    /**
     * A store that keeps nothing and says what it is told.
     *
     * @param  bool  $durable
     * @param  list<string>  $participatesOn
     * @return self
     */
    public static function saying(bool $durable, array $participatesOn = []): self
    {
        return new self(static function (): void {}, $durable, $participatesOn);
    }

    /**
     * A store whose every call throws the failure.
     *
     * @param  \Throwable  $failure
     * @param  bool  $durable
     * @param  list<string>  $participatesOn
     * @return self
     */
    public static function failingWith(#[\SensitiveParameter] \Throwable $failure, bool $durable = true, array $participatesOn = []): self
    {
        return new self(static function () use ($failure): never {
            throw $failure;
        }, $durable, $participatesOn);
    }

    /**
     * Run the callback with the record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        ($this->callback)($record);
    }

    /**
     * Whether it says a return is durable.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return $this->durable;
    }

    /**
     * Whether it says it joins a transaction on the connection.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return in_array($connection, $this->participatesOn, true);
    }
}
