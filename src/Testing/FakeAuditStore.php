<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store for tests: keeps every finalised record it is given instead of
 * writing it, and runs no query.
 *
 * Deferral stays in the real delivery, so an after-commit record arrives only
 * when its transaction commits, but an immediate or transactional record stays
 * held if the host rolls back afterwards. Under `delivery.mode = outbox` a
 * record arrives only when drained.
 *
 * It claims to be durable, to join any connection's transaction and to keep
 * attachments, so no record is refused for want of a store that could keep it.
 * The store contract's no-state clause is waived for this test double.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord> The records stored, oldest first. */
    private array $finalised = [];

    /**
     * Constructor.
     *
     * @param  ?\Throwable  $failure
     */
    private function __construct(

        /** What every store call throws, if anything. */
        private readonly ?\Throwable $failure = null,
    ) {}

    /**
     * Bind a fresh fake as the store in the container (the application's, when
     * none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        return self::bind(new self, $container);
    }

    /**
     * Bind a fake that throws the exception from every store call and holds
     * nothing, in the container (the application's, when none is given), and
     * return it.
     *
     * @param  \Throwable  $exception
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function failing(\Throwable $exception, ?ContainerContract $container = null): self
    {
        return self::bind(new self($exception), $container);
    }

    /**
     * Keep the finalised record instead of writing it, or throw the exception
     * of a failing fake.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        $this->finalised[] = $record;
    }

    /**
     * Whether a return is a durable acknowledgement: always, so a fail-closed
     * record can be tested against the fake.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return true;
    }

    /**
     * Whether a write joins a transaction on the connection: always, so a
     * transactional record can be tested against the fake, whatever its
     * connection.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return true;
    }

    /**
     * Whether the store keeps a record's attachment: always, so a bulk record
     * can be tested against the fake.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return true;
    }

    /**
     * The records stored, oldest first, or those of them the filter accepts; a
     * bulk record carries its attachment.
     *
     * @param  (\Closure(\SineMacula\Laravel\AuditLog\Records\AuditRecord): bool)|null  $filter
     * @return list<\SineMacula\Laravel\AuditLog\Records\AuditRecord>
     */
    public function recorded(?\Closure $filter = null): array
    {
        $records = array_map(static fn (FinalisedRecord $record): AuditRecord => $record->record, $this->finalised);

        return $filter === null ? $records : array_values(array_filter($records, $filter));
    }

    /**
     * The records as the store received them, oldest first, with the time each
     * was recorded and its integrity fields.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord>
     */
    public function finalised(): array
    {
        return $this->finalised;
    }

    /**
     * Whether a record of the code was stored; the code is held to the grammar
     * and the length, so a malformed one is refused, and may be one of the
     * package's own.
     *
     * @param  \BackedEnum|string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function hasRecorded(\BackedEnum|string $code): bool
    {
        $value = EventCode::forReading($code)->value;

        return $this->recorded(static fn (AuditRecord $record): bool => $record->event === $value) !== [];
    }

    /**
     * How many records were stored.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->finalised);
    }

    /**
     * Forget every record stored so far; a failing fake goes on failing.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->finalised = [];
    }

    /**
     * Bind the fake as the store in the container, or in the application's when
     * none is given, and return it.
     *
     * @param  self  $fake
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    private static function bind(self $fake, ?ContainerContract $container): self
    {
        ($container ?? Container::getInstance())->instance(AuditStore::class, $fake);

        return $fake;
    }
}
