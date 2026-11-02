<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store for tests: keeps every finalised record it is given instead of
 * writing it, so a test can read what the database would have been asked to
 * store. It runs no query.
 *
 * `FakeAuditStore::fake()` binds a fresh instance as the application's store
 * and returns it; `FakeAuditStore::failing()` binds one that throws the
 * exception given from every call and holds nothing. Assert on what it holds
 * with the test framework's own assertions, or with
 * `Concerns\InteractsWithAuditLog`.
 *
 * It observes successful store calls and is not a transaction engine. Deferral
 * stays in the real delivery, so an after-commit record arrives when its
 * transaction commits and never when it is rolled back, but a record an
 * immediate or a transactional write stored stays held here if the host rolls
 * back afterwards; rollback and atomicity are for tests against a real
 * database. The store contract's clause that an implementation keeps no state
 * is expressly waived for this test double, whose state is the point.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeAuditStore implements AuditStore
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
    public function store(FinalisedRecord $record): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        $this->finalised[] = $record;
    }

    /**
     * The records stored, oldest first, or those of them the filter accepts.
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
     * Whether a record of the code was stored; the code is read as `event()`
     * reads it, so a malformed one is refused.
     *
     * @param  \BackedEnum|string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function hasRecorded(\BackedEnum|string $code): bool
    {
        $value = EventCode::of($code)->value;

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
