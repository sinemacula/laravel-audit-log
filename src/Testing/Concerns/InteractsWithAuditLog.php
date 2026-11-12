<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Testing\Concerns;

use Illuminate\Container\Container;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;

/**
 * Assertions on what the audit log was asked to store, read from the fake
 * `AuditLog::fake()` bound as the store.
 *
 * A code is held to the grammar, so a malformed one is refused, and may be one
 * of the package's own. A failure lists the codes recorded, in order, and never
 * another value of a record.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait InteractsWithAuditLog
{
    /**
     * Assert a record of the code was stored, and one the closure accepts when
     * one is given.
     *
     * @param  \BackedEnum|string  $code
     * @param  (\Closure(\SineMacula\Laravel\AuditLog\Records\AuditRecord): bool)|null  $filter
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\AssertionFailedError
     */
    public function assertAudited(\BackedEnum|string $code, ?\Closure $filter = null): static
    {
        $fake  = self::auditLogFake();
        $value = EventCode::forReading($code)->value;

        Assert::assertTrue(
            self::auditRecordsOf($fake, $value, $filter) !== [],
            sprintf('Expected a record of [%s]%s. %s', $value, $filter === null ? '' : ' that the closure accepts', self::auditedCodes($fake)),
        );

        return $this;
    }

    /**
     * Assert no record of the code was stored, or none the closure accepts when
     * one is given.
     *
     * @param  \BackedEnum|string  $code
     * @param  (\Closure(\SineMacula\Laravel\AuditLog\Records\AuditRecord): bool)|null  $filter
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\AssertionFailedError
     */
    public function assertNotAudited(\BackedEnum|string $code, ?\Closure $filter = null): static
    {
        $fake  = self::auditLogFake();
        $value = EventCode::forReading($code)->value;

        Assert::assertTrue(
            self::auditRecordsOf($fake, $value, $filter) === [],
            sprintf('Expected no record of [%s]%s. %s', $value, $filter === null ? '' : ' that the closure accepts', self::auditedCodes($fake)),
        );

        return $this;
    }

    /**
     * Assert no record was stored.
     *
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PHPUnit\Framework\AssertionFailedError
     */
    public function assertNothingAudited(): static
    {
        $fake = self::auditLogFake();

        Assert::assertTrue($fake->count() === 0, sprintf('Expected no record. %s', self::auditedCodes($fake)));

        return $this;
    }

    /**
     * Assert exactly so many records of the code were stored.
     *
     * @param  \BackedEnum|string  $code
     * @param  int  $times
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\AssertionFailedError
     */
    public function assertAuditedTimes(\BackedEnum|string $code, int $times): static
    {
        $fake  = self::auditLogFake();
        $value = EventCode::forReading($code)->value;
        $count = count(self::auditRecordsOf($fake, $value, null));

        Assert::assertTrue($count === $times, sprintf('Expected %d of [%s], and there were %d. %s', $times, $value, $count, self::auditedCodes($fake)));

        return $this;
    }

    /**
     * The fake bound as the current container's store; anything else, no store
     * at all included, fails the test.
     *
     * @return \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PHPUnit\Framework\AssertionFailedError
     */
    private static function auditLogFake(): FakeAuditStore
    {
        $container = Container::getInstance();
        $store     = $container->bound(AuditStore::class) ? $container->make(AuditStore::class) : null;

        if (!$store instanceof FakeAuditStore) {
            Assert::fail('Call `AuditLog::fake()` before asserting on the audit log.');
        }

        return $store;
    }

    /**
     * The records of the code the fake holds, and those the filter accepts when
     * one is given; the filter sees only records of the code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @param  string  $code
     * @param  (\Closure(\SineMacula\Laravel\AuditLog\Records\AuditRecord): bool)|null  $filter
     * @return list<\SineMacula\Laravel\AuditLog\Records\AuditRecord>
     */
    private static function auditRecordsOf(FakeAuditStore $fake, string $code, ?\Closure $filter): array
    {
        return $fake->recorded(static fn (AuditRecord $record): bool => $record->event === $code && ($filter === null || $filter($record)));
    }

    /**
     * What a failure says was stored: the codes, in order, and nothing else of
     * a record, since a failure message is printed to a build's log.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return string
     */
    private static function auditedCodes(FakeAuditStore $fake): string
    {
        $codes = array_map(static fn (AuditRecord $record): string => $record->event, $fake->recorded());

        return $codes === [] ? 'No record was stored.' : sprintf('Stored, in order: %s.', implode(', ', $codes));
    }
}
