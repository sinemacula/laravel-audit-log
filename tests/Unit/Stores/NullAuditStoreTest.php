<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the store that keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NullAuditStore::class)]
final class NullAuditStoreTest extends TestCase
{
    /**
     * Storing a record always succeeds and leaves the store without state.
     *
     * @return void
     */
    public function testStoresNothingAndSucceeds(): void
    {
        $store  = new NullAuditStore;
        $record = new FinalisedRecord(RecordFactory::captured(), '2026-11-01T12:00:01.000000Z', 1, 'k2026', str_repeat('a', 64));

        $store->store($record);
        $store->store($record);

        self::assertInstanceOf(DurableAuditStore::class, $store);
        self::assertSame([], (new \ReflectionObject($store))->getProperties());
    }

    /**
     * It accepts attachments, since it keeps nothing of any record.
     *
     * @return void
     */
    public function testItAcceptsAttachmentsAndKeepsNothing(): void
    {
        $store = new NullAuditStore;

        self::assertInstanceOf(AcceptsAttachments::class, $store);
        self::assertTrue($store->acceptsAttachments());

        $store->store(RecordFactory::finalisedBundle());

        self::assertSame([], (new \ReflectionObject($store))->getProperties());
    }

    /**
     * It never says a return is durable, since nothing is kept.
     *
     * @return void
     */
    public function testIsNotDurable(): void
    {
        self::assertFalse((new NullAuditStore)->isDurable());
    }

    /**
     * Rows of `[connection]`: the test connection, another and an empty name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConnections(): iterable
    {
        yield from [
            'the test connection' => ['testing'],
            'another'             => ['audit'],
            'an empty name'       => [''],
        ];
    }

    /**
     * It joins no transaction, on any connection.
     *
     * @param  string  $connection
     * @return void
     */
    #[DataProvider('provideConnections')]
    public function testParticipatesInNothing(string $connection): void
    {
        self::assertFalse((new NullAuditStore)->participatesIn($connection));
    }

    /**
     * The record is marked sensitive, so no trace shows a value of it.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(NullAuditStore::class, 'store'))->getParameters()[0];

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }
}
