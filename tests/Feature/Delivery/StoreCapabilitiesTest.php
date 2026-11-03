<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for what the delivery reads of the bound store: durability and
 * participation as the store says them, neither for a store without the
 * contract, its class without a path, and always the store bound now.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoreCapabilities::class)]
final class StoreCapabilitiesTest extends TestCase
{
    /**
     * A store that implements the store contract alone is neither durable nor
     * joins a transaction, on any connection.
     *
     * @return void
     */
    public function testAStoreWithoutTheInterfaceIsNeither(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        $capabilities = $this->capabilities();

        self::assertFalse($capabilities->isDurable());
        self::assertFalse($capabilities->participatesIn(self::CONNECTION));
        self::assertFalse($capabilities->participatesIn('audit'));
    }

    /**
     * The store is resolved on every call, so a store bound after the reader
     * was built is the one read.
     *
     * @return void
     */
    public function testReadsTheCurrentBinding(): void
    {
        $capabilities = $this->capabilities();

        $this->app?->instance(AuditStore::class, CallbackStore::saying(true, [self::CONNECTION]));

        self::assertTrue($capabilities->isDurable());
        self::assertTrue($capabilities->participatesIn(self::CONNECTION));
        self::assertSame(CallbackStore::class, $capabilities->storeClass());

        $this->app?->instance(AuditStore::class, new NullAuditStore);

        self::assertFalse($capabilities->isDurable());
        self::assertFalse($capabilities->participatesIn(self::CONNECTION));
        self::assertSame(NullAuditStore::class, $capabilities->storeClass());
    }

    /**
     * Rows of `[durable, connections, connection, participates]`: what a store
     * with the contract says, read back as it says it.
     *
     * @return iterable<string, array{0: bool, 1: list<string>, 2: string, 3: bool}>
     */
    public static function provideSayings(): iterable
    {
        yield from [
            'durable, joining the connection asked' => [true, ['testing'], 'testing', true],
            'durable, joining another'              => [true, ['audit'], 'testing', false],
            'durable, joining none'                 => [true, [], 'testing', false],
            'not durable, joining the connection'   => [false, ['testing'], 'testing', true],
            'not durable, joining none'             => [false, [], 'testing', false],
            'durable, joining several, one asked'   => [true, ['audit', 'testing'], 'audit', true],
        ];
    }

    /**
     * Durability and participation are read from the store as it says them,
     * each apart from the other.
     *
     * @param  bool  $durable
     * @param  list<string>  $connections
     * @param  string  $connection
     * @param  bool  $participates
     * @return void
     */
    #[DataProvider('provideSayings')]
    public function testReadsADurableStore(bool $durable, array $connections, string $connection, bool $participates): void
    {
        $this->app?->instance(AuditStore::class, CallbackStore::saying($durable, $connections));

        $capabilities = $this->capabilities();

        self::assertSame($durable, $capabilities->isDurable());
        self::assertSame($participates, $capabilities->participatesIn($connection));
    }

    /**
     * The package's default store is durable and joins a transaction on the
     * storage connection alone.
     *
     * @return void
     */
    public function testTheDefaultStoreIsDurableOnTheStorageConnection(): void
    {
        $capabilities = $this->capabilities();

        self::assertSame(DatabaseAuditStore::class, $capabilities->storeClass());
        self::assertTrue($capabilities->isDurable());
        self::assertTrue($capabilities->participatesIn(self::CONNECTION));
        self::assertFalse($capabilities->participatesIn('audit'));
    }

    /**
     * The fake a test binds says it is durable and joins any transaction.
     *
     * @return void
     */
    public function testTheFakeIsDurableAndJoinsAnyTransaction(): void
    {
        FakeAuditStore::fake();

        $capabilities = $this->capabilities();

        self::assertSame(FakeAuditStore::class, $capabilities->storeClass());
        self::assertTrue($capabilities->isDurable());
        self::assertTrue($capabilities->participatesIn('audit'));
    }

    /**
     * The bound store is named by its class, and an anonymous one without the
     * file path its class name holds.
     *
     * @return void
     */
    public function testNamesTheBoundClass(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        self::assertSame(PlainStore::class, $this->capabilities()->storeClass());

        $this->app?->instance(AuditStore::class, new class implements AuditStore {
            /**
             * Keep nothing.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                // The class name is all this store is for
            }
        });

        self::assertSame('SineMacula\Laravel\AuditLog\Contracts\AuditStore@anonymous', $this->capabilities()->storeClass());
    }

    /**
     * The store is resolved from the container the reader was given, not the
     * application's.
     *
     * @return void
     */
    public function testReadsTheContainerItWasGiven(): void
    {
        $container = new Container;

        $container->instance(AuditStore::class, new NullAuditStore);

        $capabilities = new StoreCapabilities($container);

        self::assertFalse($capabilities->isDurable());
        self::assertSame(NullAuditStore::class, $capabilities->storeClass());
    }

    /**
     * The reader, built on the application.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities
     */
    private function capabilities(): StoreCapabilities
    {
        self::assertNotNull($this->app);

        return new StoreCapabilities($this->app);
    }
}
