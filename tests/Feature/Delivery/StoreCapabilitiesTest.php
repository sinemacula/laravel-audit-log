<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
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
 * contract, whether it keeps attachments by the one rule a given store is
 * judged by too, the refusal naming its class, its class without a path, and
 * always the store bound now.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoreCapabilities::class)]
final class StoreCapabilitiesTest extends TestCase
{
    /** @var string The refusal of an attachment, by the store's class. */
    private const string REFUSAL = 'The store %s does not keep attachments, so a bulk operation cannot be stored there. Bind one that does, such as the database store.';

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
     * A store that implements the store contract alone keeps no attachment, and
     * neither does one that is durable and joins every transaction but says
     * nothing of attachments.
     *
     * @return void
     */
    public function testAStoreWithoutTheContractAcceptsNoAttachments(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        self::assertFalse($this->capabilities()->acceptsAttachments());

        $this->app?->instance(AuditStore::class, CallbackStore::saying(true, [self::CONNECTION]));

        self::assertFalse($this->capabilities()->acceptsAttachments());
    }

    /**
     * A store with the contract that says it keeps attachments accepts them,
     * and asserting so returns.
     *
     * @return void
     */
    public function testAStoreThatSaysSoAcceptsAttachments(): void
    {
        $this->app?->instance(AuditStore::class, self::attachmentStore(true));

        $capabilities = $this->capabilities();

        self::assertTrue($capabilities->acceptsAttachments());

        $capabilities->assertAcceptsAttachments();
    }

    /**
     * A store with the contract that says it keeps no attachment accepts none,
     * and asserting so refuses with a `\LogicException`.
     *
     * @return void
     */
    public function testAStoreThatSaysNotIsRefused(): void
    {
        $this->app?->instance(AuditStore::class, self::attachmentStore(false));

        $capabilities = $this->capabilities();

        self::assertFalse($capabilities->acceptsAttachments());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::REFUSAL, 'SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments@anonymous'));

        $capabilities->assertAcceptsAttachments();
    }

    /**
     * The refusal names the class of the store bound, a named one by its name
     * and an anonymous one without the file path its class name holds, and
     * holds no previous exception.
     *
     * @return void
     */
    public function testTheRefusalNamesTheStoreClass(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        $refusal = $this->refusal();

        self::assertSame(sprintf(self::REFUSAL, PlainStore::class), $refusal->getMessage());
        self::assertNull($refusal->getPrevious());

        $this->app?->instance(AuditStore::class, self::attachmentStore(false));

        self::assertStringStartsWith('The store SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments@anonymous does not', $this->refusal()->getMessage());
        self::assertStringNotContainsString('.php', $this->refusal()->getMessage());
    }

    /**
     * The store is resolved on every call, so a store bound after the reader
     * was built is the one judged, in either direction.
     *
     * @return void
     */
    public function testTheStoreIsReadOnEveryCall(): void
    {
        $capabilities = $this->capabilities();

        $this->app?->instance(AuditStore::class, self::attachmentStore(true));

        self::assertTrue($capabilities->acceptsAttachments());

        $capabilities->assertAcceptsAttachments();

        $this->app?->instance(AuditStore::class, new PlainStore);

        self::assertFalse($capabilities->acceptsAttachments());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::REFUSAL, PlainStore::class));

        $capabilities->assertAcceptsAttachments();
    }

    /**
     * Rows of `[store, keeps]`: a store given to the rule, and whether it keeps
     * attachments.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Contracts\AuditStore, 1: bool}>
     */
    public static function provideGivenStores(): iterable
    {
        yield from [
            'the store contract alone'           => [new PlainStore, false],
            'durable, saying nothing of it'      => [CallbackStore::saying(true, ['testing']), false],
            'the contract, saying it keeps'      => [self::attachmentStore(true), true],
            'the contract, saying it keeps none' => [self::attachmentStore(false), false],
        ];
    }

    /**
     * A store given to the rule is judged as the bound one is, whatever the
     * container binds, and its refusal names that store's class, so a drain can
     * refuse one destination of a stack.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @param  bool  $keeps
     * @return void
     */
    #[DataProvider('provideGivenStores')]
    public function testAGivenStoreIsJudgedByTheSameRule(AuditStore $store, bool $keeps): void
    {
        $this->app?->instance(AuditStore::class, self::attachmentStore(!$keeps));

        self::assertSame($keeps, StoreCapabilities::keepsAttachments($store));

        $this->app?->instance(AuditStore::class, $store);

        self::assertSame($keeps, $this->capabilities()->acceptsAttachments());

        $refusal = StoreCapabilities::refuseAttachmentsTo($store);

        self::assertSame(\LogicException::class, $refusal::class);
        self::assertSame(sprintf(self::REFUSAL, get_debug_type($store)), $refusal->getMessage());
        self::assertNull($refusal->getPrevious());
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

    /**
     * The refusal the bound store gets, failing the test when there is none.
     *
     * @return \LogicException
     */
    private function refusal(): \LogicException
    {
        try {
            $this->capabilities()->assertAcceptsAttachments();
        } catch (\LogicException $exception) {
            return $exception;
        }

        self::fail('Expected the store to be refused.');
    }

    /**
     * A store with the attachment contract that says so or not, keeping
     * nothing.
     *
     * @param  bool  $accepts
     * @return \SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments
     */
    private static function attachmentStore(bool $accepts): AcceptsAttachments
    {
        return new class ($accepts) implements AcceptsAttachments {
            /**
             * Constructor.
             *
             * @param  bool  $accepts
             */
            public function __construct(

                /** Whether the store says it keeps attachments. */
                private readonly bool $accepts,
            ) {}

            /**
             * Whether the store says it keeps attachments.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return $this->accepts;
            }

            /**
             * Keep nothing.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                // What the store says is all this store is for
            }
        };
    }
}
