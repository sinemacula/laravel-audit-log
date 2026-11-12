<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * End-to-end tests for what the fake does and does not model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeAuditStore::class)]
#[CoversClass(Recorder::class)]
final class FakeParityTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code the tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The id every record of the parity test is pinned to. */
    private const string ID = '019b0000-0000-7000-8000-000000000001';

    /**
     * Roll back any transaction a test left open, and put UUIDs back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * The fake holds the record the database store writes, signature included.
     *
     * @return void
     */
    public function testTheFakeHoldsTheRecordTheStoreReceived(): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at('2026-11-01T12:00:00.123456Z'));

        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString(self::ID));

        $fake = AuditLog::fake();

        self::record();

        $this->app?->instance(AuditStore::class, app(DatabaseAuditStore::class));

        self::record();

        self::assertCount(1, $fake->finalised());
        self::assertSame(1, $this->entryCount());
        self::assertSame(
            CanonicalEncoder::encode($fake->finalised()[0]->toArray()),
            CanonicalEncoder::encode($this->storedRow(self::ID)),
        );
    }

    /**
     * A bulk record's bundle reaches the fake as the database keeps it.
     *
     * @return void
     */
    public function testABundleReachesTheFakeAsTheDatabaseKeepsIt(): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at('2026-11-01T12:00:00.223456Z'));

        $record = RecordFactory::bundled();
        $fake   = AuditLog::fake();

        app(RecordDelivery::class)->deliver($record, Timing::IMMEDIATE, null);

        $this->app?->instance(AuditStore::class, app(DatabaseAuditStore::class));

        app(RecordDelivery::class)->deliver($record, Timing::IMMEDIATE, null);

        $held       = $fake->finalised()[0];
        $attachment = $fake->recorded()[0]->attachment;
        $artifact   = (new RowCodec)->encodeAttachment($held);
        $stored     = (array) $this->storageConnection()->table(EntrySettings::artifactsTable())->sole();

        self::assertCount(1, $fake->finalised());
        self::assertNotNull($attachment);
        self::assertSame(1, $this->entryCount());
        self::assertSame(CanonicalEncoder::encode($held->toArray()), CanonicalEncoder::encode($this->storedRow($record->id)));
        self::assertSame(
            [...$artifact, 'member_count' => (string) $artifact['member_count'], 'created_at' => $held->recordedAt],
            [...array_map(strval(...), $stored), 'created_at' => StoredTime::fromStorage((string) $stored['created_at'])],
        );
        self::assertSame($attachment->digest, hash('sha256', app('encrypter')->decryptString((string) $stored['members'])));
    }

    /**
     * Records reaching the fake have been through every contributor.
     *
     * @return void
     */
    #[DefineEnvironment('registerTheTenantContributor')]
    public function testContributorsRunWithTheFake(): void
    {
        $fake = AuditLog::fake();

        AuditLog::record(self::CODE);

        $record = $fake->recorded()[0];

        self::assertSame(TenantContributor::ID, $record->tenantId);
        self::assertSame('console', $record->origin);
        self::assertNotNull($record->requestId);
    }

    /**
     * An after-commit record reaches the fake on commit and never on rollback.
     *
     * @return void
     */
    public function testDeferralRunsWithTheFake(): void
    {
        $fake       = AuditLog::fake();
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        AuditLog::record('invoice.dropped');

        self::assertSame(0, $fake->count());

        $connection->rollBack();

        self::assertSame(0, $fake->count());

        $connection->beginTransaction();

        AuditLog::record(self::CODE);

        self::assertSame(0, $fake->count());

        $connection->commit();

        self::assertSame(1, $fake->count());
        self::assertTrue($fake->hasRecorded(self::CODE));
        self::assertFalse($fake->hasRecorded('invoice.dropped'));
    }

    /**
     * An immediate record stays in the fake after a host rollback.
     *
     * @return void
     */
    public function testAnImmediateRecordStaysInTheFakeAfterAHostRollback(): void
    {
        $fake       = AuditLog::fake();
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        AuditLog::event(self::CODE)->immediately()->record();

        $connection->rollBack();

        self::assertSame(1, $fake->count());
    }

    /**
     * Under `throw`, a failing fake's sanitised exception reaches the caller.
     *
     * @return void
     */
    public function testFailingPropagatesThroughTheRecorder(): void
    {
        config()->set('audit-log.failure.mode', 'throw');

        $fake = FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            AuditLog::record(self::CODE);

            self::fail('Expected the failure to propagate.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(\RuntimeException::class, $exception->exceptionClass);
        }

        self::assertSame(0, $fake->count());
    }

    /**
     * Register the tenant contributor as a provider would, while booting.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function registerTheTenantContributor(Application $app): void
    {
        $app->booting(static function (Application $app): void {
            $app->make(Recorder::class)->contribute(TenantContributor::class);
        });
    }

    /**
     * Record the one activity the parity test compares.
     *
     * @return void
     */
    private static function record(): void
    {
        AuditLog::event(self::CODE)
            ->on(Reference::of('invoice', '42'))
            ->by(Reference::of('staff', '7'))
            ->withProperties(['amount' => '1200.00', 'nested' => ['currency' => 'GBP']])
            ->record();
    }
}
