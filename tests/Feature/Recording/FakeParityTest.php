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
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * End-to-end tests for what the fake does and does not model: it holds exactly
 * what the real store would have been given, after the same contributors and
 * the same deferral, and it is no transaction engine, so what a rollback undoes
 * in a database stays held in it.
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
     * With the clock and the id pinned, the record the fake was given and the
     * envelope the database store wrote in a second run are the same, every
     * field and the signature included.
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
     * Records reaching the fake have been through the contributors, the
     * package's and the application's.
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
     * Deferral stays in the real delivery: an after-commit record reaches the
     * fake on the commit, and never on a rollback.
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
     * The fake is no transaction engine: an immediate record it was given stays
     * held after the host rolls back, where a shared database would have undone
     * it. Rollback and atomicity are for tests against a real database.
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
     * What a failing fake throws comes through the recorder to the caller, and
     * it holds nothing.
     *
     * @return void
     */
    public function testFailingPropagatesThroughTheRecorder(): void
    {
        $failure = new \RuntimeException('The store is down.');
        $fake    = FakeAuditStore::failing($failure);

        try {
            AuditLog::record(self::CODE);

            self::fail('Expected the failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
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
