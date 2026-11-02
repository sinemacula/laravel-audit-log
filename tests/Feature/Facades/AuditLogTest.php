<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the facade: it resolves the recorder, gives it typed, and
 * has a real static `fake()`, with which a record still runs the whole pipeline
 * up to the store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLog::class)]
final class AuditLogTest extends TestCase
{
    /** @var string The code each test records. */
    private const string CODE = 'invoice.approved';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * The facade's root is the application's recorder.
     *
     * @return void
     */
    public function testResolvesTheRecorder(): void
    {
        self::assertSame(app(Recorder::class), AuditLog::getFacadeRoot());
    }

    /**
     * `recorder()` gives the same recorder, typed.
     *
     * @return void
     */
    public function testRecorderGivesTheTypedService(): void
    {
        self::assertSame(app(Recorder::class), AuditLog::recorder());
    }

    /**
     * Anything else bound under the recorder is refused, naming the provider to
     * check.
     *
     * @return void
     */
    public function testRecorderRefusesAnotherBinding(): void
    {
        $this->app?->instance(Recorder::class, new \stdClass);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The `Recorder` container binding did not resolve to a Recorder instance - check that AuditLogServiceProvider is registered.');

        AuditLog::recorder();
    }

    /**
     * With no application there is no binding to resolve, and the refusal is
     * the same.
     *
     * @return void
     */
    public function testRecorderRefusesWithNoApplication(): void
    {
        AuditLog::setFacadeApplication(null);

        try {
            AuditLog::recorder();

            self::fail('Expected the recorder to be refused.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('The `Recorder` container binding did not resolve', $exception->getMessage());
        } finally {
            AuditLog::setFacadeApplication($this->app);
        }
    }

    /**
     * `fake()` binds the fake as the application's store and returns it, a
     * fresh one each call.
     *
     * @return void
     */
    public function testFakeBindsTheFakeAndReturnsIt(): void
    {
        $fake = AuditLog::fake();

        self::assertInstanceOf(FakeAuditStore::class, $fake);
        self::assertSame($fake, app(AuditStore::class));

        $second = AuditLog::fake();

        self::assertNotSame($fake, $second);
        self::assertSame($second, app(AuditStore::class));
    }

    /**
     * Faking after the recorder is resolved still takes effect, because the
     * store is resolved for every capture.
     *
     * @return void
     */
    public function testFakeWorksAfterTheRecorderIsResolved(): void
    {
        AuditLog::recorder();

        $fake = AuditLog::fake();

        AuditLog::record(self::CODE);

        self::assertTrue($fake->hasRecorded(self::CODE));
    }

    /**
     * A record reaches the fake through the pipeline: the contributors filled
     * it, and it was finalised with an integrity signature.
     *
     * @return void
     */
    public function testRecordsReachTheFakeThroughThePipeline(): void
    {
        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 42]));

        $fake = AuditLog::fake();

        AuditLog::record(self::CODE);

        $finalised = $fake->finalised()[0];

        self::assertSame('42', $finalised->record->actorId);
        self::assertSame('web', $finalised->record->guard);
        self::assertSame('console', $finalised->record->origin);
        self::assertNotNull($finalised->record->requestId);
        self::assertNotSame('', $finalised->hmac);
    }

    /**
     * Deferral stays in the real delivery, so a record inside a transaction is
     * absent from the fake until it commits.
     *
     * @return void
     */
    public function testADeferredRecordIsAbsentFromTheFakeUntilCommit(): void
    {
        $fake = AuditLog::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        AuditLog::record(self::CODE);

        self::assertSame(0, $fake->count());

        DB::connection(self::CONNECTION)->commit();

        self::assertSame(1, $fake->count());
    }

    /**
     * A record deferred to a transaction that rolls back never reaches the
     * fake.
     *
     * @return void
     */
    public function testARolledBackRecordIsAbsentFromTheFake(): void
    {
        $fake = AuditLog::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        AuditLog::record(self::CODE);

        DB::connection(self::CONNECTION)->rollBack();

        self::assertSame(0, $fake->count());
    }
}
