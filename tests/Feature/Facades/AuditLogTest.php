<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the facade: it resolves the recorder, gives it typed, and
 * has a real static `fake()`, with which a record, a bulk record and its
 * attachment included, still runs the whole pipeline up to the store; it is the
 * way into the trail, whose reads the fake records; and it is the way into the
 * lifecycle.
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

    /**
     * A bulk record reaches the fake, which keeps attachments, with the sealed
     * manifest of its subjects, bound by the descriptor the signed record
     * holds.
     *
     * @return void
     */
    public function testABulkRecordReachesTheFakeWithItsAttachment(): void
    {
        $fake = AuditLog::fake();

        $record = AuditLog::bulk('invoice.voided', [Reference::of('invoice', '2'), Reference::of('invoice', '1'), Reference::of('invoice', '2')])->record();

        $stored     = $fake->recorded()[0] ?? null;
        $attachment = $stored?->attachment;

        self::assertSame($record, $stored);
        self::assertNotNull($attachment);
        self::assertSame(2, $attachment->memberCount);
        self::assertSame('bulk', $attachment->kind);
        self::assertTrue($attachment->describes(['artifact_id' => $attachment->id, 'kind' => 'bulk', 'digest' => $attachment->digest, 'count' => 2]));
        self::assertSame($record->properties['_audit']['manifest'] ?? null, ['artifact_id' => $attachment->id, 'kind' => 'bulk', 'digest' => $attachment->digest, 'count' => 2]);
        self::assertNotNull($attachment->members);
        self::assertSame(Manifest::encode([['invoice', '1'], ['invoice', '2']]), app(StringEncrypter::class)->decryptString($attachment->members));
        self::assertSame($record, $fake->finalised()[0]->record);
    }

    /**
     * `trail()` gives a new trail through the facade on each call, and a read
     * of it is authorised by the default policy, which denies, and recorded
     * through the fake before its empty result is returned.
     *
     * @return void
     */
    public function testTrailIsReachedThroughTheFacade(): void
    {
        $fake  = AuditLog::fake();
        $trail = AuditLog::trail();

        self::assertInstanceOf(AuditTrail::class, $trail);
        self::assertNotSame($trail, AuditLog::trail());
        self::assertSame(0, $trail->visibleTo(Reference::of('user', '7'))->count());

        $recorded = $fake->recorded();

        self::assertCount(1, $recorded);
        self::assertSame('audit_log.trail_counted', $recorded[0]->event);
        self::assertSame('denied', $recorded[0]->outcome);
        self::assertSame('no_scope', $recorded[0]->reason);
    }

    /**
     * `lifecycle()` gives a new way into the lifecycle through the facade on
     * each call, and the recorder's own when called on it.
     *
     * @return void
     */
    public function testLifecycleIsReachedThroughTheFacade(): void
    {
        $lifecycle = AuditLog::lifecycle();

        self::assertInstanceOf(AuditLifecycle::class, $lifecycle);
        self::assertNotSame($lifecycle, AuditLog::lifecycle());
        self::assertInstanceOf(AuditLifecycle::class, AuditLog::recorder()->lifecycle());
    }
}
