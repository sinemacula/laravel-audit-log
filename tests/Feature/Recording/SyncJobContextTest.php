<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\Fixtures\Commands\NestingCommand;
use Tests\Fixtures\Jobs\DispatchingJob;
use Tests\Fixtures\Jobs\FailedHookJob;
use Tests\Fixtures\Jobs\RecordingJob;
use Tests\Fixtures\Jobs\ThrowingJob;
use Tests\Fixtures\Providers\AuditsFrameEndsProvider;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for a job run on the sync queue, inside whatever dispatched
 * it: the job's own origin and name with its dispatcher's identity, the
 * caller's frame coming back on success and on failure, the `failed()` hook,
 * what an application's listeners on a job's end see, and a snapshot one job
 * leaves in Context not reaching the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrackJobFrames::class)]
#[CoversClass(CarryContextIntoJobs::class)]
#[CoversClass(ExecutionFrames::class)]
#[CoversClass(ActorContributor::class)]
#[CoversClass(OriginContributor::class)]
#[CoversClass(RequestContributor::class)]
final class SyncJobContextTest extends TestCase
{
    use WithConsoleEvents;

    /** @var string The code a route records before the job. */
    private const string BEFORE = 'route.before';

    /** @var string The code a route records after the job. */
    private const string AFTER = 'route.after';

    /** @var string The address a request comes from. */
    private const string CLIENT_IP = '203.0.113.7';

    /** @var int The key of the user who dispatches. */
    private const int USER_ID = 42;

    /**
     * Surface a failure inside a route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();
    }

    /**
     * A sync job's record has the queue origin and its class, with the request
     * id and actor of the request that dispatched it, and no route of its own.
     *
     * @return void
     */
    public function testASyncJobRecordsQueueTheJobClassAndTheDispatchersRequestIdAndActor(): void
    {
        $this->getRouteRunning(static function (): void {
            Bus::dispatchSync(new RecordingJob);
        });

        $job = $this->entry(RecordingJob::CODE);

        self::assertSame('queue', $job->origin);
        self::assertEquals(['job' => RecordingJob::class], $job->context);
        self::assertSame($this->entry(self::BEFORE)->request_id, $job->request_id);
        self::assertSame(StubAuthUser::class, $job->actor_type);
        self::assertSame((string) self::USER_ID, $job->actor_id);
        self::assertSame('web', $job->guard);
    }

    /**
     * When a sync job ends, the request comes back.
     *
     * @return void
     */
    public function testASyncJobRestoresTheRequestOnSuccess(): void
    {
        $this->getRouteRunning(static function (): void {
            Bus::dispatchSync(new RecordingJob);
        });

        $this->assertIsTheRequestsRecord($this->entry(self::AFTER));
    }

    /**
     * When a sync job throws, the request comes back too.
     *
     * @return void
     */
    public function testAFailingSyncJobRestoresTheRequest(): void
    {
        $this->getRouteRunning(static function (): void {
            try {
                Bus::dispatchSync(new ThrowingJob);

                self::fail('Expected the job\'s exception to reach its caller.');
            } catch (\RuntimeException $exception) {
                self::assertSame(ThrowingJob::MESSAGE, $exception->getMessage());
            }
        });

        self::assertSame('queue', $this->entry(ThrowingJob::CODE)->origin);

        $this->assertIsTheRequestsRecord($this->entry(self::AFTER));
    }

    /**
     * When a sync job ends, the command that dispatched it comes back.
     *
     * @return void
     */
    public function testASyncJobRestoresACommandOnSuccess(): void
    {
        $this->nest(static function (): void {
            Bus::dispatchSync(new RecordingJob);
        });

        self::assertEquals(['job' => RecordingJob::class], $this->entry(RecordingJob::CODE)->context);

        $this->assertIsTheCommandsRecord($this->entry(NestingCommand::AFTER));
    }

    /**
     * When a sync job throws, the command that dispatched it comes back too.
     *
     * @return void
     */
    public function testAFailingSyncJobRestoresACommand(): void
    {
        $this->nest(static function (): void {
            Bus::dispatchSync(new ThrowingJob);
        });

        self::assertEquals(['job' => ThrowingJob::class], $this->entry(ThrowingJob::CODE)->context);

        $this->assertIsTheCommandsRecord($this->entry(NestingCommand::AFTER));
    }

    /**
     * A sync job inside a sync job gives the outer one back, and the stack is
     * empty when the outer one ends.
     *
     * @return void
     */
    public function testANestedSyncJobRestoresTheOuterJob(): void
    {
        Bus::dispatchSync(new DispatchingJob(new RecordingJob));

        self::assertEquals(['job' => RecordingJob::class], $this->entry(RecordingJob::CODE)->context);
        self::assertEquals(['job' => DispatchingJob::class], $this->entry(DispatchingJob::BEFORE)->context);
        self::assertEquals(['job' => DispatchingJob::class], $this->entry(DispatchingJob::AFTER)->context);
        self::assertSame('queue', $this->entry(DispatchingJob::AFTER)->origin);
        self::assertNull(app(ExecutionFrames::class)->current());

        $this->assertShareOneRequestId(DispatchingJob::BEFORE, RecordingJob::CODE, DispatchingJob::AFTER);
    }

    /**
     * An inner sync job that throws gives the outer one back as well.
     *
     * @return void
     */
    public function testAFailingNestedSyncJobRestoresTheOuterJob(): void
    {
        Bus::dispatchSync(new DispatchingJob(new ThrowingJob));

        self::assertEquals(['job' => ThrowingJob::class], $this->entry(ThrowingJob::CODE)->context);
        self::assertEquals(['job' => DispatchingJob::class], $this->entry(DispatchingJob::AFTER)->context);
        self::assertNull(app(ExecutionFrames::class)->current());

        $this->assertShareOneRequestId(DispatchingJob::BEFORE, ThrowingJob::CODE, DispatchingJob::AFTER);
    }

    /**
     * A route running a job running a job gets each frame back in turn, with
     * one request id all the way down and up again.
     *
     * @return void
     */
    public function testARouteOuterJobAndInnerJobEachGetTheirFrameBack(): void
    {
        $this->getRouteRunning(static function (): void {
            Bus::dispatchSync(new DispatchingJob(new RecordingJob));
        });

        self::assertEquals(['job' => DispatchingJob::class], $this->entry(DispatchingJob::BEFORE)->context);
        self::assertEquals(['job' => RecordingJob::class], $this->entry(RecordingJob::CODE)->context);
        self::assertEquals(['job' => DispatchingJob::class], $this->entry(DispatchingJob::AFTER)->context);

        $this->assertIsTheRequestsRecord($this->entry(self::AFTER));
        $this->assertShareOneRequestId(self::BEFORE, DispatchingJob::BEFORE, RecordingJob::CODE, DispatchingJob::AFTER, self::AFTER);
    }

    /**
     * Rows of `[inner job, code it records]`: an inner job that succeeds and
     * one that throws.
     *
     * @return iterable<string, array{0: \Illuminate\Contracts\Queue\ShouldQueue, 1: string}>
     */
    public static function provideInnerJobs(): iterable
    {
        yield from [
            'an inner job that succeeds' => [new RecordingJob, RecordingJob::CODE],
            'an inner job that throws'   => [new ThrowingJob, ThrowingJob::CODE],
        ];
    }

    /**
     * Laravel hydrates an inner sync job's payload into the one Context, and
     * that snapshot stays there when it ends. The outer job's records go on
     * naming the actor it carried, and not whoever it signed in for the inner
     * job, on success and on failure.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $inner
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideInnerJobs')]
    public function testANestedSyncJobDoesNotReplaceTheOuterJobsCarriedActor(ShouldQueue $inner, string $code): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::dispatchSync(new DispatchingJob($inner, signsInAs: 7));

        self::assertSame((string) self::USER_ID, $this->entry(DispatchingJob::BEFORE)->actor_id);
        self::assertSame('7', $this->entry($code)->actor_id);
        self::assertSame((string) self::USER_ID, $this->entry(DispatchingJob::AFTER)->actor_id);
        self::assertSame('web', $this->entry(DispatchingJob::AFTER)->guard);
    }

    /**
     * What the outer job sends on afterwards carries its own actor, and not the
     * one the inner job's payload left in Context.
     *
     * @return void
     */
    public function testWhatAnOuterJobSendsOnCarriesItsOwnActor(): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::dispatchSync(new DispatchingJob(new RecordingJob, signsInAs: 7, then: new RecordingJob('job.sent_on')));

        self::assertSame((string) self::USER_ID, $this->entry('job.sent_on')->actor_id);
    }

    /**
     * An outer job that carried nobody goes on having nobody once an inner job
     * that had someone has ended.
     *
     * @return void
     */
    public function testAnOuterJobThatCarriedNoActorStaysWithoutOne(): void
    {
        Bus::dispatchSync(new DispatchingJob(new RecordingJob, signsInAs: 7));

        self::assertSame('7', $this->entry(RecordingJob::CODE)->actor_id);
        self::assertNull($this->entry(DispatchingJob::AFTER)->actor_id);
        self::assertNull($this->entry(DispatchingJob::AFTER)->guard);
    }

    /**
     * A listener on `JobProcessed` that a provider's `boot()` adds runs before
     * the frame ends, so what it records is the job's, with the job's origin,
     * name and dispatcher.
     *
     * @return void
     */
    public function testAListenerOnJobProcessedRunsInTheJobFrame(): void
    {
        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        $this->getRouteRunning(static function (): void {
            Bus::dispatchSync(new RecordingJob);
        });

        $entry = $this->entry(AuditsFrameEndsProvider::JOB_PROCESSED);

        self::assertSame('queue', $entry->origin);
        self::assertEquals(['job' => RecordingJob::class], $entry->context);
        self::assertSame((string) self::USER_ID, $entry->actor_id);
        self::assertSame($this->entry(self::BEFORE)->request_id, $entry->request_id);
        self::assertNull($entry->ip);

        $this->assertIsTheRequestsRecord($this->entry(self::AFTER));
    }

    /**
     * On the sync connection `JobExceptionOccurred` comes first, and its
     * listeners run before the frame ends. `JobFailed` comes after that, so
     * `Queue::failing()` runs in the caller's frame, as the `failed()` hook
     * does: pinned, and documented.
     *
     * @return void
     */
    public function testListenersOnAFailedSyncJobRunEitherSideOfTheFramesEnd(): void
    {
        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        $this->getRouteRunning(static function (): void {
            try {
                Bus::dispatchSync(new ThrowingJob);
            } catch (\RuntimeException) {
                // The listeners have run by the time the exception reaches the
                // caller
            }
        });

        $exception = $this->entry(AuditsFrameEndsProvider::JOB_EXCEPTION);

        self::assertSame('queue', $exception->origin);
        self::assertEquals(['job' => ThrowingJob::class], $exception->context);

        $this->assertIsTheRequestsRecord($this->entry(AuditsFrameEndsProvider::JOB_FAILED));
    }

    /**
     * Inside a request, a job's record has no client, method or route: the job
     * is not the request.
     *
     * @return void
     */
    public function testAJobFillsNoClient(): void
    {
        $this->getRouteRunning(static function (): void {
            Bus::dispatchSync(new RecordingJob);
        }, userAgent: 'Example/1.0');

        $job = $this->entry(RecordingJob::CODE);

        self::assertNull($job->ip);
        self::assertNull($job->user_agent);
        self::assertSame('Example/1.0', $this->entry(self::BEFORE)->user_agent);
    }

    /**
     * Dispatching before the request's first record still gives the job the
     * request's id: it is generated at dispatch and kept.
     *
     * @return void
     */
    public function testDispatchingBeforeTheFirstRecordCarriesTheRequestId(): void
    {
        Route::get('/run', static function (): string {
            Bus::dispatchSync(new RecordingJob);

            return AuditLog::record(self::AFTER)->id;
        });

        $this->get('/run')->assertOk();

        self::assertNotNull($this->entry(RecordingJob::CODE)->request_id);
        self::assertSame($this->entry(RecordingJob::CODE)->request_id, $this->entry(self::AFTER)->request_id);
    }

    /**
     * On the sync connection a job's `failed()` hook runs in its caller's
     * frame, because `JobExceptionOccurred` comes first there: pinned, and
     * documented rather than worked around.
     *
     * @return void
     */
    public function testTheFailedHookOnTheSyncConnectionRunsInTheCallersFrame(): void
    {
        $this->getRouteRunning(static function (): void {
            try {
                Bus::dispatchSync(new FailedHookJob);
            } catch (\RuntimeException) {
                // The hook has run by the time the exception reaches the caller
            }
        });

        $this->assertIsTheRequestsRecord($this->entry(FailedHookJob::CODE));
    }

    /**
     * A sync job leaves its snapshot in Context. A caller who has signed out
     * since must not send it on: the next job has no actor.
     *
     * @return void
     */
    public function testASignedOutCallerSendsNoActorAfterAnEarlierSyncJob(): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::dispatchSync(new RecordingJob('job.first'));

        Auth::guard('web')->forgetUser();

        Bus::dispatchSync(new RecordingJob('job.second'));

        self::assertSame((string) self::USER_ID, $this->entry('job.first')->actor_id);
        self::assertNull($this->entry('job.second')->actor_id);
        self::assertNull($this->entry('job.second')->guard);
    }

    /**
     * A snapshot left in Context by a sync job is never the caller's own actor
     * once its guard has signed out: only a job reads it.
     *
     * @return void
     */
    public function testALeftBehindSnapshotIsIgnoredOutsideAJob(): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::dispatchSync(new RecordingJob);

        Auth::guard('web')->forgetUser();

        AuditLog::record(self::AFTER);

        self::assertNull($this->entry(self::AFTER)->actor_id);
        self::assertNull($this->entry(self::AFTER)->guard);
    }

    /**
     * A second user signed in on the caller replaces the snapshot a first job
     * left behind.
     *
     * @return void
     */
    public function testAnotherCallerReplacesAnEarlierSnapshot(): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::dispatchSync(new RecordingJob('job.first'));

        Auth::guard('web')->setUser(self::user(7));

        Bus::dispatchSync(new RecordingJob('job.second'));

        self::assertSame('7', $this->entry('job.second')->actor_id);
    }

    /**
     * List the provider that audits a job's end, booted after the package's as
     * an application's is.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [...parent::getPackageProviders($app), AuditsFrameEndsProvider::class];
    }

    /**
     * Serve a request whose route signs a user in, records, runs the work and
     * records again.
     *
     * @param  \Closure(): void  $work
     * @param  ?string  $userAgent
     * @return void
     */
    private function getRouteRunning(\Closure $work, ?string $userAgent = null): void
    {
        Route::get('/run', static function () use ($work): string {
            Auth::guard('web')->setUser(self::user());

            AuditLog::record(self::BEFORE);

            $work();

            AuditLog::record(self::AFTER);

            return 'ok';
        })->name('run');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP]);

        if ($userAgent !== null) {
            $this->withHeader('User-Agent', $userAgent);
        }

        $this->get('/run')->assertOk();
    }

    /**
     * Register and run a nesting command around the inner work.
     *
     * @param  \Closure(): void  $inner
     * @return void
     */
    private function nest(\Closure $inner): void
    {
        Artisan::registerCommand(new NestingCommand($inner));

        self::assertSame(0, Artisan::call(NestingCommand::NAME));
    }

    /**
     * Assert the entry was recorded in the request, not in a job.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return void
     */
    private function assertIsTheRequestsRecord(AuditEntry $entry): void
    {
        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'run'], $entry->context);
    }

    /**
     * Assert the entries under the codes share one request id.
     *
     * @param  string  ...$codes
     * @return void
     */
    private function assertShareOneRequestId(string ...$codes): void
    {
        $requestId = $this->entry($codes[0])->request_id;

        self::assertNotNull($requestId);

        foreach ($codes as $code) {
            self::assertSame($requestId, $this->entry($code)->request_id, $code);
        }
    }

    /**
     * Assert the entry was recorded in the nesting command, not in a job.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return void
     */
    private function assertIsTheCommandsRecord(AuditEntry $entry): void
    {
        self::assertSame('console', $entry->origin);
        self::assertEquals(['command' => NestingCommand::NAME], $entry->context);
    }

    /**
     * The one entry stored under the code.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function entry(string $code): AuditEntry
    {
        return AuditEntry::query()->where('event', $code)->sole();
    }

    /**
     * A user a guard can hold, never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id = self::USER_ID): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
    }
}
