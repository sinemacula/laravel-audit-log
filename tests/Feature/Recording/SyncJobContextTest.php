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
 * End-to-end tests for a job run on the sync queue inside its dispatcher.
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
     * A sync job records queue, its class, and the dispatcher's id and actor.
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
     * A nested sync job restores the outer one, and the stack ends empty.
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
     * Each frame comes back in turn under one request id.
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
     * Rows of `[inner job, code]`: one that succeeds and one that throws.
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
     * Laravel leaves an inner sync job's snapshot in Context; the outer job
     * still names its own actor.
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
     * What the outer job sends on carries its own actor.
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
     * An outer job that carried no actor keeps none after an inner job ends.
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
     * A `JobProcessed` listener added in `boot()` runs inside the job frame.
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
     * On sync, `JobExceptionOccurred` runs in the job frame and `JobFailed` in
     * the caller's.
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
                // The listeners have run before the exception reaches here
            }
        });

        $exception = $this->entry(AuditsFrameEndsProvider::JOB_EXCEPTION);

        self::assertSame('queue', $exception->origin);
        self::assertEquals(['job' => ThrowingJob::class], $exception->context);

        $this->assertIsTheRequestsRecord($this->entry(AuditsFrameEndsProvider::JOB_FAILED));
    }

    /**
     * A job inside a request has no client, method or route.
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
     * A job dispatched before the request's first record gets the request's id.
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
     * On sync, a job's `failed()` hook runs in its caller's frame.
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
     * A caller who signed out after a sync job sends no actor on.
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
     * A sync job's leftover snapshot is never the signed-out caller's actor.
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
     * A second signed-in user replaces the snapshot a first job left.
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
     * Add the provider that audits a job's end, after the package's.
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
     * Serve a route that signs in, records, runs the work and records again.
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
