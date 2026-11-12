<?php

declare(strict_types = 1);

namespace Tests\Integration\Queue;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Tests\Fixtures\Jobs\DispatchingJob;
use Tests\Fixtures\Jobs\FailedHookJob;
use Tests\Fixtures\Jobs\RecordingJob;
use Tests\Fixtures\Jobs\ThrowingJob;
use Tests\Fixtures\Providers\AuditsFrameEndsProvider;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for what jobs a real database-queue worker runs carry; no
 * user table exists, so resolving a carried actor fails the job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CarryContextIntoJobs::class)]
#[CoversClass(TrackJobFrames::class)]
#[CoversClass(ActorContributor::class)]
#[CoversClass(RequestIdentity::class)]
#[CoversClass(CarriedContext::class)]
final class WorkerContextTest extends TestCase
{
    /** @var string The key under which the payload carries Context. */
    private const string PAYLOAD_CONTEXT = 'illuminate:log:context';

    /** @var string The table a saved user lives in, for the one test that needs it. */
    private const string USERS_TABLE = 'stub_auth_users';

    /** @var string A valid W3C trace id. */
    private const string TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

    /** @var string What a UUID version 7 looks like. */
    private const string UUID7 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /** @var string The peer every request comes from in a test. */
    private const string PEER = '127.0.0.1';

    /** @var int The key of the user who dispatches. */
    private const int USER_ID = 42;

    /**
     * Create the queue's table and surface failures inside routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();

        Schema::dropIfExists('jobs');

        Schema::create('jobs', static function (Blueprint $table): void {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });
    }

    /**
     * Drop the tables, and put the trusted proxies back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('jobs');
        Schema::dropIfExists(self::USERS_TABLE);

        TrustProxies::flushState();
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

    /**
     * A job records the dispatcher's request id, actor and guard.
     *
     * @return void
     */
    public function testAJobRecordsTheDispatchersRequestIdAndActor(): void
    {
        Route::get('/dispatch', static function (): string {
            Auth::guard('web')->setUser(self::user());

            Bus::dispatch(new RecordingJob);

            return AuditLog::record('route.recorded')->id;
        });

        $this->get('/dispatch')->assertOk();

        $this->startTheWorkersSide();
        $this->runTheWorker();

        $job = $this->entry(RecordingJob::CODE);

        self::assertFalse(Auth::guard('web')->hasUser());
        self::assertSame('queue', $job->origin);
        self::assertEquals(['job' => RecordingJob::class], $job->context);
        self::assertSame($this->entry('route.recorded')->request_id, $job->request_id);
        self::assertSame(StubAuthUser::class, $job->actor_type);
        self::assertSame((string) self::USER_ID, $job->actor_id);
        self::assertSame('web', $job->guard);
        self::assertNull($job->ip);
    }

    /**
     * A trusted trace id reaches the job's records.
     *
     * @return void
     */
    public function testTheTraceIdTravels(): void
    {
        TrustProxies::at(self::PEER);

        app(ConfigRepository::class)->set('audit-log.context.trust_traceparent', true);

        Route::get('/dispatch', static function (): string {
            Bus::dispatch(new RecordingJob);

            return 'ok';
        });

        $this->withHeader('traceparent', '00-' . self::TRACE_ID . '-b7ad6b7169203331-01')->get('/dispatch')->assertOk();

        $this->startTheWorkersSide();
        $this->runTheWorker();

        self::assertSame(self::TRACE_ID, $this->entry(RecordingJob::CODE)->trace_id);
    }

    /**
     * A job's records still name an actor deleted after dispatch.
     *
     * @return void
     */
    public function testAJobKeepsTheActorAfterItIsDeleted(): void
    {
        Schema::create(self::USERS_TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->timestamps();
        });

        $user = new StubAuthUser;

        $user->save();

        $id = $user->getKey();

        self::assertIsInt($id);

        $this->dispatchAs($user, new RecordingJob);

        $user->delete();

        self::assertSame(0, DB::table(self::USERS_TABLE)->count());

        $this->runTheWorker();

        $entry = $this->entry(RecordingJob::CODE);

        self::assertSame(StubAuthUser::class, $entry->actor_type);
        self::assertSame((string) $id, $entry->actor_id);
    }

    /**
     * The carried actor is never resolved: no user query, no guard holding one.
     *
     * @return void
     */
    public function testTheCarriedActorIsNeverResolved(): void
    {
        $this->dispatchAs(self::user(), new RecordingJob);

        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $this->runTheWorker();

        self::assertSame((string) self::USER_ID, $this->entry(RecordingJob::CODE)->actor_id);
        self::assertNotSame([], $queries);

        foreach ($queries as $sql) {
            self::assertDoesNotMatchRegularExpression('/(from|join)\W+\w*users\b/i', $sql);
        }

        self::assertFalse(Auth::guard('web')->hasUser());
    }

    /**
     * Two jobs in one worker each keep their own request id and actor.
     *
     * @return void
     */
    public function testTwoJobsInOneWorkerShareNoState(): void
    {
        $first  = $this->dispatchAs(self::user(1), new RecordingJob('job.first'));
        $second = $this->dispatchAs(self::user(2), new RecordingJob('job.second'));
        $third  = $this->dispatchAs(null, new RecordingJob('job.third'));

        $this->runTheWorker(3);

        self::assertSame($first, $this->entry('job.first')->request_id);
        self::assertSame('1', $this->entry('job.first')->actor_id);
        self::assertSame($second, $this->entry('job.second')->request_id);
        self::assertSame('2', $this->entry('job.second')->actor_id);
        self::assertSame($third, $this->entry('job.third')->request_id);
        self::assertNull($this->entry('job.third')->actor_id);
        self::assertNull($this->entry('job.third')->guard);
    }

    /**
     * A payload with no Context gives no actor and a fresh request id.
     *
     * @return void
     */
    public function testAJobWithNoEnvelopeHasNoActorAndAFreshRequestId(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new RecordingJob);

        $this->rewritePayload(static function (array $payload): array {
            unset($payload[self::PAYLOAD_CONTEXT]);

            return $payload;
        });

        $this->runTheWorker();

        $entry = $this->entry(RecordingJob::CODE);

        self::assertNull($entry->actor_id);
        self::assertNull($entry->guard);
        self::assertNotSame($dispatcher, $entry->request_id);
        self::assertMatchesRegularExpression(self::UUID7, (string) $entry->request_id);
    }

    /**
     * Rows of `[hidden Context values]`: malformed or incomplete envelopes.
     *
     * @return iterable<string, array{0: array<string, array<array-key, string>|bool|int|string|null>}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        $type  = CarriedContext::ACTOR_TYPE;
        $id    = CarriedContext::ACTOR_ID;
        $guard = CarriedContext::ACTOR_GUARD;

        yield from [
            'no type'             => [[$id => '42', $guard => 'web']],
            'no id'               => [[$type => 'user', $guard => 'web']],
            'no guard'            => [[$type => 'user', $id => '42']],
            'a type not a string' => [[$type => 7, $id => '42', $guard => 'web']],
            'an id not a string'  => [[$type => 'user', $id => 42, $guard => 'web']],
            'an id as a list'     => [[$type => 'user', $id => ['42'], $guard => 'web']],
            'a null guard'        => [[$type => 'user', $id => '42', $guard => null]],
            'a boolean guard'     => [[$type => 'user', $id => '42', $guard => true]],
            'an empty type'       => [[$type => '', $id => '42', $guard => 'web']],
            'an empty id'         => [[$type => 'user', $id => '', $guard => 'web']],
            'an empty guard'      => [[$type => 'user', $id => '42', $guard => '']],
            'a dirty guard'       => [[$type => 'user', $id => '42', $guard => "we\x01b"]],
            'a long guard'        => [[$type => 'user', $id => '42', $guard => str_repeat('g', 65)]],
            'a long type'         => [[$type => str_repeat('t', 1000), $id => '42', $guard => 'web']],
        ];
    }

    /**
     * A malformed envelope is ignored: the job records no actor or guard.
     *
     * @param  array<string, array<array-key, string>|bool|int|string|null>  $hidden
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testEachMalformedEnvelopeIsIgnored(array $hidden): void
    {
        $this->dispatchAs(null, new RecordingJob);

        $this->rewriteHiddenContext($hidden);

        $this->runTheWorker();

        $entry = $this->entry(RecordingJob::CODE);

        self::assertNull($entry->actor_type);
        self::assertNull($entry->actor_id);
        self::assertNull($entry->guard);
        self::assertSame('queue', $entry->origin);
    }

    /**
     * Rows of `[request id]`: what a carried request id must not be.
     *
     * @return iterable<string, array{0: array<array-key, string>|int|string|null}>
     */
    public static function provideMalformedCarriedRequestIds(): iterable
    {
        yield from [
            'a number' => [123],
            'null'     => [null],
            'a list'   => [['id']],
            'a space'  => ['carried id'],
            'too long' => [str_repeat('a', 65)],
        ];
    }

    /**
     * A malformed carried request id is replaced with a generated one.
     *
     * @param  array<array-key, string>|int|string|null  $requestId
     * @return void
     */
    #[DataProvider('provideMalformedCarriedRequestIds')]
    public function testEachMalformedCarriedRequestIdIsReplaced(array|int|string|null $requestId): void
    {
        $this->dispatchAs(null, new RecordingJob);

        $this->rewriteHiddenContext([CarriedContext::REQUEST_ID => $requestId]);

        $this->runTheWorker();

        self::assertMatchesRegularExpression(self::UUID7, (string) $this->entry(RecordingJob::CODE)->request_id);
    }

    /**
     * Rows of `[trace id]`: what a carried trace id must not be.
     *
     * @return iterable<string, array{0: int|string|null}>
     */
    public static function provideMalformedCarriedTraceIds(): iterable
    {
        yield from [
            'a number'   => [123],
            'null'       => [null],
            'upper case' => [strtoupper(self::TRACE_ID)],
            'all zeros'  => [str_repeat('0', 32)],
            'too short'  => ['0af76519'],
        ];
    }

    /**
     * A malformed carried trace id gives no trace id.
     *
     * @param  int|string|null  $traceId
     * @return void
     */
    #[DataProvider('provideMalformedCarriedTraceIds')]
    public function testEachMalformedCarriedTraceIdIsIgnored(int|string|null $traceId): void
    {
        $this->dispatchAs(null, new RecordingJob);

        $this->rewriteHiddenContext([CarriedContext::TRACE_ID => $traceId]);

        $this->runTheWorker();

        self::assertNull($this->entry(RecordingJob::CODE)->trace_id);
    }

    /**
     * Each job of a chain keeps the identity of whoever dispatched the chain.
     *
     * @return void
     */
    public function testAChainedJobKeepsTheDispatchersIdentity(): void
    {
        Auth::guard('web')->setUser(self::user());

        Bus::chain([new RecordingJob('job.first'), new RecordingJob('job.second')])->dispatch();

        $dispatcher = Context::getHidden(CarriedContext::REQUEST_ID);

        $this->startTheWorkersSide();
        $this->runTheWorker(2);

        foreach (['job.first', 'job.second'] as $code) {
            $entry = $this->entry($code);

            self::assertSame($dispatcher, $entry->request_id, $code);
            self::assertSame((string) self::USER_ID, $entry->actor_id, $code);
            self::assertSame('web', $entry->guard, $code);
        }
    }

    /**
     * A sync job in a worker's job keeps the actor; the outer frame returns.
     *
     * @return void
     */
    public function testASyncJobInsideAWorkersJobKeepsTheCarriedIdentity(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new DispatchingJob(new RecordingJob));

        $this->runTheWorker();

        $inner = $this->entry(RecordingJob::CODE);
        $after = $this->entry(DispatchingJob::AFTER);

        self::assertSame((string) self::USER_ID, $inner->actor_id);
        self::assertSame($dispatcher, $inner->request_id);
        self::assertSame((string) self::USER_ID, $after->actor_id);
        self::assertSame('web', $after->guard);
        self::assertSame($dispatcher, $after->request_id);
        self::assertEquals(['job' => DispatchingJob::class], $after->context);
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
     * An inner sync job's Context leaves the outer job's actor unchanged.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $inner
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideInnerJobs')]
    public function testANestedSyncJobDoesNotReplaceTheOuterJobsCarriedActor(ShouldQueue $inner, string $code): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new DispatchingJob($inner, signsInAs: 7));

        $this->runTheWorker();

        self::assertSame((string) self::USER_ID, $this->entry(DispatchingJob::BEFORE)->actor_id);
        self::assertSame('7', $this->entry($code)->actor_id);
        self::assertSame((string) self::USER_ID, $this->entry(DispatchingJob::AFTER)->actor_id);
        self::assertSame('web', $this->entry(DispatchingJob::AFTER)->guard);
        self::assertSame($dispatcher, $this->entry(DispatchingJob::AFTER)->request_id);
    }

    /**
     * What the outer job dispatches afterwards carries its own actor.
     *
     * @return void
     */
    public function testWhatAnOuterJobSendsOnCarriesItsOwnActor(): void
    {
        $this->dispatchAs(self::user(), new DispatchingJob(new RecordingJob, signsInAs: 7, then: new RecordingJob('job.sent_on')));

        $this->runTheWorker();

        self::assertSame((string) self::USER_ID, $this->entry('job.sent_on')->actor_id);
    }

    /**
     * An envelope-less job after one with an envelope gets a fresh request id.
     *
     * @return void
     */
    public function testAJobWithNoEnvelopeAfterOneWithAnEnvelopeHasAFreshRequestId(): void
    {
        $first = $this->dispatchAs(self::user(), new RecordingJob('job.first'));

        $this->dispatchAs(null, new RecordingJob('job.second'));

        DB::table('jobs')->orderByDesc('id')->limit(1)->get()->each(function (object $row): void {
            $payload = json_decode($row->payload, true, flags: JSON_THROW_ON_ERROR);

            unset($payload[self::PAYLOAD_CONTEXT]);

            DB::table('jobs')->where('id', $row->id)->update(['payload' => json_encode($payload, JSON_THROW_ON_ERROR)]);
        });

        $this->runTheWorker(2);

        self::assertSame($first, $this->entry('job.first')->request_id);
        self::assertNotSame($first, $this->entry('job.second')->request_id);
        self::assertMatchesRegularExpression(self::UUID7, (string) $this->entry('job.second')->request_id);
    }

    /**
     * A `JobProcessed` listener added in `boot()` runs in the job's frame.
     *
     * @return void
     */
    public function testAListenerOnJobProcessedRunsInTheJobFrame(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new RecordingJob);

        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        $this->runTheWorker();

        $this->assertIsTheJobsRecord($this->entry(AuditsFrameEndsProvider::JOB_PROCESSED), RecordingJob::class, $dispatcher);
    }

    /**
     * `JobExceptionOccurred` for a job failed for good runs outside the frame.
     *
     * @return void
     */
    public function testListenersOnAJobThatFailsForGoodRunEitherSideOfTheFramesEnd(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new ThrowingJob);

        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        $this->runTheWorker();

        $this->assertIsTheJobsRecord($this->entry(AuditsFrameEndsProvider::JOB_FAILED), ThrowingJob::class, $dispatcher);

        $exception = $this->entry(AuditsFrameEndsProvider::JOB_EXCEPTION);

        self::assertSame('console', $exception->origin);
        self::assertNull($exception->context);
        self::assertNull($exception->actor_id);
    }

    /**
     * `JobExceptionOccurred` for a job to be retried runs in the job's frame.
     *
     * @return void
     */
    public function testAListenerOnJobExceptionOccurredOfAJobToBeRetriedRunsInTheJobFrame(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new ThrowingJob);

        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        $this->runTheWorker(maxTries: 2);

        $this->assertIsTheJobsRecord($this->entry(AuditsFrameEndsProvider::JOB_EXCEPTION), ThrowingJob::class, $dispatcher);
        self::assertSame(0, AuditEntry::query()->where('event', AuditsFrameEndsProvider::JOB_FAILED)->count());
        self::assertNull(app(ExecutionFrames::class)->current());
    }

    /**
     * A failing job leaves no frame for the next job.
     *
     * @return void
     */
    public function testAFailingJobLeavesNoFrameForTheNext(): void
    {
        $this->dispatchAs(self::user(), new ThrowingJob);
        $this->dispatchAs(null, new RecordingJob);

        $this->runTheWorker(2);

        self::assertEquals(['job' => ThrowingJob::class], $this->entry(ThrowingJob::CODE)->context);
        self::assertEquals(['job' => RecordingJob::class], $this->entry(RecordingJob::CODE)->context);
        self::assertNull($this->entry(RecordingJob::CODE)->actor_id);
        self::assertNull(app(ExecutionFrames::class)->current());
    }

    /**
     * In a worker, a job's `failed()` hook runs in the job's frame.
     *
     * @return void
     */
    public function testTheFailedHookInAWorkerRunsInTheJobFrame(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new FailedHookJob);

        $this->runTheWorker();

        $entry = $this->entry(FailedHookJob::CODE);

        self::assertSame('queue', $entry->origin);
        self::assertEquals(['job' => FailedHookJob::class], $entry->context);
        self::assertSame((string) self::USER_ID, $entry->actor_id);
        self::assertSame($dispatcher, $entry->request_id);
        self::assertNull(app(ExecutionFrames::class)->current());
    }

    /**
     * Forgetting scoped instances between jobs leaves no frame behind.
     *
     * @return void
     */
    public function testForgettingScopedInstancesBetweenJobsLeavesNoFrame(): void
    {
        $this->dispatchAs(self::user(), new ThrowingJob);
        $this->dispatchAs(self::user(7), new RecordingJob);

        $this->runTheWorker();

        $frames = app(ExecutionFrames::class);

        $this->startTheWorkersSide();

        self::assertNull($frames->current());
        self::assertNotSame($frames, app(ExecutionFrames::class));

        $this->runTheWorker();

        self::assertSame('7', $this->entry(RecordingJob::CODE)->actor_id);
        self::assertEquals(['job' => RecordingJob::class], $this->entry(RecordingJob::CODE)->context);
        self::assertNull(app(ExecutionFrames::class)->current());
    }

    /**
     * Only the package's state is reset; the app's Context is untouched.
     *
     * @return void
     */
    public function testOnlyThePackagesStateIsReset(): void
    {
        Context::add('application_key', 'application-value');
        Context::addHidden('application_hidden_key', 'application-hidden-value');

        $this->dispatchAs(self::user(), new RecordingJob);

        $this->runTheWorker();

        self::assertSame('application-value', Context::get('application_key'));
        self::assertSame('application-hidden-value', Context::getHidden('application_hidden_key'));
        self::assertNull(app(ExecutionFrames::class)->current());
    }

    /**
     * The carried envelope is in the payload unencrypted, as documented.
     *
     * @return void
     */
    public function testTheHiddenEnvelopeIsInThePayloadUnencrypted(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new RecordingJob);

        $hidden = $this->hiddenContext();

        self::assertSame($dispatcher, unserialize($hidden[CarriedContext::REQUEST_ID]));
        self::assertSame(StubAuthUser::class, unserialize($hidden[CarriedContext::ACTOR_TYPE]));
        self::assertSame((string) self::USER_ID, unserialize($hidden[CarriedContext::ACTOR_ID]));
        self::assertSame('web', unserialize($hidden[CarriedContext::ACTOR_GUARD]));
    }

    /**
     * A guard Laravel keeps between jobs does not make the next job's actor.
     *
     * @return void
     */
    public function testAGuardAJobLeavesSignedInDoesNotNameTheNextJob(): void
    {
        $this->dispatchAs(null, new RecordingJob('job.signs_in', signsInAs: 7));
        $this->dispatchAs(self::user(), new RecordingJob('job.next'));

        $this->runTheWorker(2);

        self::assertSame('7', $this->entry('job.signs_in')->actor_id);
        self::assertSame((string) self::USER_ID, $this->entry('job.next')->actor_id);
        self::assertSame('web', $this->entry('job.next')->guard);
        self::assertTrue(Auth::guard('web')->hasUser());
        self::assertSame(7, Auth::guard('web')->user()?->getAuthIdentifier());
    }

    /**
     * A job with no snapshot has no actor after a job left a guard signed in.
     *
     * @return void
     */
    public function testAGuardAJobLeavesSignedInGivesAJobWithNoSnapshotNoActor(): void
    {
        $this->dispatchAs(null, new RecordingJob('job.signs_in', signsInAs: 7));
        $this->dispatchAs(null, new RecordingJob('job.next'));

        $this->runTheWorker(2);

        self::assertNull($this->entry('job.next')->actor_id);
        self::assertNull($this->entry('job.next')->guard);
    }

    /**
     * What the next job dispatches is not stamped with the leftover user.
     *
     * @return void
     */
    public function testAGuardAJobLeavesSignedInIsNotCarriedOntoWhatTheNextJobDispatches(): void
    {
        $this->dispatchAs(null, new RecordingJob('job.signs_in', signsInAs: 7));
        $this->dispatchAs(self::user(), new DispatchingJob(new RecordingJob('job.inner')));

        $this->runTheWorker(2);

        self::assertSame((string) self::USER_ID, $this->entry('job.inner')->actor_id);
    }

    /**
     * A user a job signs in itself is its actor, over what it carried.
     *
     * @return void
     */
    public function testAUserAJobSignsInItselfCounts(): void
    {
        $this->dispatchAs(null, new RecordingJob('job.first', signsInAs: 7));
        $this->dispatchAs(self::user(), new RecordingJob('job.another_user', signsInAs: 8));
        $this->dispatchAs(self::user(), new RecordingJob('job.same_user_afresh', signsInAs: 8));
        $this->dispatchAs(self::user(), new RecordingJob('job.last'));

        $this->runTheWorker(4);

        self::assertSame('8', $this->entry('job.another_user')->actor_id);
        self::assertSame('8', $this->entry('job.same_user_afresh')->actor_id);
        self::assertSame((string) self::USER_ID, $this->entry('job.last')->actor_id);
    }

    /**
     * A record after a job fails itself is outside the frame, as documented.
     *
     * @return void
     */
    public function testARecordAfterAJobFailsItselfIsOutsideTheJobFrame(): void
    {
        $dispatcher = $this->dispatchAs(self::user(), new RecordingJob(failsItselfFirst: true));

        $this->runTheWorker();

        $entry = $this->entry(RecordingJob::CODE);

        self::assertSame('console', $entry->origin);
        self::assertNull($entry->context);
        self::assertNull($entry->actor_id);
        self::assertSame($dispatcher, $entry->request_id);
    }

    /**
     * Configure a database queue.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * Register the provider auditing a job's end, booted after the package's.
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
     * Assert the entry has the job's origin and name, and what it carried.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @param  class-string  $job
     * @param  string  $dispatcher
     * @return void
     */
    private function assertIsTheJobsRecord(AuditEntry $entry, string $job, string $dispatcher): void
    {
        self::assertSame('queue', $entry->origin);
        self::assertEquals(['job' => $job], $entry->context);
        self::assertSame((string) self::USER_ID, $entry->actor_id);
        self::assertSame('web', $entry->guard);
        self::assertSame($dispatcher, $entry->request_id);
    }

    /**
     * Dispatch the job as the user or nobody, start the worker; the job's id.
     *
     * @param  ?\Tests\Unit\Stubs\StubAuthUser  $user
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $job
     * @return string
     */
    private function dispatchAs(?StubAuthUser $user, ShouldQueue $job): string
    {
        if ($user !== null) {
            Auth::guard('web')->setUser($user);
        }

        Bus::dispatch($job);

        $requestId = Context::getHidden(CarriedContext::REQUEST_ID);

        self::assertIsString($requestId);

        $this->startTheWorkersSide();

        return $requestId;
    }

    /**
     * Start the worker's side afresh: no guard and new scoped state.
     *
     * @return void
     */
    private function startTheWorkersSide(): void
    {
        Auth::forgetGuards();

        $this->app?->forgetScopedInstances();

        Facade::clearResolvedInstances();
    }

    /**
     * Run the next jobs through a real worker; only their records prove it.
     *
     * @param  int  $jobs
     * @param  int  $maxTries
     * @return void
     */
    private function runTheWorker(int $jobs = 1, int $maxTries = 1): void
    {
        $worker = app('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(sleep: 0, maxTries: $maxTries);

        for ($run = 0; $run < $jobs; $run++) {
            $worker->runNextJob('database', 'default', $options);
        }
    }

    /**
     * Replace what the queued job's payload holds.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(array<array-key, mixed>): array<array-key, mixed>  $rewrite
     * @return void
     */
    private function rewritePayload(\Closure $rewrite): void
    {
        $row = DB::table('jobs')->sole();

        DB::table('jobs')->where('id', $row->id)->update(['payload' => json_encode($rewrite($this->payload()), JSON_THROW_ON_ERROR)]);
    }

    /**
     * Replace the queued job's hidden Context with the values, serialised.
     *
     * @param  array<string, array<array-key, string>|bool|int|string|null>  $hidden
     * @return void
     */
    private function rewriteHiddenContext(array $hidden): void
    {
        $this->rewritePayload(static function (array $payload) use ($hidden): array {
            $payload[self::PAYLOAD_CONTEXT] = ['data' => [], 'hidden' => array_map(serialize(...), $hidden)];

            return $payload;
        });
    }

    /**
     * The queued job's payload, as JSON gives it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     */
    private function payload(): array
    {
        $payload = DB::table('jobs')->sole()->payload;

        self::assertIsString($payload);

        $decoded = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * The hidden Context of the queued job's payload, as it was serialised.
     *
     * @return array<string, string>
     */
    private function hiddenContext(): array
    {
        $context = $this->payload()[self::PAYLOAD_CONTEXT] ?? null;

        self::assertIsArray($context);
        self::assertIsArray($context['hidden']);

        /** @var array<string, string> */
        return $context['hidden'];
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
