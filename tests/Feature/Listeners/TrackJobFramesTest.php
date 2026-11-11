<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Log\Context\Repository;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Context;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the frames jobs enter and leave: the name kept, each ending
 * event, a failed job's two events in either order, the container reached, and
 * that nothing but the package's own state changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrackJobFrames::class)]
final class TrackJobFramesTest extends TestCase
{
    /**
     * Bind the frames as the provider binds them, which it leaves alone once it
     * binds them itself.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->scopedIf(ExecutionFrames::class);
    }

    /**
     * Put the current container back, for a test that replaced it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * A job starting enters a frame with its name, owned by the job.
     *
     * @return void
     */
    public function testJobProcessingEntersAFrameWithItsName(): void
    {
        $job = $this->job(['job' => 'App\Jobs\SendInvoice']);

        (new TrackJobFrames)(new JobProcessing('sync', $job));

        $frame = $this->frames()->current();

        self::assertNotNull($frame);
        self::assertSame('App\Jobs\SendInvoice', $frame->name);
        self::assertSame($job, $frame->owner);
        self::assertSame(Origin::QUEUE, $this->frames()->origin());
        self::assertSame(FrameKind::JOB, $this->frames()->current()?->kind);
    }

    /**
     * A job's display name is kept over the handler that runs it, which is what
     * a queued job's class or `displayName()` becomes in its payload.
     *
     * @return void
     */
    public function testAJobsDisplayNameIsKept(): void
    {
        $job = $this->job(['job' => 'Illuminate\Queue\CallQueuedHandler@call', 'displayName' => 'Send the invoice']);

        (new TrackJobFrames)(new JobProcessing('sync', $job));

        self::assertSame('Send the invoice', $this->frames()->current()?->name);
    }

    /**
     * Rows of `[display name]`: what a queued payload can hold that is not a
     * string, which the framework hands back as it found it.
     *
     * @return iterable<string, array{0: int|list<string>|true}>
     */
    public static function provideNamesThatAreNotStrings(): iterable
    {
        yield from [
            'a number' => [42],
            'a list'   => [['Send the invoice']],
            'a flag'   => [true],
        ];
    }

    /**
     * A job whose display name is not a string still has its frame, so its
     * records say they came from the queue, its end still finds the frame, and
     * a job that can run is not failed by a type error here.
     *
     * @param  int|list<string>|true  $name
     * @return void
     */
    #[DataProvider('provideNamesThatAreNotStrings')]
    public function testAJobWhoseNameIsNotAStringStillEntersAFrame(array|bool|int $name): void
    {
        $job = $this->job(['job' => 'App\Jobs\SendInvoice', 'displayName' => $name]);

        (new TrackJobFrames)(new JobProcessing('sync', $job));

        $frame = $this->frames()->current();

        self::assertNotNull($frame);
        self::assertNull($frame->name);
        self::assertSame(Origin::QUEUE, $this->frames()->origin());

        (new TrackJobFrames)(new JobProcessed('sync', $job));

        self::assertNull($this->frames()->current());
    }

    /**
     * The events that end a job read nothing of its payload, so one that cannot
     * be read still leaves its frame.
     *
     * @return void
     */
    public function testEndingAJobReadsNothingOfItsPayload(): void
    {
        $job = \Mockery::mock(Job::class);
        $job->shouldReceive('resolveName')->once()->andReturn('App\Jobs\SendInvoice');

        (new TrackJobFrames)(new JobProcessing('redis', $job));
        (new TrackJobFrames)(new JobExceptionOccurred('redis', $job, new \RuntimeException('Failed.')));
        (new TrackJobFrames)(new JobFailed('redis', $job, new \RuntimeException('Failed.')));

        self::assertNull($this->frames()->current());
    }

    /**
     * Rows of `[the event ending the job]`: each event that ends a job.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Illuminate\Contracts\Queue\Job): (\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed|\Illuminate\Queue\Events\JobProcessed)}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideEndingEvents(): iterable
    {
        yield from [
            'JobProcessed'         => [static fn (Job $job): JobProcessed => new JobProcessed('sync', $job)],
            'JobFailed'            => [static fn (Job $job): JobFailed => new JobFailed('sync', $job, new \RuntimeException('Failed.'))],
            'JobExceptionOccurred' => [static fn (Job $job): JobExceptionOccurred => new JobExceptionOccurred('sync', $job, new \RuntimeException('Failed.'))],
        ];
    }

    /**
     * Each event that ends a job leaves its frame, and another job's leaves it
     * in place.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Illuminate\Contracts\Queue\Job): (\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed|\Illuminate\Queue\Events\JobProcessed)  $ending
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideEndingEvents')]
    public function testEachEndingEventLeavesIt(\Closure $ending): void
    {
        $job = $this->job(['job' => 'App\Jobs\SendInvoice']);

        (new TrackJobFrames)(new JobProcessing('sync', $job));
        (new TrackJobFrames)($ending($this->job(['job' => 'App\Jobs\SendInvoice'])));

        self::assertSame($job, $this->currentOwner());

        (new TrackJobFrames)($ending($job));

        self::assertNull($this->frames()->current());
    }

    /**
     * Rows of `[first event, second event]`: a failed job's two events, in the
     * order the sync queue fires them and the order a worker does.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: class-string<\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed>, 1: class-string<\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFailureOrders(): iterable
    {
        yield from [
            'on the sync queue' => [JobExceptionOccurred::class, JobFailed::class],
            'on a worker'       => [JobFailed::class, JobExceptionOccurred::class],
        ];
    }

    /**
     * A failed job's two events leave its frame once, in either order, and the
     * frame of the command beneath it survives.
     *
     * @param  class-string<\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed>  $first
     * @param  class-string<\Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed>  $second
     * @return void
     */
    #[DataProvider('provideFailureOrders')]
    public function testBothFailureEventsLeaveOnlyOnce(string $first, string $second): void
    {
        $command = new \stdClass;
        $job     = $this->job(['job' => 'App\Jobs\SendInvoice']);

        $this->frames()->enterCommand($command, 'invoices:send');

        (new TrackJobFrames)(new JobProcessing('sync', $job));
        (new TrackJobFrames)(new $first('sync', $job, new \RuntimeException('Failed.')));

        self::assertSame($command, $this->currentOwner());

        (new TrackJobFrames)(new $second('sync', $job, new \RuntimeException('Failed.')));

        self::assertSame($command, $this->currentOwner());
        self::assertNotSame(FrameKind::JOB, $this->frames()->current()?->kind);
    }

    /**
     * An inner sync job's failure restores the job that dispatched it, which
     * keeps its frame when it goes on to catch the exception.
     *
     * @return void
     */
    public function testAnInnerJobsFailureRestoresTheOuterJob(): void
    {
        $outer = $this->job(['job' => 'App\Jobs\Outer']);
        $inner = $this->job(['job' => 'App\Jobs\Inner']);

        (new TrackJobFrames)(new JobProcessing('sync', $outer));
        (new TrackJobFrames)(new JobProcessing('sync', $inner));
        (new TrackJobFrames)(new JobExceptionOccurred('sync', $inner, new \RuntimeException('Failed.')));
        (new TrackJobFrames)(new JobFailed('sync', $inner, new \RuntimeException('Failed.')));

        self::assertSame($outer, $this->frames()->current()?->owner);
    }

    /**
     * The frames are those of the current container on every event, not those
     * of the container the dispatcher was built with, which is what makes the
     * listener safe under Octane.
     *
     * @return void
     */
    public function testTheFramesOfTheCurrentContainerAreUsed(): void
    {
        $booted  = $this->frames();
        $sandbox = new Container;

        $sandbox->singleton(ExecutionFrames::class);
        $sandbox->instance(Repository::class, app(Repository::class));

        Container::setInstance($sandbox);

        (new TrackJobFrames)(new JobProcessing('sync', $this->job(['job' => 'App\Jobs\SendInvoice'])));

        self::assertNull($booted->current());
        self::assertSame('App\Jobs\SendInvoice', $sandbox->make(ExecutionFrames::class)->current()?->name);
    }

    /**
     * The frame keeps the actor the job carried, read from the Context Laravel
     * has just hydrated, in a worker and on the sync queue alike.
     *
     * @return void
     */
    public function testTheFrameKeepsTheCarriedActor(): void
    {
        CarriedContext::carryActor(app(Repository::class), new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'));

        (new TrackJobFrames)(new JobProcessing('sync', $this->job(['job' => 'App\Jobs\SendInvoice'])));

        $sync = $this->frames()->carriedActor();

        self::assertSame('user-7', $sync?->held->actor->id);

        $job = $this->workerJob();

        (new TrackJobFrames)(new JobProcessing('database', $job));

        $frame = $this->frames()->current();

        self::assertNotNull($frame);
        self::assertSame($job, $frame->owner);
        self::assertSame('user-7', $frame->carried?->held->actor->id);
    }

    /**
     * A malformed envelope is no carried actor, and the job still has its
     * frame.
     *
     * @return void
     */
    public function testAMalformedEnvelopeIsNoCarriedActor(): void
    {
        Context::addHidden(CarriedContext::ACTOR_ID, 7);

        (new TrackJobFrames)(new JobProcessing('database', $this->workerJob()));

        self::assertSame(FrameKind::JOB, $this->frames()->current()?->kind);
        self::assertNull($this->frames()->carriedActor());
    }

    /**
     * A job on a worker notes the very users the guards hold as it starts, none
     * of them its own.
     *
     * @return void
     */
    public function testAJobOnAWorkerNotesTheUsersItFinds(): void
    {
        $user = (new StubAuthUser)->forceFill(['id' => 7]);

        Auth::guard('web')->setUser($user);

        (new TrackJobFrames)(new JobProcessing('database', $this->workerJob()));

        self::assertTrue($this->frames()->isLeftover('web', $user));
    }

    /**
     * A sync job runs inside its caller, so the guards' users are the caller's
     * and none of them is a leftover.
     *
     * @return void
     */
    public function testASyncJobNotesNoUser(): void
    {
        $user = (new StubAuthUser)->forceFill(['id' => 7]);

        Auth::guard('web')->setUser($user);

        (new TrackJobFrames)(new JobProcessing('sync', $this->job(['job' => 'App\Jobs\SendInvoice'])));

        self::assertFalse($this->frames()->isLeftover('web', $user));
    }

    /**
     * A setting or a guard that cannot be read must not stop a job that may
     * record nothing, and the job still has its frame.
     *
     * @return void
     */
    public function testAMalformedSettingDoesNotStopAJobOnAWorker(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        (new TrackJobFrames)(new JobProcessing('database', $this->workerJob()));

        self::assertSame(FrameKind::JOB, $this->frames()->current()?->kind);
    }

    /**
     * A job on a worker forgets the identifiers an earlier job left in the
     * scoped identity, so one with no envelope gets a fresh id.
     *
     * @return void
     */
    public function testAJobOnAWorkerForgetsAnEarlierJobsIdentifiers(): void
    {
        $identity = app(RequestIdentity::class);
        $earlier  = $identity->requestId();

        Context::forgetHidden(CarriedContext::REQUEST_ID);

        (new TrackJobFrames)(new JobProcessing('database', $this->workerJob()));

        self::assertNotSame($earlier, $identity->requestId());
    }

    /**
     * A sync job shares its caller's work, so it keeps the id the caller has.
     *
     * @return void
     */
    public function testASyncJobKeepsItsCallersIdentifiers(): void
    {
        $identity = app(RequestIdentity::class);
        $caller   = $identity->requestId();

        Context::forgetHidden(CarriedContext::REQUEST_ID);

        (new TrackJobFrames)(new JobProcessing('sync', $this->job(['job' => 'App\Jobs\SendInvoice'])));

        self::assertSame($caller, $identity->requestId());
    }

    /**
     * Context is the same after a job's events as before them, since only the
     * package's own state is ever reset.
     *
     * @return void
     */
    public function testContextIsLeftAlone(): void
    {
        Context::add('tenant', 'acme');
        Context::addHidden('audit-log.request_id', 'app:request-1');

        $job = $this->job(['job' => 'App\Jobs\SendInvoice']);

        (new TrackJobFrames)(new JobProcessing('sync', $job));
        (new TrackJobFrames)(new JobProcessed('sync', $job));

        self::assertSame(['tenant' => 'acme'], Context::all());
        self::assertSame(['audit-log.request_id' => 'app:request-1'], Context::allHidden());
    }

    /**
     * Neither event reaches the auth manager, so no guard is read or reset, and
     * a guard a job signed in stays signed in.
     *
     * @return void
     */
    public function testTheGuardsAreLeftAlone(): void
    {
        $auth = \Mockery::mock(AuthManager::class);
        $auth->shouldNotReceive('guard');

        $this->app?->instance('auth', $auth);

        $job = $this->job(['job' => 'App\Jobs\SendInvoice']);

        (new TrackJobFrames)(new JobProcessing('sync', $job));
        (new TrackJobFrames)(new JobProcessed('sync', $job));

        self::assertNull($this->frames()->current());
    }

    /**
     * A job on the sync connection with the given payload.
     *
     * @param  array<string, int|list<string>|string|true>  $payload
     * @return \Illuminate\Queue\Jobs\SyncJob
     */
    private function job(array $payload): SyncJob
    {
        return new SyncJob(Container::getInstance(), (string) json_encode($payload), 'sync', 'default');
    }

    /**
     * A job on a worker: anything that is not Laravel's sync job.
     *
     * @return \Illuminate\Contracts\Queue\Job
     */
    private function workerJob(): Job
    {
        $job = \Mockery::mock(Job::class);

        $job->shouldReceive('resolveName')->andReturn('App\Jobs\SendInvoice');

        return $job;
    }

    /**
     * The owner of the innermost frame, read afresh.
     *
     * @return ?object
     */
    private function currentOwner(): ?object
    {
        return $this->frames()->current()?->owner;
    }

    /**
     * The frames of the application under test.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }
}
