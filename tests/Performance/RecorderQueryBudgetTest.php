<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\CachedUser;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\Fixtures\Commands\RecordingCommand;
use Tests\Fixtures\Contributors\QueryingContributor;
use Tests\Fixtures\Jobs\RecordingJob;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Statement-budget contract for the recorder, scoped as its promise is to the
 * default contributors and a fresh insert: resolving the context costs no
 * query, a session holding only a user id included, one record costs one insert
 * and its timing's savepoint, a deferred record costs nothing until the commit,
 * and an application's contributor adds exactly what it runs itself. The
 * listeners on a host's own code paths, which run whether or not it records
 * anything, cost nothing: making a job's payload, and entering and leaving a
 * job or a command, leave only what the job or command runs itself.
 *
 * No `users` table exists, so a guard that tried to load its user would fail
 * the test as well as its budget.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(RecordDelivery::class)]
#[CoversClass(OriginContributor::class)]
#[CoversClass(RequestContributor::class)]
#[CoversClass(ActorContributor::class)]
#[CoversClass(AmbientActor::class)]
#[CoversClass(CachedUser::class)]
#[CoversClass(CarryContextIntoJobs::class)]
#[CoversClass(TrackJobFrames::class)]
#[CoversClass(TrackCommandFrames::class)]
final class RecorderQueryBudgetTest extends PerformanceContractTestCase
{
    use WithConsoleEvents;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The session guard tests sign users into. */
    private const string GUARD = 'web';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::connection()->transactionLevel() > 0) {
            DB::connection()->rollBack();
        }

        parent::tearDown();
    }

    /**
     * The three defaults fill origin, client, request id, actor and guard in an
     * HTTP frame, from a real session guard holding a user, without one
     * statement.
     *
     * @return void
     */
    public function testResolvingTheContextCostsNoQueries(): void
    {
        $this->enterARequest();

        $this->guard()->setUser($this->user());

        $snapshot = $this->assertStatementBudget(0, 0, 0, 0, fn (): PendingSnapshot => $this->contributed());

        self::assertSame([OriginContributor::class, RequestContributor::class, ActorContributor::class], app(ContributorRegistry::class)->classes());
        self::assertSame(Origin::HTTP, $snapshot->origin);
        self::assertSame('203.0.113.9', $snapshot->ip);
        self::assertNotNull($snapshot->requestId);
        self::assertSame('7', $snapshot->actor?->id);
        self::assertSame(self::GUARD, $snapshot->guard);
    }

    /**
     * A session holding a user id is never loaded: the guard still holds no
     * user afterwards and the record has no actor, for no statement.
     *
     * @return void
     */
    public function testASessionHoldingAUserIdCostsNoQueries(): void
    {
        $this->enterARequest();

        $guard = $this->guard();

        $guard->getSession()->put($guard->getName(), 7);

        $snapshot = $this->assertStatementBudget(0, 0, 0, 0, fn (): PendingSnapshot => $this->contributed());

        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->guard);
        self::assertFalse($guard->hasUser());
    }

    /**
     * Making a job's payload costs nothing, from a request whose session holds
     * only a user id, which is never loaded to find out who dispatched.
     *
     * @return void
     */
    public function testMakingAJobsPayloadCostsNoQueries(): void
    {
        $this->enterARequest();

        $guard = $this->guard();

        $guard->getSession()->put($guard->getName(), 7);

        $payload = $this->assertStatementBudget(0, 0, 0, 0, static fn (): ?array => Context::dehydrate());

        self::assertIsArray($payload);
    }

    /**
     * A sync job costs only the insert its own record makes.
     *
     * @return void
     */
    public function testASyncJobCostsOnlyItsOwnInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, static fn () => Bus::dispatchSync(new RecordingJob));
    }

    /**
     * A command costs only the insert its own record makes.
     *
     * @return void
     */
    public function testACommandCostsOnlyItsOwnInsert(): void
    {
        Artisan::registerCommand(new RecordingCommand);

        $this->assertStatementBudget(0, 1, 0, 0, static fn (): int => Artisan::call(RecordingCommand::NAME));
    }

    /**
     * A job starting on a worker notes who the guards hold for nothing, a
     * session holding only a user id included.
     *
     * @return void
     */
    public function testAJobStartingOnAWorkerCostsNoQueries(): void
    {
        $guard = $this->guard();

        $guard->getSession()->put($guard->getName(), 7);

        $job = \Mockery::mock(Job::class);

        $job->shouldReceive('resolveName')->andReturn(RecordingJob::class);

        $this->assertStatementBudget(0, 0, 0, 0, static function () use ($job): void {
            (new TrackJobFrames)(new JobProcessing('database', $job));
        });

        self::assertFalse($guard->hasUser());
    }

    /**
     * An explicit record with no transaction open is one plain insert.
     *
     * @return void
     */
    public function testOneExplicitRecordIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, static fn () => AuditLog::record(self::CODE));
    }

    /**
     * The whole pipeline, in an HTTP frame with a signed-in user, costs the
     * same one insert: filling the context adds nothing to it.
     *
     * @return void
     */
    public function testAnAuthenticatedRequestsRecordIsOneInsert(): void
    {
        $this->enterARequest();

        $this->guard()->setUser($this->user());

        $record = $this->assertStatementBudget(0, 1, 0, 0, static fn () => AuditLog::record(self::CODE));

        self::assertSame('7', $record->actorId);
    }

    /**
     * A disclosure costs what any other record does.
     *
     * @return void
     */
    public function testAnAccessRecordIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, static fn () => AuditLog::accessed('document.downloaded', Reference::of('document', '1'), 'support.ticket', 'portal')->record());
    }

    /**
     * Inside a transaction a default record costs nothing until the commit,
     * when it is one plain insert, outside the transaction, so no savepoint.
     *
     * @return void
     */
    public function testAnExplicitRecordInATransactionCostsNothingUntilCommit(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, static fn () => AuditLog::record(self::CODE));

        $this->assertStatementBudget(0, 1, 0, 0, static fn () => DB::connection()->commit());
    }

    /**
     * A deferred record the host rolls back costs nothing at all.
     *
     * @return void
     */
    public function testADroppedRecordCostsNothing(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 1, static function (): void {
            AuditLog::record(self::CODE);

            DB::connection()->rollBack();
        });
    }

    /**
     * A transactional record is one insert and the savepoint that isolates it.
     *
     * @return void
     */
    public function testATransactionalRecordIsOneInsertAndASavepoint(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, static fn () => AuditLog::event(self::CODE)->transactional()->record());
    }

    /**
     * An immediate record with no transaction open is one plain insert.
     *
     * @return void
     */
    public function testAnImmediateRecordOutsideATransactionIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, static fn () => AuditLog::event(self::CODE)->immediately()->record());
    }

    /**
     * An immediate record inside a transaction adds only the savepoint.
     *
     * @return void
     */
    public function testAnImmediateRecordInsideATransactionAddsOnlyASavepoint(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, static fn () => AuditLog::event(self::CODE)->immediately()->record());
    }

    /**
     * The fake runs the same pipeline and issues no statement, whether the
     * record reaches it at once or on a commit.
     *
     * @return void
     */
    public function testTheFakeCostsNoQueries(): void
    {
        $fake = AuditLog::fake();

        $this->assertStatementBudget(0, 0, 0, 0, static function (): void {
            AuditLog::record(self::CODE);

            DB::connection()->beginTransaction();

            AuditLog::record(self::CODE);

            DB::connection()->commit();
        });

        self::assertSame(2, $fake->count());
    }

    /**
     * A contributor an application registers adds exactly its own read and no
     * more: the promise covers the defaults only, and this says so.
     *
     * @return void
     */
    public function testTheBudgetExcludesAQueryingContributor(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(QueryingContributor::class);

        $recorder = new Recorder(new EventCatalogue, $registry);

        $record = $this->assertStatementBudget(1, 1, 0, 0, static fn () => $recorder->record(self::CODE));

        self::assertSame('select 1', $this->capturedStatements()[0]);
        self::assertSame(['queried' => true], $record->context);
    }

    /**
     * Keep the session in memory, so reading it could not reach a database.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $app->make(ConfigRepository::class)->set('session.driver', 'array');
    }

    /**
     * Enter the HTTP frame of a request, from a client address the contributors
     * can read back.
     *
     * @return void
     */
    private function enterARequest(): void
    {
        app(ExecutionFrames::class)->enterRequest(Request::create('/invoices/7', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9']));
    }

    /**
     * The real session guard tests sign users into.
     *
     * @return \Illuminate\Auth\SessionGuard
     */
    private function guard(): SessionGuard
    {
        return Auth::guard(self::GUARD);
    }

    /**
     * A saved-looking user the guard can hold, with no table behind it.
     *
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private function user(): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => 7]);
    }

    /**
     * What the default contributors fill into a fresh builder, each made from
     * the container as a capture makes it.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private function contributed(): PendingSnapshot
    {
        $pending = (new PendingRecord)->event(self::CODE);

        foreach (app(ContributorRegistry::class)->classes() as $contributor) {
            app($contributor)->contribute(new Contribution($pending));
        }

        return $pending->snapshot();
    }
}
