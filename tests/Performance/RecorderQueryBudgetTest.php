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
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
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
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Statement budget for the recorder with the default contributors: a record is
 * one insert, a deferred one costs nothing until commit, and context, listeners
 * and minimising add no query.
 *
 * No `users` table exists, so a guard that loaded its user would fail the test.
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
#[CoversClass(RecordMinimiser::class)]
final class RecorderQueryBudgetTest extends PerformanceContractTestCase
{
    use WithConsoleEvents;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The id of the entry every capture here is minimised as. */
    private const string ENTRY_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

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
     * The defaults fill an HTTP frame's context from a real session guard
     * without a statement.
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
     * A session holding only a user id is never loaded: the record has no
     * actor, for no statement.
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
     * Making a job's payload never loads a session's user id to find who
     * dispatched.
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
     * A job starting on a worker notes who the guards hold for nothing.
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
     * An authenticated request's record is the same one insert: filling the
     * context adds nothing.
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
     * then one plain insert with no savepoint, plus the commit's question on
     * PostgreSQL.
     *
     * @return void
     */
    public function testAnExplicitRecordInATransactionCostsNothingUntilCommit(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, static fn () => AuditLog::record(self::CODE));

        $this->assertStatementBudget($this->commitQuestionReads(), 1, 0, 0, static fn () => DB::connection()->commit());
    }

    /**
     * However many records wait on one commit, it asks that question once.
     *
     * @return void
     */
    public function testRecordsWaitingOnACommitShareItsOneQuestion(): void
    {
        DB::connection()->beginTransaction();

        AuditLog::record(self::CODE);
        AuditLog::record(self::CODE);
        AuditLog::record(self::CODE);

        $this->assertStatementBudget($this->commitQuestionReads(), 3, 0, 0, static fn () => DB::connection()->commit());
    }

    /**
     * A commit with nothing of the audit log waiting on it asks nothing.
     *
     * @return void
     */
    public function testACommitWithNoRecordWaitingAsksNothing(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, static fn () => DB::connection()->commit());
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
     * The fake writes nothing, whether the record reaches it at once or on a
     * commit, whose question is all it adds.
     *
     * @return void
     */
    public function testTheFakeCostsNoQueries(): void
    {
        $fake = AuditLog::fake();

        $this->assertStatementBudget($this->commitQuestionReads(), 0, 0, 0, static function (): void {
            AuditLog::record(self::CODE);

            DB::connection()->beginTransaction();

            AuditLog::record(self::CODE);

            DB::connection()->commit();
        });

        self::assertSame(2, $fake->count());
    }

    /**
     * An application's contributor adds exactly its own read: the budget covers
     * the defaults only.
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
     * A record using every handling costs what a plain record does in a
     * transaction: one insert and its savepoint.
     *
     * @return void
     */
    public function testMinimisingAddsNoQuery(): void
    {
        $pending = $this->fullyMinimisedPending();

        DB::connection()->beginTransaction();

        $record = $this->assertStatementBudget(0, 1, 1, 0, static fn () => $pending->immediately()->record());

        self::assertSame(app(IdentifierHasher::class)->ip('203.0.113.9'), $record->ip);
        self::assertSame(Redactor::MARKER, $record->properties['customer'] ?? null);
        self::assertSame(app(IdentifierHasher::class)->field('alice@example.com'), $record->properties['email'] ?? null);
        self::assertSame(['v' => 1, 'k' => 'key_7', 'c' => base64_encode('"078-05-1120"')], $record->properties['ssn'] ?? null);
        self::assertSame(['v' => 1, 'k' => 'key_7', 'c' => base64_encode('"Erasable."')], $record->properties['_audit']['note'] ?? null);
        self::assertSame(app(IdentifierHasher::class)->identifier('alice@example.com'), $record->properties['_audit']['identifier_hash'] ?? null);
    }

    /**
     * With no transaction open the same record is one plain insert.
     *
     * @return void
     */
    public function testAFullyMinimisedRecordOutsideATransactionIsOneInsert(): void
    {
        $pending = $this->fullyMinimisedPending();

        $this->assertStatementBudget(0, 1, 0, 0, static fn () => $pending->immediately()->record());
    }

    /**
     * The minimiser on its own runs no statement at all.
     *
     * @return void
     */
    public function testTheMinimiserRunsNoStatement(): void
    {
        $snapshot = $this->fullyMinimisedPending()->snapshot();

        $this->assertStatementBudget(0, 0, 0, 0, static fn (): Minimised => app(RecordMinimiser::class)->minimise($snapshot, self::everyHandling(), self::ENTRY_ID));
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
     * A builder using every handling, with a hashed address and an encrypter
     * holding a key for everyone, on a recorder of its own.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private function fullyMinimisedPending(): PendingRecord
    {
        app(ConfigRepository::class)->set('audit-log.redaction.ip', 'hash');

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->define(self::everyHandling());

        $pending = $recorder->event(self::CODE)
            ->by(Reference::of('user', '7'))
            ->withProperties([
                'amount'   => '1200.00',
                'customer' => ['name' => 'Alice Example'],
                'email'    => 'alice@example.com',
                'ssn'      => '078-05-1120',
                'internal' => 'dropped',
                'password' => 's3cr3t',
            ])
            ->withIdentifier('alice@example.com')
            ->withNote('Erasable.', KeyOwner::ACTOR);

        $pending->fillClient('203.0.113.9', null);
        $pending->fillContext(['api_key' => 's3cr3t', 'plan' => 'pro']);

        return $pending;
    }

    /**
     * A definition of the code using every handling.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    private static function everyHandling(): EventDefinition
    {
        return EventDefinition::for(self::CODE)
            ->retain('amount')
            ->redact('customer')
            ->pseudonymise('email')
            ->encrypt('ssn', KeyOwner::ACTOR)
            ->drop('internal');
    }

    /**
     * What the default contributors fill into a fresh builder, each resolved as
     * a capture resolves it.
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
