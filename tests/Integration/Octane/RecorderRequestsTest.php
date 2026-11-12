<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Symfony\Component\Console\Input\ArrayInput;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Integration\Octane\Fixtures\RecordingCommand;
use Tests\Integration\Octane\Fixtures\RecordingSyncJob;
use Tests\Integration\Octane\Fixtures\ThrowingSyncJob;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for a recorder resolved at boot and served by one Octane
 * worker: each record holds its own request's state alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(OriginContributor::class)]
#[CoversClass(RequestContributor::class)]
#[CoversClass(ActorContributor::class)]
#[CoversClass(AmbientActor::class)]
#[CoversClass(EnterHttpFrame::class)]
#[CoversClass(ExecutionFrames::class)]
#[CoversClass(RequestIdentity::class)]
#[CoversClass(TrackCommandFrames::class)]
#[CoversClass(TrackJobFrames::class)]
#[CoversClass(CarryContextIntoJobs::class)]
final class RecorderRequestsTest extends TestCase
{
    use InteractsWithAuditStore, ServesRequestsThroughOctane, WithConsoleEvents;

    /** @var string The code a route records. */
    private const string CODE = 'invoice.approved';

    /** @var string The code a route records once its response has gone. */
    private const string TERMINATING_CODE = 'invoice.archived';

    /** @var string The message a route that fails fails with. */
    private const string ROUTE_FAILURE = 'The route failed.';

    /** @var string A client's address, which is a trusted proxy once the edge is trusted. */
    private const string FIRST_IP = '203.0.113.7';

    /** @var string Another client's address, which is a trusted proxy once the edge is trusted. */
    private const string SECOND_IP = '198.51.100.9';

    /** @var string A valid `traceparent` header. */
    private const string TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

    /** @var string The trace id of that header. */
    private const string TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';

    /** @var string Another valid `traceparent` header. */
    private const string OTHER_TRACEPARENT = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00';

    /** @var string The trace id of that header. */
    private const string OTHER_TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

    /** @var array<string, string> The record's context on the named route. */
    private const array RECORD_CONTEXT = ['method' => 'GET', 'route' => 'octane.record'];

    /** @var list<\SineMacula\Laravel\AuditLog\Recorder> The recorder each request resolved, in order. */
    private array $recorders = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames> The frames each request resolved, in order. */
    private array $frames = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Runtime\RequestIdentity> The identity each request resolved, in order. */
    private array $identities = [];

    /** @var list<?\Illuminate\Http\Request> The request each request's frames held, in order. */
    private array $framedRequests = [];

    /** @var list<\Illuminate\Http\Request> The request each request was given, in order. */
    private array $givenRequests = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Testing\FakeAuditStore> The fake each request bound, in order. */
    private array $fakes = [];

    /** @var list<list<class-string>> The classes the recorder held during each request, in order. */
    private array $heldInRequests = [];

    /**
     * Add the routes and the command, and run jobs on the sync queue.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        app(ConfigRepository::class)->set('queue.default', 'sync');

        Artisan::registerCommand(new RecordingCommand);

        $this->addRecordingRoutes();
        $this->addNestedWorkRoutes();
        $this->addContainerRoutes();
        $this->addTransactionRoutes();
    }

    /**
     * Forget the trusted proxies and roll back a transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        Request::setTrustedProxies([], 0);

        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A recorder resolved at boot gives each request its own user and headers.
     *
     * @return void
     */
    public function testARecorderResolvedAtBootServesTwoRequestsWithDifferentUsersAndHeaders(): void
    {
        $this->trustTheEdge();
        $this->bootWorkerWithTheRecorderResolved();

        $first = $this->serve(self::octaneRequest('GET', '/record', ['user' => '7'], ip: self::FIRST_IP, server: [
            'HTTP_USER_AGENT'   => 'First/1.0',
            'HTTP_X_REQUEST_ID' => 'edge-first',
            'HTTP_TRACEPARENT'  => self::TRACEPARENT,
        ]));

        $second = $this->serve(self::octaneRequest('GET', '/record', ['user' => '8'], ip: self::SECOND_IP, server: [
            'HTTP_USER_AGENT'   => 'Second/2.0',
            'HTTP_X_REQUEST_ID' => 'edge-second',
            'HTTP_TRACEPARENT'  => self::OTHER_TRACEPARENT,
        ]));

        $firstFields = [
            'actor_id'   => '7',
            'guard'      => 'web',
            'ip'         => self::FIRST_IP,
            'user_agent' => 'First/1.0',
            'request_id' => 'edge-first',
            'trace_id'   => self::TRACE_ID,
            'origin'     => Origin::HTTP->value,
        ];

        $secondFields = [
            'actor_id'   => '8',
            'guard'      => 'web',
            'ip'         => self::SECOND_IP,
            'user_agent' => 'Second/2.0',
            'request_id' => 'edge-second',
            'trace_id'   => self::OTHER_TRACE_ID,
            'origin'     => Origin::HTTP->value,
        ];

        self::assertFields($firstFields, $first);
        self::assertFields($secondFields, $second);

        self::assertRow($firstFields, $this->storedRow(self::stringField($first, 'id')));
        self::assertRow($secondFields, $this->storedRow(self::stringField($second, 'id')));

        self::assertSame(2, $this->entryCount());
    }

    /**
     * A guest request after a user's has no actor and no guard.
     *
     * @return void
     */
    public function testAGuestRequestAfterAUsersCarriesNoActor(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $user = $this->serve(self::octaneRequest('GET', '/record', ['user' => '7']));
        $this->serve(self::octaneRequest('GET', '/guest-guard'))->assertExactJson(['has_user' => false]);
        $guest = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertFields(['actor_type' => (new StubAuthUser)->getMorphClass(), 'actor_id' => '7', 'guard' => 'web'], $user);
        self::assertFields(['actor_type' => null, 'actor_id' => null, 'guard' => null], $guest);
    }

    /**
     * An explicit `by()` in one request does not reach the next.
     *
     * @return void
     */
    public function testAnExplicitActorOfOneRequestDoesNotReachTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $explicit = $this->serve(self::octaneRequest('GET', '/record-by'));
        $guest    = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertFields(['actor_type' => 'service', 'actor_id' => 'billing', 'guard' => null], $explicit);
        self::assertFields(['actor_type' => null, 'actor_id' => null, 'guard' => null], $guest);
    }

    /**
     * Each request has its own UUID v7 request id, shared by its records.
     *
     * @return void
     */
    public function testEachRequestHasItsOwnRequestId(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $ids = [];

        foreach ([1, 2, 3] as $request) {
            $response = $this->serve(self::octaneRequest('GET', '/record-twice'));
            $id       = self::stringField($response, 'first');

            self::assertTrue(Str::isUuid($id, 7), "Request {$request} has a UUID v7.");
            self::assertSame($id, $response->json('second'), "Request {$request} shares its id across its records.");

            $ids[] = $id;
        }

        self::assertCount(3, array_unique($ids));
    }

    /**
     * An identity made at boot does not reach the first request.
     *
     * @return void
     */
    public function testAnIdentityMadeAtBootDoesNotReachTheFirstRequest(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 7]));

        $atBoot = AuditLog::record(self::CODE);

        self::assertSame('7', $atBoot->actorId);
        self::assertNotNull($atBoot->requestId);

        $response = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertNotSame($atBoot->requestId, $response->json('request_id'));
        self::assertFields(['actor_id' => null, 'guard' => null, 'origin' => Origin::HTTP->value, 'context' => self::RECORD_CONTEXT], $response);
    }

    /**
     * A trusted inbound request id does not reach the next request.
     *
     * @return void
     */
    public function testATrustedHeaderInOneRequestDoesNotReachTheNext(): void
    {
        $this->trustTheEdge();
        $this->bootWorkerWithTheRecorderResolved();

        $trusted = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP, server: ['HTTP_X_REQUEST_ID' => 'edge-id']));
        $none    = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP));
        $foreign = $this->serve(self::octaneRequest('GET', '/record', ip: '192.0.2.44', server: ['HTTP_X_REQUEST_ID' => 'edge-id']));

        self::assertSame('edge-id', $trusted->json('request_id'));
        self::assertTrue(Str::isUuid(self::stringField($none, 'request_id'), 7));
        self::assertTrue(Str::isUuid(self::stringField($foreign, 'request_id'), 7));
        self::assertNotSame($none->json('request_id'), $foreign->json('request_id'));
    }

    /**
     * A trace id does not reach the next request; none is ever generated.
     *
     * @return void
     */
    public function testATraceIdInOneRequestDoesNotReachTheNext(): void
    {
        $this->trustTheEdge();
        $this->bootWorkerWithTheRecorderResolved();

        $traced = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP, server: ['HTTP_TRACEPARENT' => self::TRACEPARENT]));
        $none   = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP));

        self::assertSame(self::TRACE_ID, $traced->json('trace_id'));
        self::assertNull($none->json('trace_id'));
    }

    /**
     * Neither the origin nor the context of one request reaches the next.
     *
     * @return void
     */
    public function testOriginAndContextOfOneRequestDoNotReachTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $accessed = $this->serve(self::octaneRequest('GET', '/accessed'));
        $unnamed  = $this->serve(self::octaneRequest('POST', '/unnamed'));

        self::assertFields(['origin' => Origin::HTTP->value, 'context' => ['channel' => 'export', 'method' => 'GET', 'route' => 'octane.accessed']], $accessed);
        self::assertFields(['origin' => Origin::HTTP->value, 'context' => ['method' => 'POST']], $unnamed);

        $this->serve(self::octaneRequest('GET', '/context/read'))->assertExactJson(['added' => null, 'request_id' => null]);
    }

    /**
     * A request's address and user agent do not reach the next.
     *
     * @return void
     */
    public function testTheClientOfOneRequestDoesNotReachTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $first = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP, server: ['HTTP_USER_AGENT' => 'First/1.0']));

        $request = self::octaneRequest('GET', '/record', ip: self::SECOND_IP);

        $request->headers->remove('User-Agent');

        $second = $this->serve($request);

        self::assertFields(['ip' => self::FIRST_IP, 'user_agent' => 'First/1.0'], $first);
        self::assertFields(['ip' => self::SECOND_IP, 'user_agent' => null], $second);
    }

    /**
     * A client forwarded by a trusted proxy does not reach the next request.
     *
     * @return void
     */
    public function testAForwardedClientOfOneRequestDoesNotReachTheNext(): void
    {
        $this->trustTheEdge();
        $this->bootWorkerWithTheRecorderResolved();

        $forwarded = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP, server: ['HTTP_X_FORWARDED_FOR' => '192.0.2.44']));
        $direct    = $this->serve(self::octaneRequest('GET', '/record', ip: self::FIRST_IP));

        self::assertFields(['ip' => '192.0.2.44'], $forwarded);
        self::assertFields(['ip' => self::FIRST_IP], $direct);
    }

    /**
     * A command records in its request's frame and leaves no frame behind.
     *
     * @return void
     */
    public function testACommandInARequestLeavesNoFrameForTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $inside = $this->serve(self::octaneRequest('GET', '/command'));
        $next   = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertRow(
            ['origin' => Origin::CONSOLE->value, 'ip' => null, 'user_agent' => null, 'context' => ['command' => RecordingCommand::NAME]],
            $this->entryOf(RecordingCommand::CODE, self::stringField($inside, 'request_id')),
        );

        self::assertFields(['origin' => Origin::HTTP->value, 'ip' => self::FIRST_IP, 'context' => ['method' => 'GET', 'route' => 'octane.command']], $inside);
        self::assertFields(['origin' => Origin::HTTP->value, 'ip' => self::FIRST_IP, 'context' => self::RECORD_CONTEXT], $next);
        self::assertNotSame($inside->json('request_id'), $next->json('request_id'));
    }

    /**
     * A command that throws also leaves no frame behind.
     *
     * @return void
     */
    public function testAThrowingCommandInARequestLeavesNoFrameForTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $inside = $this->serve(self::octaneRequest('GET', '/command/throw'));
        $next   = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertRow(
            ['origin' => Origin::CONSOLE->value, 'context' => ['command' => RecordingCommand::NAME]],
            $this->entryOf(RecordingCommand::CODE, self::stringField($inside, 'request_id')),
        );

        self::assertFields(['origin' => Origin::HTTP->value, 'context' => ['method' => 'GET', 'route' => 'octane.command-throw']], $inside);
        self::assertFields(['origin' => Origin::HTTP->value, 'context' => self::RECORD_CONTEXT], $next);
    }

    /**
     * A failing sync job records in its own frame and leaves none behind.
     *
     * @return void
     */
    public function testAFailingSyncJobInARequestLeavesNoFrameForTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $inside = $this->serve(self::octaneRequest('GET', '/job/throw'));
        $next   = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertRow(
            ['origin' => Origin::QUEUE->value, 'ip' => null, 'user_agent' => null, 'context' => ['job' => ThrowingSyncJob::class]],
            $this->entryOf(ThrowingSyncJob::CODE, self::stringField($inside, 'request_id')),
        );

        self::assertFields(['origin' => Origin::HTTP->value, 'ip' => self::FIRST_IP, 'context' => ['method' => 'GET', 'route' => 'octane.job-throw']], $inside);
        self::assertFields(['origin' => Origin::HTTP->value, 'ip' => self::FIRST_IP, 'context' => self::RECORD_CONTEXT], $next);
    }

    /**
     * An uncaught sync job failure is an error response; the next is its own.
     *
     * @return void
     */
    public function testAnUncaughtSyncJobFailureLeavesNoFrameForTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $this->serve(self::octaneRequest('GET', '/job/uncaught', ['user' => '7']))->assertInternalServerError();

        $next = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertFields(['origin' => Origin::HTTP->value, 'actor_id' => null, 'context' => self::RECORD_CONTEXT], $next);
    }

    /**
     * A sync job's carried actor reaches neither its request nor the next.
     *
     * @return void
     */
    public function testTheCarriedActorOfASyncJobDoesNotReachTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $user = $this->serve(self::octaneRequest('GET', '/job', ['user' => '7', 'forget' => '1']));

        self::assertRow(
            ['origin' => Origin::QUEUE->value, 'actor_id' => '7', 'guard' => 'web', 'context' => ['job' => RecordingSyncJob::class]],
            $this->entryOf(RecordingSyncJob::CODE, self::stringField($user, 'request_id')),
        );

        self::assertFields(['origin' => Origin::HTTP->value, 'actor_id' => null, 'guard' => null], $user);

        $this->serve(self::octaneRequest('GET', '/context/read'))->assertExactJson(['added' => null, 'request_id' => null]);

        $guest = $this->serve(self::octaneRequest('GET', '/job', ['forget' => '1']));

        self::assertRow(
            ['origin' => Origin::QUEUE->value, 'actor_id' => null, 'guard' => null],
            $this->entryOf(RecordingSyncJob::CODE, self::stringField($guest, 'request_id')),
        );

        self::assertNotSame($user->json('request_id'), $guest->json('request_id'));
    }

    /**
     * A route's failure leaves no user, record or Context for the next request.
     *
     * @return void
     */
    public function testAnExceptionInARouteLeaksNothingIntoTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $this->serve(self::octaneRequest('GET', '/throw', ['user' => '7']))->assertInternalServerError();

        $next = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertFields(['actor_id' => null, 'guard' => null, 'origin' => Origin::HTTP->value, 'context' => self::RECORD_CONTEXT], $next);

        $this->serve(self::octaneRequest('GET', '/context/read'))->assertExactJson(['added' => null, 'request_id' => null]);
    }

    /**
     * A record made after the response keeps its request; the next has its own.
     *
     * @return void
     */
    public function testATerminatingRecordKeepsItsRequestAndLeavesNothingForTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $terminating = $this->serve(self::octaneRequest('GET', '/terminating', ['user' => '7'], ip: self::FIRST_IP));
        $next        = $this->serve(self::octaneRequest('GET', '/record', ip: self::SECOND_IP));

        self::assertRow(
            ['origin' => Origin::HTTP->value, 'actor_id' => '7', 'ip' => self::FIRST_IP, 'context' => ['method' => 'GET', 'route' => 'octane.terminating']],
            $this->entryOf(self::TERMINATING_CODE, self::stringField($terminating, 'request_id')),
        );

        self::assertFields(['actor_id' => null, 'ip' => self::SECOND_IP, 'context' => self::RECORD_CONTEXT], $next);
        self::assertNotSame($terminating->json('request_id'), $next->json('request_id'));
    }

    /**
     * A fake bound after the recorder resolves takes every record.
     *
     * @return void
     */
    public function testAFakeBoundAfterTheRecorderIsResolvedIsUsed(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $fake = AuditLog::fake();

        $first  = $this->serve(self::octaneRequest('GET', '/record', ['user' => '7']));
        $second = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertSame(0, $this->entryCount());
        self::assertSame([$first->json('id'), $second->json('id')], self::idsHeldBy($fake));
    }

    /**
     * A fake bound in a request does not reach the next.
     *
     * @return void
     */
    public function testAFakeBoundInARequestDoesNotReachTheNext(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $faked = $this->serve(self::octaneRequest('GET', '/fake'));
        $next  = $this->serve(self::octaneRequest('GET', '/record'));

        self::assertCount(1, $this->fakes);
        self::assertSame([$faked->json('id')], self::idsHeldBy($this->fakes[0]));

        self::assertSame(1, $this->entryCount());
        self::assertSame(self::stringField($next, 'id'), $this->storedRow(self::stringField($next, 'id'))['id']);
    }

    /**
     * An after-commit write resolves its store from its request's container.
     *
     * @return void
     */
    public function testADeferredWriteUsesTheContainerOfItsRequest(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $deferred = $this->serve(self::octaneRequest('GET', '/deferred'));

        self::assertCount(1, $this->fakes);
        self::assertSame([$deferred->json('id')], self::idsHeldBy($this->fakes[0]));
        self::assertSame(0, $this->entryCount());

        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A record rolled back in a request is never written.
     *
     * @return void
     */
    public function testARecordRolledBackInARequestIsNeverWritten(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $rolledBack = $this->serve(self::octaneRequest('GET', '/rollback'));

        self::assertSame(0, $this->entryCount());

        $this->serve(self::octaneRequest('GET', '/commit'))->assertOk();

        self::assertSame(1, $this->entryCount());
        self::assertNull($this->storageConnection()->table(EntrySettings::table())->where('id', $rolledBack->json('id'))->first());
    }

    /**
     * Every request resolves the one recorder of the booted application.
     *
     * @return void
     */
    public function testTheRecorderIsTheSameObjectInEveryRequest(): void
    {
        $recorder = $this->bootWorkerWithTheRecorderResolved();

        $this->serve(self::octaneRequest('GET', '/recorder'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/recorder'))->assertOk();

        self::assertCount(4, $this->recorders);

        foreach ($this->recorders as $resolved) {
            self::assertSame($recorder, $resolved);
        }
    }

    /**
     * Each request resolves its own frames and identity.
     *
     * @return void
     */
    public function testEachRequestResolvesItsOwnFrames(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $this->serve(self::octaneRequest('GET', '/frames'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/frames'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/frames'))->assertOk();

        self::assertCount(3, $this->frames);

        self::assertNotSame($this->frames[0], $this->frames[1]);
        self::assertNotSame($this->frames[1], $this->frames[2]);
        self::assertNotSame($this->frames[0], $this->frames[2]);

        self::assertNotSame($this->identities[0], $this->identities[1]);
        self::assertNotSame($this->identities[1], $this->identities[2]);
        self::assertNotSame($this->identities[0], $this->identities[2]);

        foreach ($this->givenRequests as $index => $request) {
            self::assertSame($request, $this->framedRequests[$index], "Request {$index}'s frames hold it.");
        }
    }

    /**
     * The recorder holds its registration data, and no request or frame.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testTheRecorderRetainsNoRequestObject(): void
    {
        $recorder = $this->bootWorkerWithTheRecorderResolved();

        $registrationData = [ContributorRegistry::class, FieldHandling::class, EventCatalogue::class, EventDefinition::class, FieldRule::class, Recorder::class];

        $this->serve(self::octaneRequest('GET', '/held', ['user' => '7']))->assertOk();
        $this->serve(self::octaneRequest('GET', '/held'))->assertOk();

        self::assertSame([$registrationData, $registrationData], $this->heldInRequests);
        self::assertSame($registrationData, self::classesHeldBy($recorder));
    }

    /**
     * The walk finds a request however it is held, so an empty walk counts.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testTheWalkFindsARequestHoweverItIsHeld(): void
    {
        $request = Request::create('/held');

        $inAnArray = new class ([['deep' => $request]]) {
            /**
             * Constructor.
             *
             * @param  list<array<string, \Illuminate\Http\Request>>  $held
             */
            public function __construct(

                /** What the object holds. */
                public readonly array $held,
            ) {}
        };

        $inAClosure     = static fn (): Request => $request;
        $throughAParent = new class (['held' => $request]) extends ArrayInput {};

        self::assertContains(Request::class, self::classesHeldBy($inAnArray));
        self::assertContains(Request::class, self::classesHeldBy($inAClosure));
        self::assertContains(Request::class, self::classesHeldBy($throughAParent));
    }

    /**
     * The listeners reach the request's container, never the booted one's.
     *
     * @return void
     */
    public function testTheListenersUseTheRequestsContainer(): void
    {
        $this->bootWorkerWithTheRecorderResolved();

        $response  = $this->serve(self::octaneRequest('GET', '/listeners'));
        $requestId = self::stringField($response, 'request_id');

        self::assertRow(['origin' => Origin::CONSOLE->value, 'context' => ['command' => RecordingCommand::NAME]], $this->entryOf(RecordingCommand::CODE, $requestId));
        self::assertRow(['origin' => Origin::QUEUE->value, 'context' => ['job' => RecordingSyncJob::class]], $this->entryOf(RecordingSyncJob::CODE, $requestId));

        self::assertFalse($this->octaneApplication()->resolved(ExecutionFrames::class));
        self::assertFalse($this->octaneApplication()->resolved(RequestIdentity::class));
    }

    /**
     * The routes that record, and those that read what a request can still see.
     *
     * @return void
     */
    private function addRecordingRoutes(): void
    {
        Route::get('/record', static function (Request $request): array {
            self::signInFrom($request);

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.record');

        Route::post('/unnamed', static fn (): array => AuditLog::record(self::CODE)->toArray());

        Route::get('/record-by', static fn (): array => AuditLog::event(self::CODE)->by(Reference::of('service', 'billing'))->record()->toArray());

        Route::get('/record-twice', static fn (): array => [
            'first'  => AuditLog::record(self::CODE)->requestId,
            'second' => AuditLog::record(self::CODE)->requestId,
        ]);

        Route::get('/accessed', static function (): array {
            Context::add('added', 'by the request');

            return AuditLog::accessed('invoice.viewed', Reference::of('invoice', 'invoice-1'), 'support', 'export')->record()->toArray();
        })->name('octane.accessed');

        Route::get('/context/read', static fn (): array => [
            'added'      => Context::get('added'),
            'request_id' => Context::getHidden(CarriedContext::REQUEST_ID),
        ]);

        Route::get('/guest-guard', static fn (): array => ['has_user' => Auth::guard('web')->hasUser()]);

        Route::get('/throw', static function (Request $request): never {
            self::signInFrom($request);

            Context::add('added', 'by the request');

            AuditLog::record(self::CODE);

            throw new \RuntimeException(self::ROUTE_FAILURE);
        });

        Route::get('/terminating', static function (Request $request): array {
            self::signInFrom($request);

            app()->terminating(static function (): void {
                AuditLog::record(self::TERMINATING_CODE);
            });

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.terminating');
    }

    /**
     * The routes that run a command or a sync job.
     *
     * @return void
     */
    private function addNestedWorkRoutes(): void
    {
        Route::get('/command', static function (): array {
            Artisan::call(RecordingCommand::NAME);

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.command');

        Route::get('/command/throw', static function (): array {
            try {
                Artisan::call(RecordingCommand::NAME, ['--fail' => true]);
            } catch (\RuntimeException $exception) { // @phpstan-ignore catch.neverThrown
                self::assertSame(RecordingCommand::MESSAGE, $exception->getMessage());
            }

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.command-throw');

        Route::get('/job', static function (Request $request): array {
            self::signInFrom($request);

            RecordingSyncJob::dispatch($request->query('forget') !== null);

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.job');

        Route::get('/job/throw', static function (): array {
            try {
                ThrowingSyncJob::dispatch();
            } catch (\RuntimeException $exception) { // @phpstan-ignore catch.neverThrown
                self::assertSame(ThrowingSyncJob::MESSAGE, $exception->getMessage());
            }

            return AuditLog::record(self::CODE)->toArray();
        })->name('octane.job-throw');

        Route::get('/job/uncaught', static function (Request $request): array {
            self::signInFrom($request);

            ThrowingSyncJob::dispatch();

            return ['reached' => true];
        });
    }

    /**
     * The routes that report what each request's container gave it.
     *
     * @return void
     */
    private function addContainerRoutes(): void
    {
        Route::get('/recorder', function (): array {
            $this->recorders[] = app(Recorder::class);
            $this->recorders[] = AuditLog::recorder();

            return ['resolved' => true];
        });

        Route::get('/frames', function (Request $request): array {
            $frames = app(ExecutionFrames::class);

            $this->frames[]         = $frames;
            $this->identities[]     = app(RequestIdentity::class);
            $this->framedRequests[] = $frames->request();
            $this->givenRequests[]  = $request;

            return ['resolved' => true];
        });

        Route::get('/held', function (Request $request): array {
            self::signInFrom($request);

            AuditLog::record(self::CODE);
            Artisan::call(RecordingCommand::NAME);
            RecordingSyncJob::dispatch();

            $this->heldInRequests[] = self::classesHeldBy(app(Recorder::class));

            return ['walked' => true];
        });

        Route::get('/listeners', static function (): array {
            Artisan::call(RecordingCommand::NAME);
            RecordingSyncJob::dispatch();

            return AuditLog::record(self::CODE)->toArray();
        });

        Route::get('/fake', function (): array {
            $this->fakes[] = FakeAuditStore::fake();

            return AuditLog::record(self::CODE)->toArray();
        });
    }

    /**
     * The routes that open a transaction around a record.
     *
     * @return void
     */
    private function addTransactionRoutes(): void
    {
        Route::get('/deferred', function (): array {
            $connection = DB::connection(self::CONNECTION);

            $connection->beginTransaction();

            $record = AuditLog::record(self::CODE);

            $this->fakes[] = FakeAuditStore::fake();

            $connection->commit();

            return $record->toArray();
        });

        Route::get('/rollback', static function (): array {
            $connection = DB::connection(self::CONNECTION);

            $connection->beginTransaction();

            $record = AuditLog::record(self::CODE);

            $connection->rollBack();

            return $record->toArray();
        });

        Route::get('/commit', static function (): array {
            $connection = DB::connection(self::CONNECTION);

            $connection->beginTransaction();

            $record = AuditLog::record(self::CODE);

            $connection->commit();

            return $record->toArray();
        });
    }

    /**
     * Trust both clients as proxies on the booted application.
     *
     * @return void
     */
    private function trustTheEdge(): void
    {
        TrustProxies::at([self::FIRST_IP, self::SECOND_IP]);

        $config = app(ConfigRepository::class);

        $config->set('audit-log.context.trust_request_id', true);
        $config->set('audit-log.context.trust_traceparent', true);
    }

    /**
     * Resolve the recorder on the booted application, then boot the worker.
     *
     * @return \SineMacula\Laravel\AuditLog\Recorder
     */
    private function bootWorkerWithTheRecorderResolved(): Recorder
    {
        $recorder = $this->octaneApplication()->make(Recorder::class);

        $this->bootOctaneWorker();

        return $recorder;
    }

    /**
     * Put the user the request names on the `web` guard, if it names one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    private static function signInFrom(Request $request): void
    {
        $id = $request->query('user');

        if (!is_string($id)) {
            return;
        }

        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => (int) $id]));
    }

    /**
     * The one row the code wrote under the request id, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $code
     * @param  string  $requestId
     * @return array<string, mixed>
     */
    private function entryOf(string $code, string $requestId): array
    {
        $rows = $this->storageConnection()->table(EntrySettings::table())->where('event', $code)->where('request_id', $requestId)->get();

        self::assertCount(1, $rows, "One `{$code}` entry is stored under the request's id.");

        return (new RowCodec)->decode((array) $rows->first());
    }

    /**
     * Assert the request succeeded and each field is present with its value.
     *
     * @param  array<string, array<string, string>|string|null>  $expected
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return void
     */
    private static function assertFields(array $expected, TestResponse $response): void
    {
        $response->assertOk();

        $body = $response->json();

        self::assertIsArray($body);

        foreach ($expected as $field => $value) {
            self::assertTrue(Arr::has($body, $field), "The response has the record's `{$field}`.");
            self::assertSame($value, $response->json($field), "The record's `{$field}`.");
        }
    }

    /**
     * Assert each field of the row; context maps compare in any key order, as
     * an engine may reorder them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, array<string, string>|string|null>  $expected
     * @param  array<string, mixed>  $row
     * @return void
     */
    private static function assertRow(array $expected, array $row): void
    {
        foreach ($expected as $field => $value) {
            self::assertSame(self::inKeyOrder($value), self::inKeyOrder($row[$field]), "The row's `{$field}`.");
        }
    }

    /**
     * The value as it is, or an array or object as an array in key order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function inKeyOrder(mixed $value): mixed
    {
        if (!is_array($value) && !is_object($value)) {
            return $value;
        }

        $map = (array) $value;

        ksort($map);

        return $map;
    }

    /**
     * The response's field, which must be a string.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  string  $field
     * @return string
     */
    private static function stringField(TestResponse $response, string $field): string
    {
        $value = $response->json($field);

        self::assertIsString($value, "The response's `{$field}`.");

        return $value;
    }

    /**
     * The ids of the records the fake holds, oldest first.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return list<string>
     */
    private static function idsHeldBy(FakeAuditStore $fake): array
    {
        return array_map(static fn (AuditRecord $record): string => $record->id, $fake->recorded());
    }

    /**
     * The classes of every object reachable from the object, sorted, each once.
     *
     * @param  object  $object
     * @return list<class-string>
     */
    private static function classesHeldBy(object $object): array
    {
        $seen = [];

        self::walk($object, $seen);

        $classes = array_values(array_unique(array_map(static fn (object $held): string => $held::class, $seen)));

        sort($classes);

        return $classes;
    }

    /**
     * Add the value, and whatever it holds, to the objects seen, each once.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  array<int, object>  $seen
     * @return void
     */
    private static function walk(mixed $value, array &$seen): void
    {
        if (is_array($value)) {
            foreach ($value as $held) {
                self::walk($held, $seen);
            }

            return;
        }

        if (!is_object($value) || isset($seen[spl_object_id($value)])) {
            return;
        }

        $seen[spl_object_id($value)] = $value;

        foreach (self::valuesHeldBy($value) as $held) {
            self::walk($held, $seen);
        }
    }

    /**
     * Everything the object holds directly, whatever the visibility.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @SuppressWarnings("php:S3011")
     *
     * @param  object  $object
     * @return list<mixed>
     */
    private static function valuesHeldBy(object $object): array
    {
        if ($object instanceof \Closure) {
            $closure = new \ReflectionFunction($object);

            return [$closure->getClosureThis(), ...array_values($closure->getStaticVariables())];
        }

        $values = [];

        for ($class = new \ReflectionObject($object); $class !== false; $class = $class->getParentClass()) {
            foreach ($class->getProperties() as $property) {
                if (!$property->isInitialized($object)) {
                    continue;
                }

                $values[] = $property->getValue($object);
            }
        }

        return $values;
    }
}
