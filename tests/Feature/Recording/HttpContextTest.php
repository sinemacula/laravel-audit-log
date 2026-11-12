<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Foundation\Http\Middleware\InvokeDeferredCallbacks;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Defer\DeferredCallback;
use Illuminate\Support\Defer\DeferredCallbackCollection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for a record made inside an HTTP request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(EnterHttpFrame::class)]
#[CoversClass(ActorContributor::class)]
#[CoversClass(AmbientActor::class)]
#[CoversClass(OriginContributor::class)]
#[CoversClass(RequestContributor::class)]
final class HttpContextTest extends TestCase
{
    /** @var string The code most tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The guard the auth middleware authenticates on. */
    private const string GUARD = 'token';

    /** @var int The key of the user the guard authenticates. */
    private const int USER_ID = 42;

    /** @var string What a UUID version 7 looks like. */
    private const string UUID7 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /** @var string The address a request comes from. */
    private const string CLIENT_IP = '203.0.113.7';

    /** @var string An address a client claims to be behind. */
    private const string CLAIMED_IP = '198.51.100.9';

    /** @var string The user agent a request sends. */
    private const string USER_AGENT = 'Example/1.0';

    /** @var string The name a test's middleware instance is bound under. */
    private const string MIDDLEWARE = 'audit-test.recording';

    /** @var int How many times the guard looked its user up. */
    private int $userLookups = 0;

    /** @var int How many `Authenticated` events were dispatched. */
    private int $authenticatedEvents = 0;

    /**
     * Surface a failure inside a route, and give the guard its user.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();

        Auth::viaRequest(self::GUARD, function (): StubAuthUser {
            $this->userLookups++;

            return self::user();
        });
    }

    /**
     * Put the trusted proxies back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

    /**
     * A signed-in request records actor, guard, client, route, method and id.
     *
     * @return void
     */
    public function testAnAuthenticatedRequestRecordsActorGuardClientRouteMethodAndRequestId(): void
    {
        Route::post('/invoices/{invoice}/approve', static fn (): string => AuditLog::record(self::CODE)->id)
            ->name('invoices.approve')
            ->middleware(Authenticate::using(self::GUARD));

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])
            ->withHeader('User-Agent', self::USER_AGENT)
            ->post('/invoices/42/approve')
            ->assertOk();

        $entry = $this->entry();

        self::assertSame(StubAuthUser::class, $entry->actor_type);
        self::assertSame((string) self::USER_ID, $entry->actor_id);
        self::assertSame(self::GUARD, $entry->guard);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertSame(self::USER_AGENT, $entry->user_agent);
        self::assertSame('http', $entry->origin);
        self::assertEquals(['method' => 'POST', 'route' => 'invoices.approve'], $entry->context);
        self::assertMatchesRegularExpression(self::UUID7, (string) $entry->request_id);
    }

    /**
     * An unauthenticated request records no actor or guard and asks no guard.
     *
     * @return void
     */
    public function testAnUnauthenticatedRequestRecordsNoActor(): void
    {
        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id);

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertNull($entry->actor_type);
        self::assertNull($entry->actor_id);
        self::assertNull($entry->guard);
        self::assertSame('http', $entry->origin);
        self::assertSame(0, $this->userLookups);
    }

    /**
     * A record before the auth middleware has no actor; one after it does.
     *
     * @return void
     */
    public function testARecordBeforeTheAuthMiddlewareHasNoActor(): void
    {
        $before = $this->recordingMiddleware(static fn (): PendingRecord => AuditLog::event('invoice.before_auth'));

        Route::get('/invoices', static fn (): string => AuditLog::record('invoice.after_auth')->id)
            ->middleware([$before, Authenticate::using(self::GUARD)]);

        $this->get('/invoices')->assertOk();

        $before = $this->entry('invoice.before_auth');
        $after  = $this->entry('invoice.after_auth');

        self::assertNull($before->actor_id);
        self::assertNull($before->guard);
        self::assertSame((string) self::USER_ID, $after->actor_id);
        self::assertSame(self::GUARD, $after->guard);
        self::assertSame(1, $this->userLookups);
    }

    /**
     * `by()` names the actor before the auth middleware, with no guard.
     *
     * @return void
     */
    public function testByNamesTheActorBeforeTheAuthMiddleware(): void
    {
        $before = $this->recordingMiddleware(static fn (): PendingRecord => AuditLog::event(self::CODE)->by(Reference::of('staff', '7')));

        Route::get('/invoices', static fn (): string => 'ok')
            ->middleware([$before, Authenticate::using(self::GUARD)]);

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertSame('staff', $entry->actor_type);
        self::assertSame('7', $entry->actor_id);
        self::assertNull($entry->guard);
    }

    /**
     * `by(null)` means nobody did it, whoever the guard holds.
     *
     * @return void
     */
    public function testByNullStaysNullInAnAuthenticatedRequest(): void
    {
        Route::get('/invoices', static fn (): string => AuditLog::event(self::CODE)->by(null)->record()->id)
            ->middleware(Authenticate::using(self::GUARD));

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertNull($entry->actor_type);
        self::assertNull($entry->actor_id);
        self::assertNull($entry->guard);
    }

    /**
     * An explicit actor beats the one the guard holds, and fills no guard.
     *
     * @return void
     */
    public function testAnExplicitActorBeatsTheAmbientOne(): void
    {
        Route::get('/invoices', static fn (): string => AuditLog::event(self::CODE)->by(Reference::of('staff', '7'))->record()->id)
            ->middleware(Authenticate::using(self::GUARD));

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertSame('staff', $entry->actor_type);
        self::assertSame('7', $entry->actor_id);
        self::assertNull($entry->guard);
    }

    /**
     * No part of the URL is stored in the row.
     *
     * @return void
     */
    public function testNoUrlOrQueryStringIsStored(): void
    {
        Route::get('/invoices/{invoice}', static fn (): string => AuditLog::record(self::CODE)->id)->name('invoices.show');

        $this->get('/invoices/private-path-sentinel?token=private-query-sentinel')->assertOk();

        $row = $this->rowText($this->entry());

        self::assertStringNotContainsString('private-path-sentinel', $row);
        self::assertStringNotContainsString('private-query-sentinel', $row);
        self::assertStringNotContainsString('invoices/', $row);
    }

    /**
     * Without a trusted proxy, an address the client claims is ignored.
     *
     * @return void
     */
    public function testASpoofedForwardedForIsIgnoredWithoutATrustedProxy(): void
    {
        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id);

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])
            ->withHeader('X-Forwarded-For', self::CLAIMED_IP)
            ->get('/invoices')
            ->assertOk();

        self::assertSame(self::CLIENT_IP, $this->entry()->ip);
        self::assertStringNotContainsString(self::CLAIMED_IP, $this->rowText($this->entry()));
    }

    /**
     * From a trusted proxy, the address it forwards is the client's.
     *
     * @return void
     */
    public function testAForwardedForIsUsedWithATrustedProxy(): void
    {
        TrustProxies::at(self::CLIENT_IP);

        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id);

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])
            ->withHeader('X-Forwarded-For', self::CLAIMED_IP)
            ->get('/invoices')
            ->assertOk();

        self::assertSame(self::CLAIMED_IP, $this->entry()->ip);
    }

    /**
     * A vendor's client address header is ignored, trusted proxy or not.
     *
     * @return void
     */
    public function testCfConnectingIpIsIgnored(): void
    {
        TrustProxies::at(self::CLIENT_IP);

        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id);

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])
            ->withHeader('CF-Connecting-IP', self::CLAIMED_IP)
            ->get('/invoices')
            ->assertOk();

        self::assertSame(self::CLIENT_IP, $this->entry()->ip);
    }

    /**
     * Every record of one request has its request id.
     *
     * @return void
     */
    public function testOneRequestIdAcrossManyRecords(): void
    {
        Route::get('/invoices', static function (): string {
            AuditLog::record('invoice.first');
            AuditLog::record('invoice.second');

            return 'ok';
        });

        $this->get('/invoices')->assertOk();

        self::assertNotNull($this->entry('invoice.first')->request_id);
        self::assertSame($this->entry('invoice.first')->request_id, $this->entry('invoice.second')->request_id);
    }

    /**
     * Two requests in one process have different request ids.
     *
     * @return void
     */
    public function testTwoRequestsHaveDifferentIds(): void
    {
        Route::get('/invoices/{code}', static fn (string $code): string => AuditLog::record($code)->id);

        $this->get('/invoices/invoice.first')->assertOk();
        $this->get('/invoices/invoice.second')->assertOk();

        self::assertNotSame($this->entry('invoice.first')->request_id, $this->entry('invoice.second')->request_id);
    }

    /**
     * A record in a global middleware has its request but no route.
     *
     * @return void
     */
    public function testARecordInAGlobalMiddlewareHasTheHttpOrigin(): void
    {
        $this->kernel()->pushMiddleware($this->recordingMiddleware(static fn (): PendingRecord => AuditLog::event('invoice.global')));

        Route::get('/invoices', static fn (): string => 'ok')->name('invoices.index');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/invoices')->assertOk();

        $entry = $this->entry('invoice.global');

        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertEquals(['method' => 'GET'], $entry->context);
    }

    /**
     * Rows of `[name, value]`: long or malformed method overrides.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideOverrides(): iterable
    {
        yield from [
            'an oversized `_method`' => ['_method', str_repeat('A', 200000)],
            'a malformed `_method`'  => ['_method', 'a1'],
            'an oversized header'    => ['X-HTTP-Method-Override', str_repeat('A', 4096)],
            'a malformed header'     => ['X-HTTP-Method-Override', 'a1'],
        ];
    }

    /**
     * A method override never reaches the row; a malformed one stops nothing.
     *
     * @param  string  $name
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideOverrides')]
    public function testAMethodOverrideNeitherReachesTheRowNorStopsTheRecord(string $name, string $value): void
    {
        $this->withExceptionHandling();

        $this->kernel()->pushMiddleware($this->recordingMiddleware(static fn (): PendingRecord => AuditLog::event('invoice.global')));

        Route::post('/invoices', static fn (): string => 'ok');

        $body    = $name === '_method' ? [$name => $value] : [];
        $headers = $name === '_method' ? [] : [$name => $value];

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->post('/invoices', $body, $headers);

        $entry = $this->entry('invoice.global');

        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertNull($entry->context);
    }

    /**
     * A deferred callback runs after the response and keeps its request.
     *
     * @return void
     */
    public function testARecordInADeferredCallbackKeepsTheRequest(): void
    {
        $this->kernel()->pushMiddleware(InvokeDeferredCallbacks::class);

        Route::get('/invoices', static function (): string {
            AuditLog::record('invoice.in_route');

            app(DeferredCallbackCollection::class)[] = new DeferredCallback(static function (): void {
                AuditLog::record('invoice.deferred');
            });

            return 'ok';
        })->name('invoices.index');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/invoices')->assertOk();

        $entry = $this->entry('invoice.deferred');

        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'invoices.index'], $entry->context);
        self::assertSame($this->entry('invoice.in_route')->request_id, $entry->request_id);
    }

    /**
     * A terminable middleware runs after the response and keeps its request.
     *
     * @return void
     */
    public function testARecordInATerminableMiddlewareKeepsTheRequest(): void
    {
        $this->app?->instance(self::MIDDLEWARE, new class {
            /**
             * Pass the request on.
             *
             * @param  \Illuminate\Http\Request  $request
             * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
             * @return \Symfony\Component\HttpFoundation\Response
             */
            public function handle(Request $request, \Closure $next): Response
            {
                return $next($request);
            }

            /**
             * Record, once the response has been sent.
             *
             * @return void
             */
            public function terminate(): void
            {
                AuditLog::record('invoice.terminated');
            }
        });

        Route::get('/invoices', static fn (): string => AuditLog::record('invoice.in_route')->id)
            ->name('invoices.index')
            ->middleware(self::MIDDLEWARE);

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/invoices')->assertOk();

        $entry = $this->entry('invoice.terminated');

        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'invoices.index'], $entry->context);
        self::assertSame($this->entry('invoice.in_route')->request_id, $entry->request_id);
    }

    /**
     * A contributor the application registered while booting fills the tenant.
     *
     * @return void
     */
    #[DefineEnvironment('registerTheTenantContributor')]
    public function testATenantContributorFillsTheTenant(): void
    {
        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id);

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertSame(TenantContributor::TYPE, $entry->tenant_type);
        self::assertSame(TenantContributor::ID, $entry->tenant_id);
    }

    /**
     * By default no principal, tenant, session or session id is stored.
     *
     * @return void
     */
    public function testNoPrincipalTenantOrSessionByDefault(): void
    {
        $sessionId = null;

        Route::get('/invoices', static function (Request $request) use (&$sessionId): string {
            $sessionId = $request->session()->getId();

            return AuditLog::record(self::CODE)->id;
        })->middleware([StartSession::class, Authenticate::using(self::GUARD)]);

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertNull($entry->principal_type);
        self::assertNull($entry->principal_id);
        self::assertNull($entry->tenant_type);
        self::assertNull($entry->tenant_id);
        self::assertNull($entry->session_id);
        self::assertIsString($sessionId);
        self::assertStringNotContainsString($sessionId, $this->rowText($entry));
    }

    /**
     * Rows of `[told, actor type, actor id, tenant type, tenant id]`; an
     * explicit value, `null` included, beats a contributor's.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 1: ?string, 2: ?string, 3: ?string, 4: ?string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideExplicitValues(): iterable
    {
        $staff        = Reference::of('staff', '7');
        $organisation = Reference::of('organisation', 'explicit');

        yield from [
            'nothing explicit' => [
                static fn (PendingRecord $pending): PendingRecord => $pending,
                ActorFillingContributor::TYPE, ActorFillingContributor::ID, TenantContributor::TYPE, TenantContributor::ID,
            ],
            'an explicit actor' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->by($staff),
                'staff', '7', TenantContributor::TYPE, TenantContributor::ID,
            ],
            'an explicit null actor' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->by(null),
                null, null, TenantContributor::TYPE, TenantContributor::ID,
            ],
            'an explicit tenant' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->forTenant($organisation),
                ActorFillingContributor::TYPE, ActorFillingContributor::ID, 'organisation', 'explicit',
            ],
            'an explicit null tenant' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->forTenant(null),
                ActorFillingContributor::TYPE, ActorFillingContributor::ID, null, null,
            ],
            'both explicit' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->by($staff)->forTenant($organisation),
                'staff', '7', 'organisation', 'explicit',
            ],
            'both explicitly null' => [
                static fn (PendingRecord $pending): PendingRecord => $pending->by(null)->forTenant(null),
                null, null, null, null,
            ],
        ];
    }

    /**
     * An explicit value stands and a contributor fills only the gaps.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $explicit
     * @param  ?string  $actorType
     * @param  ?string  $actorId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @return void
     */
    #[DataProvider('provideExplicitValues')]
    #[DefineEnvironment('registerBothContributors')]
    public function testExplicitBeatsContributorForActorAndTenant(\Closure $explicit, ?string $actorType, ?string $actorId, ?string $tenantType, ?string $tenantId): void
    {
        Route::get('/invoices', static fn (): string => $explicit(AuditLog::event(self::CODE))->record()->id);

        $this->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertSame($actorType, $entry->actor_type);
        self::assertSame($actorId, $entry->actor_id);
        self::assertSame($tenantType, $entry->tenant_type);
        self::assertSame($tenantId, $entry->tenant_id);
    }

    /**
     * Recording loads no user, so no `Authenticated` event is dispatched.
     *
     * @return void
     */
    public function testRecordingDispatchesNoAuthenticatedEvent(): void
    {
        Event::listen(Authenticated::class, function (): void {
            $this->authenticatedEvents++;
        });

        app(ConfigRepository::class)->set('audit-log.actor.guards', ['web']);

        Route::get('/invoices', static function (Request $request): string {
            $request->session()->put(Auth::guard('web')->getName(), self::USER_ID);

            return AuditLog::record(self::CODE)->id;
        })->middleware(StartSession::class);

        $this->get('/invoices')->assertOk();

        self::assertSame(0, $this->authenticatedEvents);
        self::assertNull($this->entry()->actor_id);
    }

    /**
     * A record costs one insert and reads no user.
     *
     * @return void
     */
    public function testRecordingMakesNoUserQuery(): void
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id)
            ->middleware(Authenticate::using(self::GUARD));

        $this->get('/invoices')->assertOk();

        self::assertCount(1, $queries);
        self::assertStringStartsWith('insert into', $queries[0]);
        self::assertSame(1, $this->userLookups);
    }

    /**
     * A request without middleware enters no frame, so its record is console.
     *
     * @return void
     */
    public function testAWithoutMiddlewareRequestHasTheConsoleOrigin(): void
    {
        $this->withoutMiddleware();

        Route::get('/invoices', static fn (): string => AuditLog::record(self::CODE)->id)->name('invoices.index');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/invoices')->assertOk();

        $entry = $this->entry();

        self::assertSame('console', $entry->origin);
        self::assertNull($entry->ip);
        self::assertNull($entry->context);
    }

    /**
     * Configure the guard the auth middleware authenticates on, as the default.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => self::GUARD]);
        $config->set('auth.defaults.guard', self::GUARD);
        $config->set('session.driver', 'array');
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
     * Register the actor and tenant contributors as a provider would.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function registerBothContributors(Application $app): void
    {
        $app->booting(static function (Application $app): void {
            $recorder = $app->make(Recorder::class);

            $recorder->contribute(ActorFillingContributor::class);
            $recorder->contribute(TenantContributor::class);
        });
    }

    /**
     * Bind a middleware recording what the closure builds and return its name.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $builds
     * @return string
     */
    private function recordingMiddleware(\Closure $builds): string
    {
        $this->app?->instance(self::MIDDLEWARE, new class ($builds) {
            /**
             * Constructor.
             *
             * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $builds
             */
            public function __construct(

                /** Builds what is recorded. */
                private readonly \Closure $builds,
            ) {}

            /**
             * Record, then pass the request on.
             *
             * @param  \Illuminate\Http\Request  $request
             * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
             * @return \Symfony\Component\HttpFoundation\Response
             */
            public function handle(Request $request, \Closure $next): Response
            {
                ($this->builds)()->record();

                return $next($request);
            }
        });

        return self::MIDDLEWARE;
    }

    /**
     * The user the guard authenticates, which is never saved.
     *
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => self::USER_ID]);
    }

    /**
     * The one entry stored under the code.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function entry(string $code = self::CODE): AuditEntry
    {
        return AuditEntry::query()->where('event', $code)->sole();
    }

    /**
     * Every column of the stored row as one string.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return string
     */
    private function rowText(AuditEntry $entry): string
    {
        return json_encode($entry->getAttributes(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * The HTTP kernel, for a test that adds a global middleware.
     *
     * @return \Illuminate\Foundation\Http\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        return $kernel;
    }
}
