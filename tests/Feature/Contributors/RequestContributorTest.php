<?php

declare(strict_types = 1);

namespace Tests\Feature\Contributors;

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Context;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Tests\TestCase;

/**
 * Feature tests for the default contributor of the request: the identifiers
 * always, and the client, method and route's name only from an innermost HTTP
 * frame, never a URL or a query string, and never from Laravel's placeholder
 * console request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestContributor::class)]
final class RequestContributorTest extends TestCase
{
    /** @var string A valid W3C trace id. */
    private const string TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

    /** @var bool Whether a `_method` override was honoured before the test. */
    private bool $overrideWasHonoured;

    /**
     * Honour a `_method` override, as Laravel's HTTP kernel does for every
     * request and `Request::create()` does not.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->overrideWasHonoured = Request::getHttpMethodParameterOverride();

        Request::enableHttpMethodParameterOverride();
    }

    /**
     * Put the process-wide `_method` flag back, which Symfony offers no method
     * to turn off.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        (new \ReflectionProperty(SymfonyRequest::class, 'httpMethodParameterOverride'))->setValue(null, $this->overrideWasHonoured);

        parent::tearDown();
    }

    /**
     * The identifiers Context carries are the ones filled.
     *
     * @return void
     */
    public function testFillsTheRequestAndTraceIds(): void
    {
        Context::addHidden(CarriedContext::REQUEST_ID, 'app:request-1');
        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        $snapshot = $this->contributed();

        self::assertSame('app:request-1', $snapshot->requestId);
        self::assertSame(self::TRACE_ID, $snapshot->traceId);
    }

    /**
     * An HTTP frame fills the client's IP address and user agent.
     *
     * @return void
     */
    public function testFillsTheClientFromAnHttpFrame(): void
    {
        $this->frames()->enterRequest(self::request());

        $snapshot = $this->contributed();

        self::assertSame('203.0.113.7', $snapshot->ip);
        self::assertSame('Example/1.0', $snapshot->userAgent);
    }

    /**
     * An HTTP frame fills the method and the route's name.
     *
     * @return void
     */
    public function testFillsTheRouteNameAndMethod(): void
    {
        $request = self::request('POST');
        $route   = (new Route(['POST'], '/invoices/{invoice}', static fn (): string => 'ok'))->name('invoices.approve');

        $request->setRouteResolver(static fn (): Route => $route);

        $this->frames()->enterRequest($request);

        self::assertSame(['method' => 'POST', 'route' => 'invoices.approve'], $this->contributed()->context);
    }

    /**
     * A route with no name fills only the method, as does a request no route
     * has matched yet.
     *
     * @return void
     */
    public function testAnUnnamedRouteFillsOnlyTheMethod(): void
    {
        $request = self::request();
        $route   = new Route(['GET'], '/invoices', static fn (): string => 'ok');

        $this->frames()->enterRequest($request);

        self::assertSame(['method' => 'GET'], $this->contributed()->context);

        $request->setRouteResolver(static fn (): Route => $route);

        self::assertSame(['method' => 'GET'], $this->contributed()->context);
    }

    /**
     * A route resolved to something other than a route gives no name.
     *
     * @return void
     */
    public function testARouteThatIsNotARouteFillsOnlyTheMethod(): void
    {
        $request = self::request();

        $request->setRouteResolver(static fn (): string => 'invoices.approve');

        $this->frames()->enterRequest($request);

        self::assertSame(['method' => 'GET'], $this->contributed()->context);
    }

    /**
     * Nothing of the URL reaches the record, in any field.
     *
     * @return void
     */
    public function testNoUrlPathOrQueryStringIsFilled(): void
    {
        $request = Request::create('https://example.test/invoices/42?token=sentinel', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.7']);

        $this->frames()->enterRequest($request);

        $snapshot = $this->contributed();
        $filled   = (string) json_encode([$snapshot->context, $snapshot->ip, $snapshot->userAgent, $snapshot->requestId, $snapshot->traceId]);

        self::assertStringNotContainsString('sentinel', $filled);
        self::assertStringNotContainsString('invoices', $filled);
        self::assertStringNotContainsString('example.test', $filled);
        self::assertSame(['method' => 'GET'], $snapshot->context);
    }

    /**
     * An IP address that is not one is left out, and the user agent still goes
     * in.
     *
     * @return void
     */
    public function testAnInvalidIpIsKeptOut(): void
    {
        $this->frames()->enterRequest(self::request('GET', 'not-an-address'));

        $snapshot = $this->contributed();

        self::assertNull($snapshot->ip);
        self::assertSame('Example/1.0', $snapshot->userAgent);
    }

    /**
     * A command fills the identifiers and nothing of a client.
     *
     * @return void
     */
    public function testACommandFrameFillsIdsAndNoClient(): void
    {
        $this->frames()->enterCommand(new \stdClass, 'invoices:send');

        self::assertFillsIdsAndNoClient($this->contributed());
    }

    /**
     * A job fills the identifiers and nothing of a client.
     *
     * @return void
     */
    public function testAJobFrameFillsIdsAndNoClient(): void
    {
        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertFillsIdsAndNoClient($this->contributed());
    }

    /**
     * Outside any frame the identifiers are filled, and nothing of a client.
     *
     * @return void
     */
    public function testNoFrameFillsIdsAndNoClient(): void
    {
        self::assertFillsIdsAndNoClient($this->contributed());
    }

    /**
     * The application's own request object, which the console fills with a
     * placeholder, is never a frame, so nothing is read from it.
     *
     * @return void
     */
    public function testThePlaceholderConsoleRequestIsNeverRead(): void
    {
        $this->app?->instance('request', self::request());

        self::assertFillsIdsAndNoClient($this->contributed());
    }

    /**
     * A job run inside a request has the request's identity and no client: only
     * an innermost HTTP frame gives one.
     *
     * @return void
     */
    public function testAnHttpFrameBeneathAJobFillsNoClient(): void
    {
        $this->frames()->enterRequest(self::request());
        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertFillsIdsAndNoClient($this->contributed());
    }

    /**
     * A user agent longer than the column is cut to its 512 bytes.
     *
     * @return void
     */
    public function testALongUserAgentIsCapped(): void
    {
        $this->frames()->enterRequest(self::request('GET', '203.0.113.7', str_repeat('a', 600)));

        self::assertSame(str_repeat('a', 512), $this->contributed()->userAgent);
    }

    /**
     * Rows of `[method]`: every method a record may store.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideStandardMethods(): iterable
    {
        foreach (['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'] as $method) {
            yield $method => [$method];
        }
    }

    /**
     * Each standard method is filled.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideStandardMethods')]
    public function testEachStandardMethodIsFilled(string $method): void
    {
        $this->frames()->enterRequest(self::request($method));

        self::assertSame(['method' => $method], $this->contributed()->context);
    }

    /**
     * Rows of `[override]`: what a client can send that is no standard method.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMethodsThatAreNotStored(): iterable
    {
        yield from [
            'a word'                         => ['BREW'],
            'an oversized override'          => [str_repeat('A', 200000)],
            'digits, which Symfony refuses'  => ['a1'],
            'a space, which Symfony refuses' => ['PU T'],
        ];
    }

    /**
     * An override that is no standard method is left out, and the record still
     * has the rest: neither the client's value nor Symfony's exception gets
     * through.
     *
     * @param  string  $override
     * @return void
     */
    #[DataProvider('provideMethodsThatAreNotStored')]
    public function testAnOverrideThatIsNoStandardMethodIsLeftOut(string $override): void
    {
        $request = Request::create('/invoices', 'POST', ['_method' => $override], server: ['REMOTE_ADDR' => '203.0.113.7']);
        $route   = (new Route(['POST'], '/invoices', static fn (): string => 'ok'))->name('invoices.store');

        $request->setRouteResolver(static fn (): Route => $route);

        $this->frames()->enterRequest($request);

        $snapshot = $this->contributed();

        self::assertSame(['route' => 'invoices.store'], $snapshot->context);
        self::assertSame('203.0.113.7', $snapshot->ip);
    }

    /**
     * A malformed override with no route fills no context at all.
     *
     * @return void
     */
    public function testAMalformedOverrideWithNoRouteFillsNoContext(): void
    {
        $this->frames()->enterRequest(Request::create('/invoices', 'POST', ['_method' => 'a1']));

        self::assertNull($this->contributed()->context);
    }

    /**
     * A standard override is the request's method, as the router treats it.
     *
     * @return void
     */
    public function testAStandardOverrideIsFilled(): void
    {
        $this->frames()->enterRequest(Request::create('/invoices', 'POST', ['_method' => 'put']));

        self::assertSame(['method' => 'PUT'], $this->contributed()->context);
    }

    /**
     * Assert the identifiers are filled and nothing of the client or the route.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return void
     */
    private static function assertFillsIdsAndNoClient(PendingSnapshot $snapshot): void
    {
        self::assertNotNull($snapshot->requestId);
        self::assertNull($snapshot->ip);
        self::assertNull($snapshot->userAgent);
        self::assertNull($snapshot->context);
    }

    /**
     * A request from the address, with the user agent.
     *
     * @param  string  $method
     * @param  string  $ip
     * @param  string  $userAgent
     * @return \Illuminate\Http\Request
     */
    private static function request(string $method = 'GET', string $ip = '203.0.113.7', string $userAgent = 'Example/1.0'): Request
    {
        return Request::create('/invoices', $method, [], [], [], ['REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $userAgent]);
    }

    /**
     * The frames of the application.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }

    /**
     * What the contributor fills into a fresh builder.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private function contributed(): PendingSnapshot
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        (new RequestContributor($this->frames(), app(RequestIdentity::class)))->contribute(new Contribution($pending));

        return $pending->snapshot();
    }
}
