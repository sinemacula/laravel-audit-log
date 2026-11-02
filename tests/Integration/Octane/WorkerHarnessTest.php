<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Route;
use Laravel\Octane\Events\RequestHandled;
use Laravel\Octane\Events\RequestReceived;
use Laravel\Octane\Events\RequestTerminated;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\TestCase;

/**
 * Tests for the harness that serves requests through one Laravel Octane worker,
 * so a leakage test built on it passes for the right reason: each request runs
 * through the real worker, in a sandbox cloned from the booted application, and
 * an error the worker catches fails the test. No package class is under test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class WorkerHarnessTest extends TestCase
{
    use ServesRequestsThroughOctane;

    /** @var list<\Illuminate\Foundation\Application> The application each request ran in, in order. */
    private array $sandboxes = [];

    /** @var list<object> The instance of the scoped binding each request resolved, in order. */
    private array $scopedInstances = [];

    /** @var list<object> The instance of the root's binding each request resolved, in order. */
    private array $rootInstances = [];

    /** @var bool Whether the next request fails outside the HTTP kernel. */
    private bool $failNextRequest = false;

    /**
     * Add the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::post('/echo', static fn (Request $request): array => [
            'method' => $request->getMethod(),
            'path'   => $request->path(),
            'name'   => $request->input('name'),
            'ip'     => $request->ip(),
            'bound'  => app('request') === $request,
        ]);

        Route::get('/sandbox', function (): array {
            $this->sandboxes[]       = $this->currentApplication();
            $this->scopedInstances[] = app('harness.scoped');
            $this->rootInstances[]   = app('harness.root');

            $bound = app()->bound('harness.request');

            app()->instance('harness.request', new \stdClass);

            return ['bound' => $bound];
        });

        Route::get('/config', static function (): array {
            $value = app(ConfigRepository::class)->get('harness.value');

            app(ConfigRepository::class)->set('harness.value', 'set in a request');

            return ['value' => $value];
        });

        Route::get('/throw', static function (): never {
            throw new \RuntimeException('Failed in the route.');
        });

        $this->app?->scoped('harness.scoped', static fn (): \stdClass => new \stdClass);
        $this->app?->instance('harness.root', new \stdClass);

        Event::listen(RequestReceived::class, function (): void {
            if ($this->failNextRequest) {
                $this->failNextRequest = false;

                throw new \RuntimeException('Failed outside the kernel.');
            }
        });
    }

    /**
     * A request reaches its route through the worker's whole lifecycle, and the
     * route's response comes back.
     *
     * @return void
     */
    public function testServesARequestThroughTheWorker(): void
    {
        $lifecycle = [];

        Event::listen([RequestReceived::class, RequestHandled::class, RequestTerminated::class], static function (object $event) use (&$lifecycle): void {
            $lifecycle[] = $event::class;
        });

        $this->bootOctaneWorker();

        $response = $this->serve(self::octaneRequest('POST', '/echo', ['name' => 'first']));

        $response->assertOk();
        $response->assertExactJson([
            'method' => 'POST',
            'path'   => 'echo',
            'name'   => 'first',
            'ip'     => '203.0.113.7',
            'bound'  => true,
        ]);

        self::assertSame([RequestReceived::class, RequestHandled::class, RequestTerminated::class], $lifecycle);
    }

    /**
     * Each request runs in an application of its own, cloned from the booted
     * one: what the booted application held is there, a scoped instance and an
     * instance bound in the request are not carried to the next, and the
     * sandbox is flushed once the worker is done with it.
     *
     * @return void
     */
    public function testEachRequestRunsInASandboxOfTheBootedApplication(): void
    {
        $root = $this->octaneApplication();

        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/sandbox'))->assertExactJson(['bound' => false]);
        $this->serve(self::octaneRequest('GET', '/sandbox'))->assertExactJson(['bound' => false]);

        self::assertCount(2, $this->sandboxes);
        self::assertNotSame($root, $this->sandboxes[0]);
        self::assertNotSame($root, $this->sandboxes[1]);
        self::assertNotSame($this->sandboxes[0], $this->sandboxes[1]);

        self::assertSame($root->make('harness.root'), $this->rootInstances[0]);
        self::assertSame($this->rootInstances[0], $this->rootInstances[1]);

        self::assertNotSame($this->scopedInstances[0], $this->scopedInstances[1]);

        self::assertSame([], $this->sandboxes[0]->getBindings());
        self::assertFalse($root->bound('harness.request'));
    }

    /**
     * An error the worker catches outside the HTTP kernel fails the test that
     * served the request.
     *
     * @return void
     */
    public function testAWorkerErrorFailsTheTest(): void
    {
        $this->bootOctaneWorker();
        $this->failTheNextRequestOutsideTheKernel();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The Octane worker caught an error.');

        $level = ob_get_level();

        try {
            $this->serve(self::octaneRequest('GET', '/sandbox'));
        } finally {
            self::closeOutputBuffersAbove($level);
        }
    }

    /**
     * An error the worker caught for one request does not fail the next, which
     * the same worker serves.
     *
     * @return void
     */
    public function testAnEarlierWorkerErrorDoesNotFailTheNextRequest(): void
    {
        $this->bootOctaneWorker();
        $this->failTheNextRequestOutsideTheKernel();

        $level = ob_get_level();

        try {
            $this->serve(self::octaneRequest('GET', '/sandbox'));

            self::fail('The worker error did not fail the request that caused it.');
        } catch (AssertionFailedError $error) {
            self::assertStringContainsString('The Octane worker caught an error.', $error->getMessage());
        } finally {
            self::closeOutputBuffersAbove($level);
        }

        $this->serve(self::octaneRequest('GET', '/sandbox'))->assertOk();
    }

    /**
     * An exception a route throws is the HTTP kernel's to answer: the request
     * gets an error response, and the worker catches nothing.
     *
     * @return void
     */
    public function testAnExceptionInARouteIsAResponseAndNotAWorkerError(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/throw'))->assertInternalServerError();

        $this->serve(self::octaneRequest('POST', '/echo'))->assertOk();
    }

    /**
     * Serving a request before the worker has booted fails with what to do.
     *
     * @return void
     */
    public function testServingBeforeTheWorkerHasBootedFailsTheTest(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Boot the Octane worker before serving a request.');

        $this->serve(self::octaneRequest('GET', '/sandbox'));
    }

    /**
     * Every response is the one for its own request, however many came before.
     *
     * @return void
     */
    public function testEachResponseIsTheOneForItsRequest(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('POST', '/echo', ['name' => 'first']))->assertJsonPath('name', 'first');
        $this->serve(self::octaneRequest('POST', '/echo', ['name' => 'second']))->assertJsonPath('name', 'second');
        $this->serve(self::octaneRequest('POST', '/echo', ['name' => 'third']))->assertJsonPath('name', 'third');
    }

    /**
     * Configuration a request changes stays in its sandbox: neither the next
     * request nor the booted application sees it.
     *
     * @return void
     */
    public function testConfigurationSetInARequestDoesNotReachTheNext(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/config'))->assertExactJson(['value' => null]);
        $this->serve(self::octaneRequest('GET', '/config'))->assertExactJson(['value' => null]);

        self::assertNull(app(ConfigRepository::class)->get('harness.value'));
    }

    /**
     * Between requests the booted application is current again, and the test
     * can open a new database connection, which reads the configuration through
     * the application the database manager holds.
     *
     * @return void
     */
    public function testTheBootedApplicationIsCurrentBetweenRequests(): void
    {
        $root = $this->octaneApplication();

        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/sandbox'))->assertOk();

        self::assertSame($root, Container::getInstance());
        self::assertSame($root, Facade::getFacadeApplication());

        $config = app(ConfigRepository::class);

        $config->set('database.connections.harness', $config->get('database.connections.' . self::CONNECTION));

        try {
            self::assertEquals(1, DB::connection('harness')->scalar('select 1'));
        } finally {
            DB::purge('harness');
        }
    }

    /**
     * A request comes from a client, asks for JSON, and carries the identifying
     * server variables that were given and no others.
     *
     * @return void
     */
    public function testAnOctaneRequestDescribesItsClient(): void
    {
        $request = self::octaneRequest('POST', '/echo', ['name' => 'first']);

        self::assertSame('POST', $request->getMethod());
        self::assertSame('first', $request->input('name'));
        self::assertSame('203.0.113.7', $request->ip());
        self::assertSame('OctaneTest/1.0', $request->userAgent());
        self::assertTrue($request->expectsJson());
        self::assertNull($request->bearerToken());
    }

    /**
     * The bearer token, the address and any other server variable can be given,
     * and a server variable given replaces the default.
     *
     * @return void
     */
    public function testAnOctaneRequestTakesTheClientItIsGiven(): void
    {
        $request = self::octaneRequest('GET', '/echo', [], 'a-token', '198.51.100.9', ['HTTP_USER_AGENT' => 'Other/2.0', 'HTTP_X_REQUEST_ID' => 'an-id']);

        self::assertSame('a-token', $request->bearerToken());
        self::assertSame('198.51.100.9', $request->ip());
        self::assertSame('Other/2.0', $request->userAgent());
        self::assertSame('an-id', $request->header('X-Request-Id'));
    }

    /**
     * Make the next request fail outside the HTTP kernel, where the worker
     * catches it. Octane streams what it catches to standard error only in the
     * local and testing environments, so the test leaves them for its output to
     * stay PHPUnit's.
     *
     * @return void
     */
    private function failTheNextRequestOutsideTheKernel(): void
    {
        $this->app?->instance('env', 'worker-harness');

        $this->failNextRequest = true;
    }

    /**
     * The application the request is running in.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function currentApplication(): Application
    {
        $application = Container::getInstance();

        self::assertInstanceOf(Application::class, $application);

        return $application;
    }

    /**
     * Close the output buffers a request left open. The worker opens one around
     * each request and closes it only when the kernel returns a response.
     *
     * @param  int  $level
     * @return void
     */
    private static function closeOutputBuffersAbove(int $level): void
    {
        while (ob_get_level() > $level) {
            ob_end_clean();
        }
    }
}
