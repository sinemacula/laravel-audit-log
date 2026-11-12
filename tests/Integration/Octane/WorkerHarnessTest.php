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
 * Tests for the harness that serves requests through one Octane worker; no
 * package class is under test.
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
     * A request reaches its route through the worker, and its response returns.
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
     * Each request runs in a sandbox cloned from the booted application.
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
     * An error the worker catches outside the kernel fails the test.
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
     * A worker error for one request does not fail the next.
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
     * A route's exception is an error response, not a worker error.
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
     * Configuration set in a request does not reach the next.
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
     * Between requests the booted application is current again.
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
     * A request has a client, asks for JSON and carries the variables given.
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
     * A request takes the bearer token, address and server variables given.
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
     * Make the next request fail outside the kernel; Octane prints what it
     * catches only in local and testing, so leave both.
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
     * Close the output buffers a request left open; the worker closes its own
     * only when the kernel responds.
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
