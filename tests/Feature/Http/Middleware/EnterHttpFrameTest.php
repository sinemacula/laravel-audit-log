<?php

declare(strict_types = 1);

namespace Tests\Feature\Http\Middleware;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * Feature tests for the middleware that starts a request's execution frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnterHttpFrame::class)]
final class EnterHttpFrameTest extends TestCase
{
    /**
     * Bind the runtime state as the provider binds it, which it leaves alone
     * once it binds it itself.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->scopedIf(ExecutionFrames::class);
        $this->app?->scopedIf(RequestIdentity::class);
    }

    /**
     * The request's frame is entered before the rest of the stack runs, so what
     * runs next already has the request and the HTTP origin.
     *
     * @return void
     */
    public function testEntersAFrameForTheRequest(): void
    {
        $request = Request::create('/invoices');
        $frames  = $this->frames();
        $seen    = null;

        $this->handle($request, static function () use ($frames, &$seen): Response {
            $seen = [$frames->request(), $frames->origin()];

            return new Response;
        });

        self::assertSame([$request, Origin::HTTP], $seen);
    }

    /**
     * Entering a request replaces whatever frames were on the stack, so a
     * request after a stale command frame is not beneath it.
     *
     * @return void
     */
    public function testReplacesAnyEarlierFrames(): void
    {
        $this->frames()->enterCommand(new ArrayInput([]), 'invoices:send');

        $request = Request::create('/invoices');

        $this->handle($request);

        self::assertSame($request, $this->frames()->request());
    }

    /**
     * Every package key an earlier request left is gone before the rest of the
     * stack runs, so a record in it gets a new request id and no earlier actor.
     *
     * @return void
     */
    public function testForgetsTheIdentityOfAnEarlierRequest(): void
    {
        Context::addHidden([
            CarriedContext::REQUEST_ID  => 'app:request-1',
            CarriedContext::TRACE_ID    => '4bf92f3577b34da6a3ce929d0e0e4736',
            CarriedContext::ACTOR_TYPE  => 'App\Models\User',
            CarriedContext::ACTOR_ID    => '42',
            CarriedContext::ACTOR_GUARD => 'web',
        ]);

        $seen = null;

        $this->handle(Request::create('/invoices'), static function () use (&$seen): Response {
            $seen = Context::allHidden();

            return new Response;
        });

        self::assertSame([], $seen);
    }

    /**
     * An application's own Context, visible or hidden, goes through untouched.
     *
     * @return void
     */
    public function testLeavesTheRestOfContextAlone(): void
    {
        Context::add('tenant', 'acme');
        Context::addHidden('app.secret', 'kept');
        Context::addHidden(CarriedContext::REQUEST_ID, 'app:request-1');

        $this->handle(Request::create('/invoices'));

        self::assertSame(['tenant' => 'acme'], Context::all());
        self::assertSame(['app.secret' => 'kept'], Context::allHidden());
    }

    /**
     * The middleware generates no request id: identity stays lazy, so a request
     * that records nothing costs nothing.
     *
     * @return void
     */
    public function testGeneratesNoIdentity(): void
    {
        $this->handle(Request::create('/invoices'));

        self::assertSame([], Context::allHidden());
    }

    /**
     * The response the rest of the stack gives is the one returned, and the
     * request passed on is the one that came in.
     *
     * @return void
     */
    public function testPassesTheResponseOn(): void
    {
        $request  = Request::create('/invoices');
        $response = new Response('done', 202);
        $seen     = null;

        $returned = $this->handle($request, static function (Request $passed) use ($response, &$seen): Response {
            $seen = $passed;

            return $response;
        });

        self::assertSame($response, $returned);
        self::assertSame($request, $seen);
    }

    /**
     * The frame outlives the response and the kernel's termination, so a
     * `terminating()` callback keeps its request.
     *
     * @return void
     */
    public function testTheFrameOutlivesTheResponse(): void
    {
        self::assertFalse((new \ReflectionClass(EnterHttpFrame::class))->hasMethod('terminate'));

        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $kernel->prependMiddleware(EnterHttpFrame::class);

        Route::get('/invoices', static fn (): string => 'done');

        $frames = $this->frames();
        $seen   = null;

        app()->terminating(static function () use ($frames, &$seen): void {
            $seen = $frames->request()?->path();
        });

        $this->get('/invoices')->assertOk();

        self::assertSame('invoices', $seen);
        self::assertSame('invoices', $frames->request()?->path());
        self::assertSame(Origin::HTTP, $frames->origin());
    }

    /**
     * A failure in the rest of the stack leaves the frame in place, so what the
     * exception handler records still has the request.
     *
     * @return void
     */
    public function testTheFrameSurvivesAFailure(): void
    {
        $request = Request::create('/invoices');

        try {
            $this->handle($request, static function (): Response {
                throw new \RuntimeException('The controller failed.');
            });

            self::fail('Expected the failure to reach the caller.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The controller failed.', $exception->getMessage());
        }

        self::assertSame($request, $this->frames()->request());
    }

    /**
     * Run the request through the middleware, with what comes next.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  ?\Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function handle(Request $request, ?\Closure $next = null): Response
    {
        return app(EnterHttpFrame::class)->handle($request, $next ?? static fn (): Response => new Response);
    }

    /**
     * The frames of the current container.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }
}
