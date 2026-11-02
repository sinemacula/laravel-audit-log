<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\Fixtures\Jobs\RecordingJob;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for the package booted as it is under PHP-FPM, where
 * `runningInConsole()` is false. Every other test runs in the console, so only
 * these fail if the HTTP frame or a listener is ever registered behind that
 * check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S3011")
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class OutsideTheConsoleTest extends TestCase
{
    /** @var string The address a request comes from. */
    private const string CLIENT_IP = '203.0.113.7';

    /**
     * The application believes it is not in the console, and the test can tell.
     *
     * @return void
     */
    public function testTheApplicationIsNotInTheConsole(): void
    {
        self::assertFalse($this->app?->runningInConsole());
    }

    /**
     * A request has the HTTP origin and the client's address, which only an
     * HTTP frame gives it.
     *
     * @return void
     */
    public function testARequestRecordsTheHttpOriginAndTheClient(): void
    {
        Route::get('/run', static fn (): string => AuditLog::record('invoice.approved')->id)->name('run');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/run')->assertOk();

        $entry = AuditEntry::query()->sole();

        self::assertSame('http', $entry->origin);
        self::assertSame(self::CLIENT_IP, $entry->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'run'], $entry->context);
    }

    /**
     * A job a request runs has the queue origin, its class and the request's
     * actor, and the request comes back when it ends.
     *
     * @return void
     */
    public function testAJobInARequestHasItsFrameAndItsDispatcher(): void
    {
        Route::get('/run', static function (): string {
            Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 42]));

            Bus::dispatchSync(new RecordingJob);

            return AuditLog::record('invoice.approved')->id;
        });

        $this->get('/run')->assertOk();

        $job = AuditEntry::query()->where('event', RecordingJob::CODE)->sole();

        self::assertSame('queue', $job->origin);
        self::assertEquals(['job' => RecordingJob::class], $job->context);
        self::assertSame('42', $job->actor_id);
        self::assertSame('http', AuditEntry::query()->where('event', 'invoice.approved')->sole()->origin);
    }

    /**
     * The middleware is at the head of the kernel's global stack.
     *
     * @return void
     */
    public function testTheHttpFrameMiddlewareIsFirst(): void
    {
        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);
        self::assertSame(EnterHttpFrame::class, $kernel->getGlobalMiddleware()[0] ?? null);
    }

    /**
     * Rows of `[event, listener]`: each event the package listens to.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideListeners(): iterable
    {
        yield from [
            'a command starting'   => [CommandStarting::class, TrackCommandFrames::class],
            'a command finishing'  => [CommandFinished::class, TrackCommandFrames::class],
            'a job starting'       => [JobProcessing::class, TrackJobFrames::class],
            'a job processed'      => [JobProcessed::class, TrackJobFrames::class],
            'a job failed'         => [JobFailed::class, TrackJobFrames::class],
            'a job exception'      => [JobExceptionOccurred::class, TrackJobFrames::class],
            'a payload being made' => [ContextDehydrating::class, CarryContextIntoJobs::class],
        ];
    }

    /**
     * Each listener is registered once.
     *
     * @param  class-string  $event
     * @param  class-string  $listener
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testEachListenerIsRegistered(string $event, string $listener): void
    {
        self::assertSame([$listener], array_values(array_filter(
            Event::getRawListeners()[$event] ?? [],
            static fn (mixed $registered): bool => is_string($registered) && str_starts_with($registered, 'SineMacula\\'),
        )));
    }

    /**
     * Make the application believe it is not in the console, as under PHP-FPM,
     * before any provider asks it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        (new \ReflectionProperty(Application::class, 'isRunningInConsole'))->setValue($app, false);
    }
}
