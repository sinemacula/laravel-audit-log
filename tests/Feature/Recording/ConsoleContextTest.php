<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\Fixtures\Commands\CallingCommand;
use Tests\Fixtures\Commands\NestingCommand;
use Tests\Fixtures\Commands\RecordingCommand;
use Tests\Fixtures\Commands\ThrowingCommand;
use Tests\Fixtures\Providers\AuditsFrameEndsProvider;
use Tests\TestCase;

/**
 * End-to-end tests for a record made from a real Artisan command: its origin
 * and name, a nested call restoring its caller on success and on failure, a
 * command inside a request, and that Laravel's placeholder console request is
 * never read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrackCommandFrames::class)]
#[CoversClass(ExecutionFrames::class)]
#[CoversClass(OriginContributor::class)]
#[CoversClass(RequestContributor::class)]
final class ConsoleContextTest extends TestCase
{
    use WithConsoleEvents;

    /** @var string The code the commands' inner work records. */
    private const string INNER = 'command.inner';

    /** @var string The address a request comes from. */
    private const string CLIENT_IP = '203.0.113.7';

    /**
     * Register the commands, and surface a failure inside a route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();

        Artisan::registerCommand(new RecordingCommand);
        Artisan::registerCommand(new ThrowingCommand);
        Artisan::registerCommand(new CallingCommand);
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
     * A command's record has the console origin and the command's name, and its
     * frame is gone when it ends.
     *
     * @return void
     */
    public function testACommandRecordsTheConsoleOriginAndItsName(): void
    {
        self::assertSame(0, Artisan::call(RecordingCommand::NAME));

        $entry = $this->entry(RecordingCommand::CODE);

        self::assertSame('console', $entry->origin);
        self::assertEquals(['command' => RecordingCommand::NAME], $entry->context);
        self::assertNull($this->frames()->current());
    }

    /**
     * A nested Artisan call's record has its own name, not its caller's.
     *
     * @return void
     */
    public function testANestedArtisanCallRecordsItsOwnName(): void
    {
        $this->nest(static function (): void {
            Artisan::call(RecordingCommand::NAME, ['code' => self::INNER]);
        });

        self::assertEquals(['command' => RecordingCommand::NAME], $this->entry(self::INNER)->context);
    }

    /**
     * When a nested call ends, its caller's name comes back.
     *
     * @return void
     */
    public function testANestedArtisanCallRestoresItsCaller(): void
    {
        $this->nest(static function (): void {
            Artisan::call(RecordingCommand::NAME, ['code' => self::INNER]);
        });

        self::assertEquals(['command' => NestingCommand::NAME], $this->entry(NestingCommand::BEFORE)->context);
        self::assertEquals(['command' => NestingCommand::NAME], $this->entry(NestingCommand::AFTER)->context);
        self::assertNull($this->frames()->current());
    }

    /**
     * When a nested call throws, its caller's name comes back too.
     *
     * @return void
     */
    public function testAFailingNestedArtisanCallRestoresItsCaller(): void
    {
        $this->nest(static function (): void {
            Artisan::call(ThrowingCommand::NAME);
        });

        self::assertEquals(['command' => ThrowingCommand::NAME], $this->entry(ThrowingCommand::CODE)->context);
        self::assertEquals(['command' => NestingCommand::NAME], $this->entry(NestingCommand::AFTER)->context);
        self::assertNull($this->frames()->current());
    }

    /**
     * Three levels unwind one at a time.
     *
     * @return void
     */
    public function testEachLevelOfDeepNestingRestoresItsOwnCaller(): void
    {
        $this->nest(static function (): void {
            Artisan::call(CallingCommand::NAME);
            Artisan::call(RecordingCommand::NAME, ['code' => self::INNER]);
        });

        self::assertEquals(['command' => CallingCommand::NAME], $this->entry(CallingCommand::INNER_CODE)->context);
        self::assertEquals(['command' => RecordingCommand::NAME], $this->entry(self::INNER)->context);
        self::assertEquals(['command' => NestingCommand::NAME], $this->entry(NestingCommand::AFTER)->context);
    }

    /**
     * Inside a request, a command's record is console with the request's id and
     * no client, and the request's own frame comes back when it ends.
     *
     * @return void
     */
    public function testACommandInARequestRestoresTheRequest(): void
    {
        Route::get('/run', static function (): string {
            AuditLog::record('route.before');
            Artisan::call(RecordingCommand::NAME, ['code' => self::INNER]);
            AuditLog::record('route.after');

            return 'ok';
        })->name('run');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/run')->assertOk();

        $inner = $this->entry(self::INNER);
        $after = $this->entry('route.after');

        self::assertSame('console', $inner->origin);
        self::assertNull($inner->ip);
        self::assertEquals(['command' => RecordingCommand::NAME], $inner->context);
        self::assertSame('http', $after->origin);
        self::assertSame(self::CLIENT_IP, $after->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'run'], $after->context);
        self::assertSame($this->entry('route.before')->request_id, $inner->request_id);
        self::assertSame($this->entry('route.before')->request_id, $after->request_id);
    }

    /**
     * Inside a request, a command that throws gives the frame back as well.
     *
     * @return void
     */
    public function testAFailingCommandInARequestRestoresTheRequest(): void
    {
        Route::get('/run', static function (): string {
            try {
                Artisan::call(ThrowingCommand::NAME);
            } catch (\Throwable) {
                AuditLog::record('route.after');
            }

            return 'ok';
        })->name('run');

        $this->withServerVariables(['REMOTE_ADDR' => self::CLIENT_IP])->get('/run')->assertOk();

        $after = $this->entry('route.after');

        self::assertSame('console', $this->entry(ThrowingCommand::CODE)->origin);
        self::assertSame('http', $after->origin);
        self::assertSame(self::CLIENT_IP, $after->ip);
        self::assertEquals(['method' => 'GET', 'route' => 'run'], $after->context);
    }

    /**
     * A command whose record is the request's first still has the request's
     * trusted id, so nothing replaces it for the rest of the request.
     *
     * @return void
     */
    public function testACommandInARequestKeepsItsTrustedRequestId(): void
    {
        TrustProxies::at('127.0.0.1');

        app(ConfigRepository::class)->set('audit-log.context.trust_request_id', true);

        Route::get('/run', static function (): string {
            Artisan::call(RecordingCommand::NAME, ['code' => self::INNER]);
            AuditLog::record('route.after');

            return 'ok';
        });

        $this->withHeader('X-Request-Id', 'edge-request-1')->get('/run')->assertOk();

        self::assertSame('edge-request-1', $this->entry(self::INNER)->request_id);
        self::assertSame('edge-request-1', $this->entry('route.after')->request_id);
    }

    /**
     * `$this->call()` dispatches no console event, so what it runs keeps the
     * name of the command that called it.
     *
     * @return void
     */
    public function testThisCallKeepsTheCallersName(): void
    {
        self::assertSame(0, Artisan::call(CallingCommand::NAME));

        self::assertEquals(['command' => CallingCommand::NAME], $this->entry(CallingCommand::INNER_CODE)->context);
    }

    /**
     * Laravel's placeholder console request, however it is dressed, is never a
     * frame: a command's record has no client, route or method from it.
     *
     * @return void
     */
    public function testThePlaceholderRequestFillsNoClientOrRoute(): void
    {
        $this->app?->instance('request', Request::create('/placeholder', 'POST', server: ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => 'Example/1.0']));

        Artisan::call(RecordingCommand::NAME);

        $entry = $this->entry(RecordingCommand::CODE);

        self::assertNull($entry->ip);
        self::assertNull($entry->user_agent);
        self::assertEquals(['command' => RecordingCommand::NAME], $entry->context);
    }

    /**
     * Outside any frame the origin is console, with no name.
     *
     * @return void
     */
    public function testARecordOutsideAnyFrameIsConsole(): void
    {
        AuditLog::record('invoice.approved');

        $entry = $this->entry('invoice.approved');

        self::assertSame('console', $entry->origin);
        self::assertNull($entry->context);
        self::assertNull($entry->ip);
        self::assertNotNull($entry->request_id);
    }

    /**
     * Recording goes by the frame and not by `runningInConsole()`, which is
     * true here, so a request is still `http`.
     *
     * @return void
     */
    public function testNoBranchOnRunningInConsole(): void
    {
        self::assertTrue($this->app?->runningInConsole());

        Route::get('/run', static fn (): string => AuditLog::record('invoice.approved')->id);

        $this->get('/run')->assertOk();

        self::assertSame('http', $this->entry('invoice.approved')->origin);
    }

    /**
     * A listener on `CommandFinished` that a provider's `boot()` adds runs
     * before the frame ends, so what it records has the command's origin and
     * name.
     *
     * @return void
     */
    public function testAListenerOnCommandFinishedRunsInTheCommandFrame(): void
    {
        app(ConfigRepository::class)->set(AuditsFrameEndsProvider::SWITCH, true);

        Artisan::registerCommand(new RecordingCommand);

        self::assertSame(0, Artisan::call(RecordingCommand::NAME));

        $entry = $this->entry(AuditsFrameEndsProvider::COMMAND_FINISHED);

        self::assertSame('console', $entry->origin);
        self::assertEquals(['command' => RecordingCommand::NAME], $entry->context);
    }

    /**
     * List the provider that audits a command's end, booted after the package's
     * as an application's is.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [...parent::getPackageProviders($app), AuditsFrameEndsProvider::class];
    }

    /**
     * Register and run the nesting command around the inner work.
     *
     * @param  \Closure(): void  $inner
     * @return void
     */
    private function nest(\Closure $inner): void
    {
        Artisan::registerCommand(new NestingCommand($inner));

        self::assertSame(0, Artisan::call(NestingCommand::NAME));
    }

    /**
     * The one entry stored under the code.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function entry(string $code): AuditEntry
    {
        return AuditEntry::query()->where('event', $code)->sole();
    }

    /**
     * The frames of the current scope.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }
}
