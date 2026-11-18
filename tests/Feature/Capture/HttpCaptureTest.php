<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\Concerns\CreatesSigningInUsers;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\TestCase;

/**
 * Feature tests for sign-ins and Gate denials captured inside an HTTP request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordLaravelAuthEvent::class)]
#[CoversClass(RecordGateDenial::class)]
#[CoversClass(EnterHttpFrame::class)]
final class HttpCaptureTest extends TestCase
{
    use CreatesSigningInUsers;

    /** @var string The address of the user who signs in. */
    private const string LOGIN = 'alice@example.com';

    /** @var array<string, string> The server variables of each request: the client's address and agent. */
    private const array CLIENT = ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'Example/1.0'];

    /** @var string The ability the Gate denies. */
    private const string ABILITY = 'approve-invoice';

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Create the users' table and a sign-in route, and hear capture failures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();

        Route::post('/login', static function (Request $request): string {
            $signedIn = Auth::guard('web')->attempt(['email' => self::LOGIN, 'password' => $request->string('password')->toString()]);

            AuditLog::record('invoice.approved');

            return $signedIn ? 'in' : 'out';
        })->name('login');

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * A sign-in in a route has the request's origin, client, route and request
     * id.
     *
     * @return void
     */
    public function testASignInCarriesTheRequestContext(): void
    {
        self::newUser(self::LOGIN);

        $this->login(SigningInUser::PASSWORD)->assertSeeText('in');

        $entry = $this->entry(CapturedActivity::SIGNED_IN->value);

        self::assertHttpContext($entry, 'login');
        self::assertSame($this->entry('invoice.approved')->request_id, $entry->request_id);
        self::assertSame([], $this->failures);
    }

    /**
     * A sign-in refused for bad credentials has the request's context.
     *
     * @return void
     */
    public function testAFailedSignInCarriesTheRequestContext(): void
    {
        self::newUser(self::LOGIN);

        $this->login('wrong-password')->assertSeeText('out');

        $entry = $this->entry(CapturedActivity::SIGN_IN_FAILED->value);

        self::assertHttpContext($entry, 'login');
        self::assertSame($this->entry('invoice.approved')->request_id, $entry->request_id);
        self::assertSame([], $this->failures);
    }

    /**
     * A `can:` middleware denial is one row with the request's context, and the
     * response stays 403.
     *
     * @return void
     */
    public function testACanMiddlewareDenialCarriesTheRequestContext(): void
    {
        app(ConfigRepository::class)->set('audit-log.capture.gate.enabled', true);

        Gate::define(self::ABILITY, static fn (): bool => false);

        Route::post('/invoices/{invoice}/approve', static fn (): string => 'approved')
            ->name('invoices.approve')
            ->middleware('can:' . self::ABILITY);

        $this->actingAs(self::newUser(self::LOGIN), 'web')
            ->withServerVariables(self::CLIENT)
            ->post('/invoices/42/approve')
            ->assertForbidden();

        $entry = $this->entry(CapturedActivity::GATE_DENIED->value);

        self::assertSame(self::ABILITY, $entry->properties['ability'] ?? null);
        self::assertHttpContext($entry, 'invoices.approve');
        self::assertSame([], $this->failures);
    }

    /**
     * Sign in quickly, against the signing-in users.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.providers.users.model', SigningInUser::class);
        $config->set('auth.timebox_duration', 0);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('session.driver', 'array');
    }

    /**
     * Assert the entry has the HTTP origin, the client, a request id and the
     * named route of a POST.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @param  string  $route
     * @return void
     */
    private static function assertHttpContext(AuditEntry $entry, string $route): void
    {
        self::assertSame(['http', ...array_values(self::CLIENT)], [$entry->origin, $entry->ip, $entry->user_agent]);
        self::assertEquals(['method' => 'POST', 'route' => $route], $entry->context);
        self::assertNotNull($entry->request_id);
    }

    /**
     * Post the sign-in form with the password, from the client.
     *
     * @param  string  $password
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function login(#[\SensitiveParameter] string $password): TestResponse
    {
        return $this->withServerVariables(self::CLIENT)->post('/login', ['password' => $password])->assertOk();
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
}
