<?php

declare(strict_types = 1);

namespace Tests\Integration\Capture;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\TestCase;

/**
 * Integration tests for the capture of Laravel's authentication events on
 * whichever engine the suite runs against, through the provider's wiring and
 * real guards: each core event written as one row the engine reads back, the
 * identifier hash of a failure correlating an identifier whose user is known
 * with the same identifier once no user has it, and fifty bearer-style requests
 * that each announce their user writing nothing, while a mapping makes the
 * routing bridge hear every one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordLaravelAuthEvent::class)]
#[CoversClass(CaptureMappedEvent::class)]
final class AuthCaptureEnginesTest extends TestCase
{
    /** @var string The key identifiers are hashed under. */
    private const string REDACTION_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The email address of the user who signs in. */
    private const string EMAIL = 'alice@example.com';

    /** @var string The token a bearer-style request carries. */
    private const string TOKEN = 'bearer-token-of-alice';

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Create the users' table on the engine, and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Each of the ten core events, fired by a real guard where Laravel fires
     * it, writes one row the engine reads back with its code, outcome, actor,
     * subject and guard.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testEachCoreEventRecordsOneRowOnTheEngine(): void
    {
        $user  = self::newUser(self::EMAIL);
        $id    = (string) $user->id;
        $guard = Auth::guard('web');

        self::assertInstanceOf(SessionGuard::class, $guard);

        $guard->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);
        $guard->attempt(['email' => self::EMAIL, 'password' => SigningInUser::PASSWORD]);
        $guard->logoutCurrentDevice();
        $guard->login($user);
        $guard->logoutOtherDevices(SigningInUser::PASSWORD);
        $guard->logout();

        Event::dispatch(new Lockout(Request::create('/login', 'POST', ['email' => self::EMAIL], [], [], ['REMOTE_ADDR' => '203.0.113.9'])));
        Event::dispatch(new Registered($user));
        Event::dispatch(new Verified($user));
        Event::dispatch(new PasswordResetLinkSent($user));
        Event::dispatch(new PasswordReset($user));

        self::assertSame(
            [
                [CapturedActivity::SIGN_IN_FAILED->value, 'failure', null, $id, 'web'],
                [CapturedActivity::SIGNED_IN->value, 'success', $id, $id, 'web'],
                [CapturedActivity::SIGNED_OUT->value, 'success', $id, $id, 'web'],
                [CapturedActivity::SIGNED_IN->value, 'success', $id, $id, 'web'],
                [CapturedActivity::SIGNED_OUT_OTHER_DEVICES->value, 'success', $id, $id, 'web'],
                [CapturedActivity::SIGNED_OUT->value, 'success', $id, $id, 'web'],
                [CapturedActivity::LOCKED_OUT->value, 'denied', null, null, null],
                [CapturedActivity::REGISTERED->value, 'success', $id, $id, null],
                [CapturedActivity::EMAIL_VERIFIED->value, 'success', $id, $id, null],
                [CapturedActivity::PASSWORD_RESET_REQUESTED->value, 'success', null, $id, null],
                [CapturedActivity::PASSWORD_RESET->value, 'success', $id, $id, null],
            ],
            array_map(static fn (AuditEntry $entry): array => [$entry->event, $entry->outcome, $entry->actor_id, $entry->subject_id, $entry->guard], $this->entries()),
        );
        self::assertSame(['remember' => false], $this->entries()[1]->properties);
        self::assertSame('203.0.113.9', $this->entries()[6]->ip);
        self::assertSame([], $this->failures);
    }

    /**
     * A failure's identifier hash correlates an identifier whose user is known
     * with the same identifier once no user has it, and tells it from another
     * identifier, as the engine stores and returns it.
     *
     * @return void
     */
    public function testTheIdentifierHashCorrelatesAKnownAndAnUnknownUser(): void
    {
        $user = self::newUser(self::EMAIL);

        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);

        $user->delete();

        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);
        Auth::guard('web')->attempt(['email' => 'bob@example.com', 'password' => 'wrong-password']);

        [$known, $unknown, $other] = array_map(self::hashOf(...), $this->entries());

        self::assertSame([SigningInUser::class, null, null], array_map(static fn (AuditEntry $entry): ?string => $entry->subject_type, $this->entries()));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $known);
        self::assertSame($known, $unknown);
        self::assertNotSame($known, $other);
    }

    /**
     * Fifty bearer-style requests, each finding its user by its token and
     * announcing it as `Authenticated`, write nothing, though a mapping makes
     * the routing bridge hear every one of them.
     *
     * @return void
     */
    public function testFiftyBearerStyleRequestsGiveNoRow(): void
    {
        self::newUser(self::EMAIL, self::TOKEN);

        $announced = 0;

        Event::listen(Authenticated::class, static function () use (&$announced): void {
            $announced++;
        });

        Route::get('/api/me', static function (): string {
            $user = Auth::guard('api')->user();

            Event::dispatch(new Authenticated('api', $user));

            return $user instanceof SigningInUser ? 'found' : 'missing';
        });

        self::assertTrue(Event::hasWildcardListeners(Authenticated::class));

        for ($request = 0; $request < 50; $request++) {
            $this->get('/api/me', ['Authorization' => 'Bearer ' . self::TOKEN])->assertOk()->assertSeeText('found');

            Auth::forgetGuards();
        }

        self::assertSame(50, $announced);
        self::assertSame([], $this->entries());
        self::assertSame([], $this->failures);
    }

    /**
     * Sign users in from the test's users' table without waiting and with a
     * cheap hash, add a token guard that finds them by their remember token,
     * set the key identifiers are hashed under, and map the portal events while
     * the application boots, so the routing bridge listens.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('audit-log.redaction.key', self::REDACTION_KEY);
        $config->set('auth.providers.users.model', SigningInUser::class);
        $config->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users', 'storage_key' => 'remember_token']);
        $config->set('auth.timebox_duration', 0);
        $config->set('hashing.bcrypt.rounds', 4);

        app()->booting(static function (Application $app): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
        });
    }

    /**
     * Every row written, oldest first.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Models\AuditEntry>
     */
    private function entries(): array
    {
        return array_values(AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all());
    }

    /**
     * The identifier hash the row keeps.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return string
     */
    private static function hashOf(AuditEntry $entry): string
    {
        $hash = $entry->properties['_audit']['identifier_hash'] ?? null;

        self::assertIsString($hash);

        return $hash;
    }

    /**
     * Create the users' table on the test's connection, and drop it before the
     * application is destroyed.
     *
     * @return void
     */
    private function createUsersTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(SigningInUser::TABLE);
        $schema->create(SigningInUser::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email', 191)->unique();
            $table->string('password', 191);
            $table->rememberToken();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(SigningInUser::TABLE);
        });
    }

    /**
     * A saved user of the email address, with the password every user is made
     * with and the remember token given.
     *
     * @param  string  $email
     * @param  ?string  $rememberToken
     * @return \Tests\Fixtures\Capture\Models\SigningInUser
     */
    private static function newUser(string $email, #[\SensitiveParameter] ?string $rememberToken = null): SigningInUser
    {
        return SigningInUser::query()->create(['email' => $email, 'password' => SigningInUser::PASSWORD, 'remember_token' => $rememberToken]);
    }
}
