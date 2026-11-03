<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\SessionGuard;
use Illuminate\Auth\TokenGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the capture of Laravel's own authentication events through
 * the provider's wiring and the real dispatcher, each written as a row: one per
 * sign-in, restore, failure, lockout, sign-out and account event, a failure
 * keeping only its identifier's hash; none for the events never recorded, for
 * `Auth::once()`, `onceUsingId()` and a token guard that fires no event; the
 * guards configured out skipped, the wildcard turning core capture off; and an
 * application's mapping of `Login` beside the core listener writing one row per
 * event object.
 *
 * The guards sign a real user in: its table is created for each test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordLaravelAuthEvent::class)]
#[CoversClass(CaptureCoordinator::class)]
final class LaravelAuthEventsTest extends TestCase
{
    /** @var string The key identifiers are hashed under. */
    private const string REDACTION_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The email address of the user who signs in. */
    private const string EMAIL = 'alice@example.com';

    /** @var string The email address of a second user. */
    private const string OTHER_EMAIL = 'bob@example.com';

    /** @var string A remember token a user holds. */
    private const string REMEMBER_TOKEN = 'remember-token-of-alice';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Create the users' table, bind the reporter, and hear each capture
     * failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * A sign-in through `attempt()` writes one row: the sign-in code, the user
     * as actor and subject, the guard, and whether it was remembered; the
     * attempt, the validation and the authentication around it write none.
     *
     * @return void
     */
    public function testASignInRecordsOneRow(): void
    {
        $user = self::newUser(self::EMAIL);

        self::assertTrue(Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => SigningInUser::PASSWORD], true));

        $entry = $this->onlyEntry();

        self::assertSame([CapturedActivity::SIGNED_IN->value, 'success'], [$entry->event, $entry->outcome]);
        self::assertSame(self::userAsActorAndSubject($user), self::actorAndSubject($entry));
        self::assertSame('web', $entry->guard);
        self::assertSame(['remember' => true], $entry->properties);
        self::assertSame(['security', 1], [$entry->category, $entry->event_version]);
        self::assertSame([], $this->failures);
    }

    /**
     * A user the session guard restores from a remember-me cookie writes one
     * session-restored row, read from that guard.
     *
     * @return void
     */
    public function testARecallerRestoreIsASessionRestore(): void
    {
        $user = self::newUser(self::EMAIL, self::REMEMBER_TOKEN);

        self::assertSame($user->id, $this->restore($user)->user()?->getAuthIdentifier());

        $entry = $this->onlyEntry();

        self::assertSame(CapturedActivity::SESSION_RESTORED->value, $entry->event);
        self::assertSame(self::userAsActorAndSubject($user), self::actorAndSubject($entry));
        self::assertSame(['web', ['remember' => true]], [$entry->guard, $entry->properties]);
    }

    /**
     * Whether a sign-in was restored is the guard's state, so an explicit
     * sign-in on the same guard after a restore is recorded as a restore too,
     * as the documentation says; the same sign-in on another guard is a
     * sign-in.
     *
     * @return void
     */
    public function testAnExplicitLoginAfterARestoreOnTheSameGuardIsTheDocumentedMisclassification(): void
    {
        $user  = self::newUser(self::EMAIL, self::REMEMBER_TOKEN);
        $other = self::newUser(self::OTHER_EMAIL);
        $guard = $this->restore($user);

        $guard->user();
        $guard->login($other);

        Auth::guard('admin')->login($other);

        self::assertSame(
            [
                [CapturedActivity::SESSION_RESTORED->value, 'web', (string) $user->id],
                [CapturedActivity::SESSION_RESTORED->value, 'web', (string) $other->id],
                [CapturedActivity::SIGNED_IN->value, 'admin', (string) $other->id],
            ],
            array_map(static fn (AuditEntry $entry): array => [$entry->event, $entry->guard, $entry->subject_id], $this->entries()),
        );
    }

    /**
     * A failed sign-in keeps only its identifier's hash: neither the email
     * address, the password, a one-time code nor a PIN reaches the row, whether
     * `attempt()` fired the failure or a flow checking a second factor did.
     *
     * @return void
     */
    public function testAFailedSignInKeepsOnlyTheIdentifierHash(): void
    {
        $user        = self::newUser(self::EMAIL);
        $credentials = ['email' => self::EMAIL, 'password' => 'wrong-password', 'otp' => 'otp-s3cr3t-qq', 'pin' => 'pin-s3cr3t-zz'];

        self::assertFalse(Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']));

        Event::dispatch(new Failed('web', $user, $credentials));

        $entries = $this->entries();

        self::assertCount(2, $entries);

        foreach ($entries as $entry) {
            self::assertSame([CapturedActivity::SIGN_IN_FAILED->value, 'failure', 'web'], [$entry->event, $entry->outcome, $entry->guard]);
            self::assertSame([null, null, SigningInUser::class, (string) $user->id], self::actorAndSubject($entry));
            self::assertSame(['_audit' => ['identifier_hash' => self::hashOf($entries[0])]], $entry->properties);

            foreach ($credentials as $credential) {
                self::assertStringNotContainsString($credential, self::rowOf($entry));
            }
        }
    }

    /**
     * A failed sign-in of an identifier no user has any more is the same
     * failure with no subject, under the same hash its user's failures had; an
     * identifier no user ever had hashes otherwise.
     *
     * @return void
     */
    public function testAFailedSignInOfAnUnknownUserIsRecordedWithTheSameHash(): void
    {
        $user = self::newUser(self::EMAIL);

        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);

        $user->delete();

        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);
        Auth::guard('web')->attempt(['email' => self::OTHER_EMAIL, 'password' => 'wrong-password']);

        [$known, $unknown, $other] = $this->entries();

        self::assertSame([CapturedActivity::SIGN_IN_FAILED->value, 'failure'], [$unknown->event, $unknown->outcome]);
        self::assertSame([null, null, SigningInUser::class, (string) $user->id], self::actorAndSubject($known));
        self::assertSame([null, null, null, null], self::actorAndSubject($unknown));
        self::assertSame(self::hashOf($known), self::hashOf($unknown));
        self::assertNotSame(self::hashOf($known), self::hashOf($other));
    }

    /**
     * A lockout writes one denied row with no actor, subject or guard, the
     * client the request came from, and its identifier's hash, the one a failed
     * sign-in of the same identifier has.
     *
     * @return void
     */
    public function testALockoutRecordsOneDeniedRow(): void
    {
        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);

        $client  = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Probe/1.0'];
        $request = Request::create('/login', 'POST', ['email' => self::EMAIL, 'password' => 'wrong-password'], [], [], $client);

        Event::dispatch(new Lockout($request));

        [$failure, $lockout] = $this->entries();

        self::assertSame([CapturedActivity::LOCKED_OUT->value, 'denied', null], [$lockout->event, $lockout->outcome, $lockout->reason]);
        self::assertSame([null, null, null, null], self::actorAndSubject($lockout));
        self::assertNull($lockout->guard);
        self::assertSame(['203.0.113.9', 'Probe/1.0'], [$lockout->ip, $lockout->user_agent]);
        self::assertSame(self::hashOf($failure), self::hashOf($lockout));
        self::assertStringNotContainsString('wrong-password', self::rowOf($lockout));
    }

    /**
     * Signing out, out of this device and out of the other devices each write
     * one row naming the user as actor and subject, and the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testEachSignOutRecordsOneRow(): void
    {
        $user  = self::newUser(self::EMAIL);
        $guard = Auth::guard('web');

        self::assertInstanceOf(SessionGuard::class, $guard);

        $guard->login($user);
        $guard->logout();
        $guard->login($user);
        $guard->logoutCurrentDevice();
        $guard->login($user);
        $guard->logoutOtherDevices(SigningInUser::PASSWORD);

        $signOuts = array_values(array_filter($this->entries(), static fn (AuditEntry $entry): bool => $entry->event !== CapturedActivity::SIGNED_IN->value));

        self::assertSame(
            [CapturedActivity::SIGNED_OUT->value, CapturedActivity::SIGNED_OUT->value, CapturedActivity::SIGNED_OUT_OTHER_DEVICES->value],
            array_map(static fn (AuditEntry $entry): string => $entry->event, $signOuts),
        );

        foreach ($signOuts as $entry) {
            self::assertSame(self::userAsActorAndSubject($user), self::actorAndSubject($entry));
            self::assertSame(['web', 'success', null], [$entry->guard, $entry->outcome, $entry->properties]);
        }

        self::assertCount(6, $this->entries());
    }

    /**
     * A registration, a verified email address and a password reset each write
     * one row naming the user as actor and subject, with no guard.
     *
     * @return void
     */
    public function testRegistrationVerificationAndResetRecordOneRowEach(): void
    {
        $user = self::newUser(self::EMAIL);

        Event::dispatch(new Registered($user));
        Event::dispatch(new Verified($user));
        Event::dispatch(new PasswordReset($user));

        $entries = $this->entries();

        self::assertSame(
            [CapturedActivity::REGISTERED->value, CapturedActivity::EMAIL_VERIFIED->value, CapturedActivity::PASSWORD_RESET->value],
            array_map(static fn (AuditEntry $entry): string => $entry->event, $entries),
        );

        foreach ($entries as $entry) {
            self::assertSame(self::userAsActorAndSubject($user), self::actorAndSubject($entry));
            self::assertSame(['success', null, null], [$entry->outcome, $entry->guard, $entry->properties]);
        }
    }

    /**
     * A reset link sent writes one row naming the user as subject and no one as
     * actor, even while another user is signed in.
     *
     * @return void
     */
    public function testAResetLinkRecordsTheUserAsSubjectAndNoActor(): void
    {
        $signedIn = self::newUser(self::OTHER_EMAIL);
        $user     = self::newUser(self::EMAIL);

        Auth::guard('web')->login($signedIn);

        Event::dispatch(new PasswordResetLinkSent($user));

        $entries = $this->entries();

        self::assertCount(2, $entries);
        self::assertSame(CapturedActivity::PASSWORD_RESET_REQUESTED->value, $entries[1]->event);
        self::assertSame([null, null, SigningInUser::class, (string) $user->id], self::actorAndSubject($entries[1]));
        self::assertSame(['success', null], [$entries[1]->outcome, $entries[1]->guard]);
    }

    /**
     * An ambient user never becomes the actor of a failure: a failed sign-in on
     * another guard while a user is signed in still has no actor.
     *
     * @return void
     */
    public function testAnAmbientUserNeverBecomesTheActorOfAFailure(): void
    {
        $signedIn = self::newUser(self::OTHER_EMAIL);
        $user     = self::newUser(self::EMAIL);

        Auth::guard('web')->login($signedIn);
        Auth::guard('admin')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);

        $failure = $this->entries()[1];

        self::assertSame([CapturedActivity::SIGN_IN_FAILED->value, 'admin'], [$failure->event, $failure->guard]);
        self::assertSame([null, null, SigningInUser::class, (string) $user->id], self::actorAndSubject($failure));
    }

    /**
     * `Attempting`, `Validated` and `Authenticated` are never recorded, each
     * dispatched on its own.
     *
     * @return void
     */
    public function testTheNeverRecordedEventsGiveNoRow(): void
    {
        $user = self::newUser(self::EMAIL);

        Event::dispatch(new Attempting('web', ['email' => self::EMAIL, 'password' => SigningInUser::PASSWORD], false));
        Event::dispatch(new Validated('web', $user));
        Event::dispatch(new Authenticated('web', $user));

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * `Auth::once()` and `onceUsingId()` sign the user in for the request
     * without firing `Login`, so they write nothing: a gap of core capture.
     *
     * @return void
     */
    public function testAuthOnceAndOnceUsingIdGiveNoRow(): void
    {
        $user = self::newUser(self::EMAIL);

        self::assertTrue(Auth::guard('web')->once(['email' => self::EMAIL, 'password' => SigningInUser::PASSWORD]));
        $once = Auth::guard('admin')->onceUsingId($user->id);

        self::assertInstanceOf(SigningInUser::class, $once);
        self::assertSame($user->id, $once->id);

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * A token guard finds its user by the request's token and fires neither
     * `Login` nor `Failed`, so it writes nothing, whether or not the token is
     * known: a gap of core capture.
     *
     * @return void
     */
    public function testATokenGuardThatFiresNoEventGivesNoRow(): void
    {
        $user = self::newUser(self::EMAIL, self::REMEMBER_TOKEN);

        self::config()->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users', 'storage_key' => 'remember_token']);

        $guard = Auth::guard('api');

        self::assertInstanceOf(TokenGuard::class, $guard);

        $guard->setRequest(Request::create('/api/me', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer ' . self::REMEMBER_TOKEN]));

        self::assertSame($user->id, $guard->user()?->getAuthIdentifier());

        $guard->forgetUser();
        $guard->setRequest(Request::create('/api/me', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer unknown-token']));

        self::assertNull($guard->user());

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * An event under a guard `except_guards` lists writes nothing, a failure
     * included; the same events under any other guard are recorded.
     *
     * @return void
     */
    public function testAListedGuardIsSkipped(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', ['admin']);

        $user = self::newUser(self::EMAIL);

        Auth::guard('admin')->login($user);
        Auth::guard('admin')->logout();
        Auth::guard('admin')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);
        Auth::guard('web')->login($user);

        self::assertSame(
            [[CapturedActivity::SIGNED_IN->value, 'web']],
            array_map(static fn (AuditEntry $entry): array => [$entry->event, $entry->guard], $this->entries()),
        );
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->failures);
    }

    /**
     * Under `['*']` no core event writes anything, whatever its guard and
     * whether it names one.
     *
     * @return void
     */
    public function testTheWildcardTurnsCoreCaptureOff(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', ['*']);

        $user = self::newUser(self::EMAIL);

        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => SigningInUser::PASSWORD]);
        Auth::guard('web')->logout();
        Auth::guard('web')->attempt(['email' => self::EMAIL, 'password' => 'wrong-password']);

        foreach (self::guardlessEvents($user) as $event) {
            Event::dispatch($event);
        }

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * An event with no guard is skipped only when every guard is: a list of
     * every configured guard leaves the lockout and the account events
     * recorded, and `['*']` skips them.
     *
     * @return void
     */
    public function testGuardlessEventsAreSkippedOnlyUnderTheWildcard(): void
    {
        $user = self::newUser(self::EMAIL);

        self::config()->set('audit-log.capture.laravel.except_guards', ['web', 'admin']);

        foreach (self::guardlessEvents($user) as $event) {
            Event::dispatch($event);
        }

        self::assertSame(
            [
                CapturedActivity::LOCKED_OUT->value,
                CapturedActivity::REGISTERED->value,
                CapturedActivity::EMAIL_VERIFIED->value,
                CapturedActivity::PASSWORD_RESET->value,
                CapturedActivity::PASSWORD_RESET_REQUESTED->value,
            ],
            array_map(static fn (AuditEntry $entry): string => $entry->event, $this->entries()),
        );

        self::config()->set('audit-log.capture.laravel.except_guards', ['*']);

        foreach (self::guardlessEvents($user) as $event) {
            Event::dispatch($event);
        }

        self::assertCount(5, $this->entries());
        self::assertSame([], $this->failures);
    }

    /**
     * An application's mapping of `Login` and the core listener write one row
     * per event object: the core listener's, since it hears the event first,
     * and the mapping is never asked for it; a sign-in the core listener skips
     * for its guard is left for the mapping, which records it with the context
     * the contributors fill, the signed-in guard's included.
     *
     * @return void
     */
    #[DefineEnvironment('mapLogin')]
    public function testAnAppMappingOfLoginAndTheCoreListenerGiveOneRow(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', ['admin']);

        $user = self::newUser(self::EMAIL);
        $seen = [];

        Event::listen(Login::class, static function (Login $event) use (&$seen): void {
            $seen[] = $event;
        });

        Auth::guard('web')->login($user);
        Auth::guard('admin')->login($user);

        self::assertSame(
            [[CapturedActivity::SIGNED_IN->value, 'web'], [PortalMapper::CODE, 'web']],
            array_map(static fn (AuditEntry $entry): array => [$entry->event, $entry->guard], $this->entries()),
        );
        self::assertCount(2, $seen);
        self::assertNull(AuditLog::capture($seen[0]));
        self::assertNull(AuditLog::capture($seen[1]));
        self::assertCount(2, $this->entries());
        self::assertSame([], $this->failures);
    }

    /**
     * Sign users in on the session guards without waiting, with a cheap hash,
     * from the test's users' table, add a second session guard, and set the key
     * identifiers are hashed under.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = self::config();

        $config->set('audit-log.redaction.key', self::REDACTION_KEY);
        $config->set('auth.providers.users.model', SigningInUser::class);
        $config->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.timebox_duration', 0);
        $config->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * Map `Login` to the portal mapper while the application boots, as an
     * application's provider would.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapLogin(Application $app): void
    {
        $app->booting(static function (): void {
            AuditLog::map(Login::class, PortalMapper::class);
        });
    }

    /**
     * The web session guard, about to read the request, holding a remember-me
     * cookie for the user, as a returning browser sends it.
     *
     * @param  \Tests\Fixtures\Capture\Models\SigningInUser  $user
     * @return \Illuminate\Auth\SessionGuard
     */
    private function restore(SigningInUser $user): SessionGuard
    {
        $guard = Auth::guard('web');

        self::assertInstanceOf(SessionGuard::class, $guard);

        $request = Request::create('/');

        $request->cookies->set($guard->getRecallerName(), $user->id . '|' . self::REMEMBER_TOKEN . '|' . $user->password);

        $guard->setRequest($request);

        return $guard;
    }

    /**
     * Assert no row was written and no capture failed.
     *
     * @return void
     */
    private function assertNoEntryAndNoFailure(): void
    {
        self::assertSame([], $this->entries());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * The one row written.
     *
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function onlyEntry(): AuditEntry
    {
        $entries = $this->entries();

        self::assertCount(1, $entries);

        return $entries[0];
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
     * The row's actor and subject, as type and id each.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return array{0: ?string, 1: ?string, 2: ?string, 3: ?string}
     */
    private static function actorAndSubject(AuditEntry $entry): array
    {
        return [$entry->actor_type, $entry->actor_id, $entry->subject_type, $entry->subject_id];
    }

    /**
     * The user as both actor and subject, as a row names them.
     *
     * @param  \Tests\Fixtures\Capture\Models\SigningInUser  $user
     * @return array{0: string, 1: string, 2: string, 3: string}
     */
    private static function userAsActorAndSubject(SigningInUser $user): array
    {
        return [SigningInUser::class, (string) $user->id, SigningInUser::class, (string) $user->id];
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
     * Every column of the row as it is stored, as one string.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return string
     */
    private static function rowOf(AuditEntry $entry): string
    {
        return (string) json_encode($entry->getRawOriginal());
    }

    /**
     * The core events that name no guard, of the user.
     *
     * @param  \Tests\Fixtures\Capture\Models\SigningInUser  $user
     * @return list<object>
     */
    private static function guardlessEvents(SigningInUser $user): array
    {
        return [
            new Lockout(Request::create('/login', 'POST', ['email' => self::EMAIL])),
            new Registered($user),
            new Verified($user),
            new PasswordReset($user),
            new PasswordResetLinkSent($user),
        ];
    }

    /**
     * The configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
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
