<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\RequestGuard;
use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the capture of Laravel's own authentication events: each of
 * the ten recorded under its package code with the actor and the subject the
 * event names, or explicitly no one, never whoever a guard holds; the guard
 * from the event and the guards configured out skipped; the one credential key
 * the only one read, as a hash; a session restored only from the named session
 * guard's remember-me state; and a malformed setting contained.
 *
 * The provider registers the listener for Laravel's authentication events; here
 * the test invokes it directly with an event of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordLaravelAuthEvent::class)]
final class RecordLaravelAuthEventTest extends TestCase
{
    /** @var string The key identifiers are hashed under. */
    private const string REDACTION_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The identifier a sign-in is attempted with. */
    private const string EMAIL = 'alice@example.com';

    /** @var string The type a user is referred to by. */
    private const string USER_TYPE = StubAuthUser::class;

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Fake the store, bind the reporter, set the key identifiers are hashed
     * under, add a second session guard, and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake     = AuditLog::fake();
        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        self::config()->set('audit-log.redaction.key', self::REDACTION_KEY);
        self::config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Forget any macro a test gave the request guard.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        RequestGuard::flushMacros();

        parent::tearDown();
    }

    /**
     * A sign-in names the user as actor and subject, the guard the event names,
     * and whether it was remembered, under the sign-in code.
     *
     * @return void
     */
    public function testASignInNamesTheUserAndTheRemember(): void
    {
        self::listener()->handle(new Login('web', self::user(7), true));
        self::listener()->handle(new Login('web', self::user(8), false));

        [$remembered, $forgotten] = $this->fake->recorded();

        self::assertSame(CapturedActivity::SIGNED_IN->value, $remembered->event);
        self::assertSame(['success', null], [$remembered->outcome, $remembered->reason]);
        self::assertSame([self::USER_TYPE, '7', self::USER_TYPE, '7'], self::actorAndSubject($remembered));
        self::assertSame('web', $remembered->guard);
        self::assertSame(['remember' => true], $remembered->properties);
        self::assertSame(['security', 1], [$remembered->category, $remembered->eventVersion]);
        self::assertSame(['remember' => false], $forgotten->properties);
        self::assertSame([self::USER_TYPE, '8', self::USER_TYPE, '8'], self::actorAndSubject($forgotten));
    }

    /**
     * A sign-in its session guard made from the remember-me cookie is a session
     * restored, with the same actor, subject and properties.
     *
     * @return void
     */
    public function testARecallerRestoreIsASessionRestore(): void
    {
        self::rememberOn('web');

        self::listener()->handle(new Login('web', self::user(7), true));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::SESSION_RESTORED->value, $record->event);
        self::assertSame([self::USER_TYPE, '7', self::USER_TYPE, '7'], self::actorAndSubject($record));
        self::assertSame(['remember' => true], $record->properties);
    }

    /**
     * Whether a sign-in was restored is read from the guard the event names,
     * not from the default guard nor from another guard that restored one.
     *
     * @return void
     */
    public function testViaRememberIsReadFromTheEventsNamedGuard(): void
    {
        self::rememberOn('admin');

        self::listener()->handle(new Login('web', self::user(7), true));
        self::listener()->handle(new Login('admin', self::user(8), true));

        self::assertSame(
            [CapturedActivity::SIGNED_IN->value, CapturedActivity::SESSION_RESTORED->value],
            array_map(static fn (AuditRecord $record): string => $record->event, $this->fake->recorded()),
        );
        self::assertSame(['web', 'admin'], array_map(static fn (AuditRecord $record): ?string => $record->guard, $this->fake->recorded()));
    }

    /**
     * A guard that is not a session guard is never a restore, even one that
     * says it signed the user in from a remember-me cookie, as a macro makes
     * the request guard say here.
     *
     * @return void
     */
    public function testAGuardThatIsNotASessionGuardIsNeverARestore(): void
    {
        RequestGuard::macro('viaRemember', new class {
            /**
             * Say the user came from a remember-me cookie.
             *
             * @return bool
             */
            public function __invoke(): bool
            {
                return true;
            }
        });
        Auth::viaRequest('remembering', static fn (): null => null);
        self::config()->set('auth.guards.remembering', ['driver' => 'remembering']);

        $guard = Auth::guard('remembering');

        self::assertInstanceOf(RequestGuard::class, $guard);
        self::assertTrue($guard->viaRemember());

        self::listener()->handle(new Login('remembering', self::user(7), true));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::SIGNED_IN->value, $record->event);
        self::assertSame('remembering', $record->guard);
    }

    /**
     * A guard the application does not configure is never asked, so its sign-in
     * is a sign-in, recorded under the name the event gives; a name the manager
     * would read as the default guard's is not read as it either. A configured
     * guard the manager fails to build, of a driver never registered or a
     * session guard with no user provider, is a sign-in too, never a failure.
     *
     * @return void
     */
    public function testAnUnresolvableGuardIsASignIn(): void
    {
        self::rememberOn('web');
        self::config()->set('auth.guards.broken', ['driver' => 'nonexistent']);
        self::config()->set('auth.guards.unprovided', ['driver' => 'session', 'provider' => 'nonexistent']);

        foreach (['missing', '0', 'broken', 'unprovided'] as $guard) {
            self::listener()->handle(new Login($guard, self::user(7), false));
        }

        self::assertSame(
            [
                [CapturedActivity::SIGNED_IN->value, 'missing'],
                [CapturedActivity::SIGNED_IN->value, '0'],
                [CapturedActivity::SIGNED_IN->value, 'broken'],
                [CapturedActivity::SIGNED_IN->value, 'unprovided'],
            ],
            array_map(static fn (AuditRecord $record): array => [$record->event, $record->guard], $this->fake->recorded()),
        );
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A failed sign-in has explicitly no actor, the user the event found as
     * subject, the guard, and the identifier only as its hash.
     *
     * @return void
     */
    public function testAFailureHasNoActorAndTheUserAsSubject(): void
    {
        self::listener()->handle(new Failed('web', self::user(7), ['email' => self::EMAIL, 'password' => 's3cr3t']));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::SIGN_IN_FAILED->value, $record->event);
        self::assertSame(['failure', null], [$record->outcome, $record->reason]);
        self::assertSame([null, null, self::USER_TYPE, '7'], self::actorAndSubject($record));
        self::assertSame('web', $record->guard);
        self::assertSame(['identifier_hash'], array_keys(self::metadataOf($record)));
        self::assertDoesNotHold($record, self::EMAIL);
        self::assertDoesNotHold($record, 's3cr3t');
    }

    /**
     * A failed sign-in of an identifier no user has is the same failure with no
     * subject, and the identifier's hash is the one a known user's gives.
     *
     * @return void
     */
    public function testAFailureOfAnUnknownUserHasNoSubjectAndTheSameHash(): void
    {
        self::listener()->handle(new Failed('web', self::user(7), ['email' => self::EMAIL]));
        self::listener()->handle(new Failed('web', null, ['email' => self::EMAIL]));
        self::listener()->handle(new Failed('web', null, ['email' => 'bob@example.com']));

        [$known, $unknown, $other] = $this->fake->recorded();

        self::assertSame([CapturedActivity::SIGN_IN_FAILED->value, 'failure'], [$unknown->event, $unknown->outcome]);
        self::assertSame([null, null, null, null], self::actorAndSubject($unknown));
        self::assertSame(self::metadataOf($known)['identifier_hash'], self::metadataOf($unknown)['identifier_hash']);
        self::assertNotSame(self::metadataOf($known)['identifier_hash'], self::metadataOf($other)['identifier_hash']);
    }

    /**
     * Only the credential under the identifier key is read: a password, a
     * one-time code and a PIN alongside it reach no record, and the hash is the
     * one the identifier alone gives.
     *
     * @return void
     */
    public function testTheIdentifierIsReadOnlyFromItsKey(): void
    {
        self::listener()->handle(new Failed('web', null, ['email' => self::EMAIL]));
        self::listener()->handle(new Failed('web', null, ['email' => self::EMAIL, 'password' => 's3cr3t-password', 'otp' => 's3cr3t-otp', 'pin' => 's3cr3t-pin']));

        [$alone, $alongside] = $this->fake->recorded();

        self::assertSame($alone->properties, $alongside->properties);

        foreach (['s3cr3t-password', 's3cr3t-otp', 's3cr3t-pin', self::EMAIL] as $credential) {
            self::assertDoesNotHold($alongside, $credential);
        }
    }

    /**
     * A failed sign-in with no identifier, or one that is not a string, is
     * still recorded, with no identifier hash.
     *
     * @return void
     */
    public function testAMissingOrNonStringIdentifierStillRecords(): void
    {
        foreach ([[], ['username' => self::EMAIL], ['email' => ['nested' => self::EMAIL]], ['email' => 42], ['email' => null]] as $credentials) {
            self::listener()->handle(new Failed('web', null, $credentials));
        }

        self::assertSame(5, $this->fake->count());

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([CapturedActivity::SIGN_IN_FAILED->value, 'failure'], [$record->event, $record->outcome]);
            self::assertNull($record->properties);
            self::assertDoesNotHold($record, self::EMAIL);
        }

        self::assertSame([], $this->failures);
    }

    /**
     * The identifier key is configurable: the credential it names is hashed,
     * and the default key's credential is then not read.
     *
     * @return void
     */
    public function testTheIdentifierKeyIsConfigurable(): void
    {
        self::listener()->handle(new Failed('web', null, ['email' => 'alice']));

        self::config()->set('audit-log.capture.laravel.identifier_key', 'username');

        self::listener()->handle(new Failed('web', null, ['username' => 'alice', 'email' => 'bob@example.com']));
        self::listener()->handle(new Failed('web', null, ['email' => 'alice']));

        [$byEmail, $byUsername, $unread] = $this->fake->recorded();

        self::assertSame(self::metadataOf($byEmail)['identifier_hash'], self::metadataOf($byUsername)['identifier_hash']);
        self::assertNull($unread->properties);
    }

    /**
     * A lockout is denied with no reason, has explicitly no actor and no
     * subject and no guard, and keeps the client the request came from and the
     * request's identifier as its hash.
     *
     * @return void
     */
    public function testALockoutIsDeniedWithTheIpAndTheIdentifierHash(): void
    {
        self::listener()->handle(new Failed('web', null, ['email' => self::EMAIL]));

        $request = Request::create('/login', 'POST', ['email' => self::EMAIL, 'password' => 's3cr3t'], [], [], ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Probe/1.0']);

        self::listener()->handle(new Lockout($request));

        [$failure, $lockout] = $this->fake->recorded();

        self::assertSame(CapturedActivity::LOCKED_OUT->value, $lockout->event);
        self::assertSame(['denied', null], [$lockout->outcome, $lockout->reason]);
        self::assertSame([null, null, null, null], self::actorAndSubject($lockout));
        self::assertNull($lockout->guard);
        self::assertSame(['203.0.113.9', 'Probe/1.0'], [$lockout->ip, $lockout->userAgent]);
        self::assertSame(['identifier_hash'], array_keys(self::metadataOf($lockout)));
        self::assertSame(self::metadataOf($failure)['identifier_hash'], self::metadataOf($lockout)['identifier_hash']);
        self::assertDoesNotHold($lockout, 's3cr3t');
    }

    /**
     * A key with a dot is one name, for a lockout as for a failed sign-in: the
     * request's input under that name is hashed as the credential under it is,
     * and input nested under the key's first part is never read.
     *
     * @return void
     */
    public function testADottedKeyIsReadAsOneNameByBoth(): void
    {
        self::config()->set('audit-log.capture.laravel.identifier_key', 'user.email');

        self::listener()->handle(new Failed('web', null, ['user.email' => self::EMAIL]));
        self::listener()->handle(new Lockout(Request::create('/login', 'POST', ['user.email' => self::EMAIL])));
        self::listener()->handle(new Lockout(Request::create('/login', 'POST', ['user' => ['email' => self::EMAIL]])));

        [$failure, $lockout, $nested] = $this->fake->recorded();

        self::assertSame(self::metadataOf($failure)['identifier_hash'], self::metadataOf($lockout)['identifier_hash']);
        self::assertNull($nested->properties);
    }

    /**
     * A lockout whose request has no identifier, or one that is not a string,
     * is still recorded, with no identifier hash.
     *
     * @return void
     */
    public function testALockoutWithNoIdentifierStillRecords(): void
    {
        self::listener()->handle(new Lockout(Request::create('/login', 'POST')));
        self::listener()->handle(new Lockout(Request::create('/login', 'POST', ['email' => ['nested' => self::EMAIL]])));

        self::assertSame(2, $this->fake->count());

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([CapturedActivity::LOCKED_OUT->value, 'denied'], [$record->event, $record->outcome]);
            self::assertNull($record->properties);
        }
    }

    /**
     * A sign-out, on this device or every device, names the user as actor and
     * subject, and the guard.
     *
     * @return void
     */
    public function testASignOutNamesTheUser(): void
    {
        self::listener()->handle(new Logout('web', self::user(7)));
        self::listener()->handle(new CurrentDeviceLogout('admin', self::user(8)));

        [$logout, $current] = $this->fake->recorded();

        self::assertSame([CapturedActivity::SIGNED_OUT->value, CapturedActivity::SIGNED_OUT->value], [$logout->event, $current->event]);
        self::assertSame([self::USER_TYPE, '7', self::USER_TYPE, '7'], self::actorAndSubject($logout));
        self::assertSame([self::USER_TYPE, '8', self::USER_TYPE, '8'], self::actorAndSubject($current));
        self::assertSame(['web', 'admin'], [$logout->guard, $current->guard]);
        self::assertSame(['success', 'success'], [$logout->outcome, $current->outcome]);
        self::assertNull($logout->properties);
    }

    /**
     * A sign-out from a session guard no one is signed in to, on this device or
     * every device, has explicitly no actor and no subject, even while another
     * guard holds a user, and still names its guard.
     *
     * @return void
     */
    public function testASignOutWithNoUserHasNoActor(): void
    {
        $guard = Auth::guard('admin');

        self::assertInstanceOf(SessionGuard::class, $guard);

        Auth::guard('web')->setUser(self::user(99));

        $guard->logout();
        $guard->logoutCurrentDevice();

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([null, null, null, null], self::actorAndSubject($record));
            self::assertSame('admin', $record->guard);
        }

        self::assertSame(2, $this->fake->count());
    }

    /**
     * A sign-out of the other devices has its own code, with the user as actor
     * and subject.
     *
     * @return void
     */
    public function testAnOtherDeviceSignOutHasItsOwnCode(): void
    {
        self::listener()->handle(new OtherDeviceLogout('web', self::user(7)));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::SIGNED_OUT_OTHER_DEVICES->value, $record->event);
        self::assertSame([self::USER_TYPE, '7', self::USER_TYPE, '7'], self::actorAndSubject($record));
        self::assertSame('web', $record->guard);
    }

    /**
     * A registration, a verified email address and a password reset each name
     * the user as actor and subject, under their own codes, with no guard.
     *
     * @return void
     */
    public function testAccountEventsNameTheUserAsActorAndSubject(): void
    {
        self::listener()->handle(new Registered(self::user(1)));
        self::listener()->handle(new Verified(self::user(2)));
        self::listener()->handle(new PasswordReset(self::user(3)));

        $records = $this->fake->recorded();

        self::assertSame(
            [CapturedActivity::REGISTERED->value, CapturedActivity::EMAIL_VERIFIED->value, CapturedActivity::PASSWORD_RESET->value],
            array_map(static fn (AuditRecord $record): string => $record->event, $records),
        );

        foreach ($records as $index => $record) {
            $id = (string) ($index + 1);

            self::assertSame([self::USER_TYPE, $id, self::USER_TYPE, $id], self::actorAndSubject($record));
            self::assertSame(['success', null, null], [$record->outcome, $record->guard, $record->properties]);
        }
    }

    /**
     * A reset link sent names the user as subject and explicitly no one as
     * actor, since whoever asked for it is not known to be that user.
     *
     * @return void
     */
    public function testAResetLinkNamesTheUserAsSubjectAndNoActor(): void
    {
        self::listener()->handle(new PasswordResetLinkSent(self::user(7)));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::PASSWORD_RESET_REQUESTED->value, $record->event);
        self::assertSame([null, null, self::USER_TYPE, '7'], self::actorAndSubject($record));
        self::assertSame(['success', null], [$record->outcome, $record->guard]);
    }

    /**
     * A user signed in on the default guard never fills the actor of an event
     * that names none: a failed sign-in, a lockout and a reset link still have
     * no actor and no guard of the ambient user's, while an explicit record
     * made beside them takes that user.
     *
     * @return void
     */
    public function testAnAmbientUserNeverFillsTheActor(): void
    {
        Auth::guard('web')->setUser(self::user(99));

        self::listener()->handle(new Failed('admin', null, ['email' => self::EMAIL]));
        self::listener()->handle(new Lockout(Request::create('/login', 'POST')));
        self::listener()->handle(new PasswordResetLinkSent(self::user(7)));

        $ambient = AuditLog::event('portal.viewed')->record();

        [$failure, $lockout, $link] = $this->fake->recorded();

        self::assertSame([null, null, 'admin'], [$failure->actorType, $failure->actorId, $failure->guard]);
        self::assertSame([null, null, null], [$lockout->actorType, $lockout->actorId, $lockout->guard]);
        self::assertSame([null, null, null], [$link->actorType, $link->actorId, $link->guard]);
        self::assertSame([self::USER_TYPE, '99', 'web'], [$ambient->actorType, $ambient->actorId, $ambient->guard]);
    }

    /**
     * The guard is the one the event names, never the default guard nor the
     * guard that holds a user.
     *
     * @return void
     */
    public function testTheGuardComesFromTheEvent(): void
    {
        Auth::guard('web')->setUser(self::user(99));

        self::listener()->handle(new Login('admin', self::user(7), false));
        self::listener()->handle(new Logout('admin', self::user(7)));

        self::assertSame(['admin', 'admin'], array_map(static fn (AuditRecord $record): ?string => $record->guard, $this->fake->recorded()));
        self::assertSame([self::USER_TYPE, '7', self::USER_TYPE, '7'], self::actorAndSubject($this->fake->recorded()[0]));
    }

    /**
     * An event under a guard `except_guards` lists is not recorded and says
     * nothing, and its event object is left for another source; one under any
     * other guard, or with no guard, is recorded.
     *
     * @return void
     */
    public function testAListedGuardIsSkipped(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', ['admin']);

        $skipped = new Login('admin', self::user(7), false);

        self::listener()->handle($skipped);
        self::listener()->handle(new Failed('admin', null, ['email' => self::EMAIL]));
        self::listener()->handle(new Logout('admin', self::user(7)));
        self::listener()->handle(new Login('web', self::user(8), false));
        self::listener()->handle(new Registered(self::user(9)));

        self::assertSame(
            [CapturedActivity::SIGNED_IN->value, CapturedActivity::REGISTERED->value],
            array_map(static fn (AuditRecord $record): string => $record->event, $this->fake->recorded()),
        );
        self::assertFalse(app(CapturedEvents::class)->isClaimed($skipped));
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->failures);
    }

    /**
     * An event with no guard is skipped only when every guard is: a list of
     * names leaves the lockout and the account events recorded, and `['*']`
     * skips all ten events.
     *
     * @return void
     */
    public function testGuardlessEventsAreSkippedOnlyUnderTheWildcard(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', ['web', 'admin']);

        foreach (self::guardlessEvents() as $event) {
            self::listener()->handle($event);
        }

        self::assertSame(5, $this->fake->count());

        $this->fake->forget();
        self::config()->set('audit-log.capture.laravel.except_guards', ['*']);

        foreach ([...self::guardlessEvents(), ...self::guardedEvents()] as $event) {
            self::listener()->handle($event);
        }

        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->failures);
    }

    /**
     * A malformed setting is a contained failure of the capture: nothing is
     * recorded, and it is reported once and dispatched once naming the event,
     * the listener and the refusal, whichever setting it is.
     *
     * @return void
     */
    public function testAMalformedSettingIsAContainedFailure(): void
    {
        self::config()->set('audit-log.capture.laravel.except_guards', 'web');

        self::listener()->handle(new Login('web', self::user(7), false));

        self::config()->set('audit-log.capture.laravel.except_guards', []);
        self::config()->set('audit-log.capture.laravel.identifier_key', 'not a key');

        self::listener()->handle(new Failed('web', null, ['email' => self::EMAIL]));
        self::listener()->handle(new Lockout(Request::create('/login', 'POST')));

        self::assertSame(0, $this->fake->count());
        self::assertCount(3, $this->reporter->reports());
        self::assertSame(
            [
                [Login::class, RecordLaravelAuthEvent::class, \InvalidArgumentException::class],
                [Failed::class, RecordLaravelAuthEvent::class, \InvalidArgumentException::class],
                [Lockout::class, RecordLaravelAuthEvent::class, \InvalidArgumentException::class],
            ],
            array_map(static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass], $this->failures),
        );

        foreach ($this->reporter->reports() as $report) {
            self::assertInstanceOf(CaptureFailedException::class, $report);
        }
    }

    /**
     * A guard name a record cannot hold is a contained failure, and the sign-in
     * goes on.
     *
     * @return void
     */
    public function testAGuardNameARecordCannotHoldIsContained(): void
    {
        self::listener()->handle(new Logout(str_repeat('g', 65), self::user(7)));

        self::assertSame(0, $this->fake->count());
        self::assertSame([[Logout::class, RecordLaravelAuthEvent::class, \InvalidArgumentException::class]], array_map(
            static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass],
            $this->failures,
        ));
    }

    /**
     * A guard that is not a string, which only an event a host builds against
     * Laravel's declared types can carry, is no guard: the event is recorded
     * with none, is skipped only when every guard is, and a sign-in under it is
     * never read as the default guard's restore.
     *
     * @return void
     */
    public function testAGuardThatIsNotAStringIsNoGuard(): void
    {
        self::rememberOn('web');
        self::config()->set('audit-log.capture.laravel.except_guards', ['web']);

        self::listener()->handle((new \ReflectionClass(Logout::class))->newInstance(42, self::user(7)));
        self::listener()->handle((new \ReflectionClass(Login::class))->newInstance(null, self::user(7), false));

        [$logout, $login] = $this->fake->recorded();

        self::assertSame([null, null], [$logout->guard, $login->guard]);
        self::assertSame(CapturedActivity::SIGNED_IN->value, $login->event);
    }

    /**
     * A user no reference can be made of, a model with no key or a user whose
     * identifier is neither a string nor an integer, is no one: the event is
     * still recorded, with no actor and no subject.
     *
     * @return void
     */
    public function testAUserThatCannotBeReferencedIsNoOne(): void
    {
        self::listener()->handle(new Login('web', new StubAuthUser, false));
        self::listener()->handle(new Registered(new GenericUser(['id' => 4.2])));

        self::assertSame(2, $this->fake->count());

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([null, null, null, null], self::actorAndSubject($record));
        }
    }

    /**
     * An event object is recorded once, however many times it is handled.
     *
     * @return void
     */
    public function testAnEventObjectIsRecordedOnce(): void
    {
        $event = new Login('web', self::user(7), false);

        self::listener()->handle($event);
        self::listener()->handle($event);
        self::listener()->handle(new Login('web', self::user(7), false));

        self::assertSame(2, $this->fake->count());
        self::assertTrue(app(CapturedEvents::class)->isClaimed($event));
    }

    /**
     * The listener takes exactly the events the provider registers it for, so
     * any other event, Laravel's attempts and validations included, never
     * reaches it, and static analysis checks the registration against what it
     * handles.
     *
     * @return void
     */
    public function testItTakesExactlyTheEventsItIsRegisteredFor(): void
    {
        $type = (new \ReflectionMethod(RecordLaravelAuthEvent::class, 'handle'))->getParameters()[0]->getType();

        self::assertInstanceOf(\ReflectionUnionType::class, $type);

        $handled    = array_map(static fn (\ReflectionType $member): string => $member instanceof \ReflectionNamedType ? $member->getName() : '', $type->getTypes());
        $registered = array_keys(array_filter(
            Event::getRawListeners(),
            static fn (mixed $listeners): bool => is_array($listeners) && in_array(RecordLaravelAuthEvent::class, $listeners, true),
        ));

        sort($handled);
        sort($registered);

        self::assertCount(10, $handled);
        self::assertSame($handled, $registered);
        self::assertNotContains(Attempting::class, $handled);
        self::assertNotContains(Validated::class, $handled);
        self::assertNotContains(Authenticated::class, $handled);
    }

    /**
     * Bind the capture state as the provider does, a registry of the test's
     * own, and define the package codes while the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->instance(MapperRegistry::class, new MapperRegistry);
        app()->scopedIf(CapturedEvents::class);

        app()->booting(static function (Application $app): void {
            $app->make(Recorder::class)->define(CapturedActivity::class);
        });
    }

    /**
     * The one record written.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function onlyRecord(): AuditRecord
    {
        $records = $this->fake->recorded();

        self::assertCount(1, $records);

        return $records[0];
    }

    /**
     * Assert the record holds the text nowhere, in any case.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $text
     * @return void
     */
    private static function assertDoesNotHold(AuditRecord $record, string $text): void
    {
        self::assertStringNotContainsString(strtolower($text), strtolower((string) json_encode($record->toArray())));
    }

    /**
     * The record's actor and subject, as type and id each.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array{0: ?string, 1: ?string, 2: ?string, 3: ?string}
     */
    private static function actorAndSubject(AuditRecord $record): array
    {
        return [$record->actorType, $record->actorId, $record->subjectType, $record->subjectId];
    }

    /**
     * The package's metadata on the record's properties.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array<string, string>
     */
    private static function metadataOf(AuditRecord $record): array
    {
        $metadata = $record->properties['_audit'] ?? null;

        self::assertIsArray($metadata);

        /** @var array<string, string> $metadata */
        return $metadata;
    }

    /**
     * The events recorded that name no guard.
     *
     * @return list<\Illuminate\Auth\Events\Lockout|\Illuminate\Auth\Events\PasswordReset|\Illuminate\Auth\Events\PasswordResetLinkSent|\Illuminate\Auth\Events\Registered|\Illuminate\Auth\Events\Verified>
     */
    private static function guardlessEvents(): array
    {
        return [
            new Lockout(Request::create('/login', 'POST')),
            new Registered(self::user(1)),
            new Verified(self::user(1)),
            new PasswordReset(self::user(1)),
            new PasswordResetLinkSent(self::user(1)),
        ];
    }

    /**
     * The events recorded that name a guard.
     *
     * @return list<\Illuminate\Auth\Events\CurrentDeviceLogout|\Illuminate\Auth\Events\Failed|\Illuminate\Auth\Events\Login|\Illuminate\Auth\Events\Logout|\Illuminate\Auth\Events\OtherDeviceLogout>
     */
    private static function guardedEvents(): array
    {
        return [
            new Login('web', self::user(1), false),
            new Failed('web', null, ['email' => self::EMAIL]),
            new Logout('web', self::user(1)),
            new CurrentDeviceLogout('web', self::user(1)),
            new OtherDeviceLogout('web', self::user(1)),
        ];
    }

    /**
     * Make the session guard of the name say its user came from the remember-me
     * cookie, as a recaller restore leaves it.
     *
     * @param  string  $name
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    private static function rememberOn(string $name): void
    {
        $guard = Auth::guard($name);

        self::assertInstanceOf(SessionGuard::class, $guard);

        (new \ReflectionProperty(SessionGuard::class, 'viaRemember'))->setValue($guard, true);

        self::assertTrue($guard->viaRemember());
    }

    /**
     * The listener, as the dispatcher would make it.
     *
     * @return \SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent
     */
    private static function listener(): RecordLaravelAuthEvent
    {
        return app(RecordLaravelAuthEvent::class);
    }

    /**
     * A user of the id, never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
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
}
