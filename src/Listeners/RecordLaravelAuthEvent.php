<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\SessionGuard;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Records Laravel's own authentication events: a sign-in or a session restored
 * from a remember-me cookie, a failed sign-in, a lockout, a sign-out on this or
 * the other devices, a registration, an email address verified, a password
 * reset and a reset link sent.
 *
 * Every value comes from the event, never from what a guard holds now: the
 * actor and the subject are the event's user, and an event with no user to
 * name, a failed sign-in, a lockout or a reset link records that no one acted,
 * so no contributor fills in whoever happens to be signed in. The guard is the
 * one the event names, and an event under a guard
 * `audit-log.capture.laravel.except_guards` lists is not recorded; one with no
 * guard is skipped only when every guard is. The only credential a failed
 * sign-in or a lockout is read for is the one
 * `audit-log.capture.laravel.identifier_key` names, and only when it is a
 * string, and both read it as one name, so a password, a one-time code or any
 * other field is never touched, and a failed sign-in and a lockout of one
 * identifier hash it alike. A sign-in is a session restored only when the guard
 * it names is a session guard that says it signed the user in from the
 * remember-me cookie.
 *
 * A malformed setting or a failure to record is contained by the capture, so
 * the sign-in, the sign-out or the reset goes on.
 *
 * It holds nothing: the capture, its settings, the guards and the configuration
 * come from the application serving the event when it is handled, not from the
 * container that built the listener, which under Octane is the application the
 * worker booted rather than the request's sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordLaravelAuthEvent
{
    /**
     * Record the authentication event.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Auth\Events\CurrentDeviceLogout|\Illuminate\Auth\Events\Failed|\Illuminate\Auth\Events\Lockout|\Illuminate\Auth\Events\Login|\Illuminate\Auth\Events\Logout|\Illuminate\Auth\Events\OtherDeviceLogout|\Illuminate\Auth\Events\PasswordReset|\Illuminate\Auth\Events\PasswordResetLinkSent|\Illuminate\Auth\Events\Registered|\Illuminate\Auth\Events\Verified  $event
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function handle(
        #[\SensitiveParameter] CurrentDeviceLogout|Failed|Lockout|Login|Logout|OtherDeviceLogout|PasswordReset|PasswordResetLinkSent|Registered|Verified $event,
    ): void {
        Container::getInstance()->make(CaptureCoordinator::class)->captured($event, self::class, self::describerOf($event));
    }

    /**
     * The description of the event.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Auth\Events\CurrentDeviceLogout|\Illuminate\Auth\Events\Failed|\Illuminate\Auth\Events\Lockout|\Illuminate\Auth\Events\Login|\Illuminate\Auth\Events\Logout|\Illuminate\Auth\Events\OtherDeviceLogout|\Illuminate\Auth\Events\PasswordReset|\Illuminate\Auth\Events\PasswordResetLinkSent|\Illuminate\Auth\Events\Registered|\Illuminate\Auth\Events\Verified  $event
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function describerOf(
        #[\SensitiveParameter] CurrentDeviceLogout|Failed|Lockout|Login|Logout|OtherDeviceLogout|PasswordReset|PasswordResetLinkSent|Registered|Verified $event,
    ): \Closure {
        return match (true) {
            $event instanceof Login   => self::signIn($event),
            $event instanceof Failed  => self::signInFailure($event),
            $event instanceof Lockout => self::lockout($event),
            default                   => self::signOutOrAccount($event),
        };
    }

    /**
     * The description of a sign-out or an account event.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Auth\Events\CurrentDeviceLogout|\Illuminate\Auth\Events\Logout|\Illuminate\Auth\Events\OtherDeviceLogout|\Illuminate\Auth\Events\PasswordReset|\Illuminate\Auth\Events\PasswordResetLinkSent|\Illuminate\Auth\Events\Registered|\Illuminate\Auth\Events\Verified  $event
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function signOutOrAccount(
        #[\SensitiveParameter] CurrentDeviceLogout|Logout|OtherDeviceLogout|PasswordReset|PasswordResetLinkSent|Registered|Verified $event,
    ): \Closure {
        return match (true) {
            $event instanceof Logout,
            $event instanceof CurrentDeviceLogout => self::userEvent($event->guard, $event->user, CapturedActivity::SIGNED_OUT),
            $event instanceof OtherDeviceLogout   => self::userEvent($event->guard, $event->user, CapturedActivity::SIGNED_OUT_OTHER_DEVICES),
            $event instanceof Registered          => self::userEvent(null, $event->user, CapturedActivity::REGISTERED),
            $event instanceof Verified            => self::userEvent(null, $event->user, CapturedActivity::EMAIL_VERIFIED),
            $event instanceof PasswordReset       => self::userEvent(null, $event->user, CapturedActivity::PASSWORD_RESET),
            default                               => self::resetLink($event->user),
        };
    }

    /**
     * A sign-in: the user as actor and subject, whether it was remembered, and
     * a session restored when the guard it names came from the remember-me
     * cookie.
     *
     * @param  \Illuminate\Auth\Events\Login  $event
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function signIn(#[\SensitiveParameter] Login $event): \Closure
    {
        return self::unlessExcluded($event->guard, static function (#[\SensitiveParameter] PendingRecord $pending) use ($event): PendingRecord {
            $code = self::restoresSession($event->guard) ? CapturedActivity::SESSION_RESTORED : CapturedActivity::SIGNED_IN;

            return self::actedOnThemselves($pending->event($code), UserReference::of($event->user))->withProperties(['remember' => $event->remember === true]);
        });
    }

    /**
     * A failed sign-in: no actor, the user as subject when the event found one,
     * and the identifier under the configured key when it is a string.
     *
     * @param  \Illuminate\Auth\Events\Failed  $event
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function signInFailure(#[\SensitiveParameter] Failed $event): \Closure
    {
        return self::unlessExcluded($event->guard, static function (#[\SensitiveParameter] PendingRecord $pending, CaptureSettings $settings) use ($event): PendingRecord {
            $user       = UserReference::of($event->user);
            $identifier = $event->credentials[$settings->identifierKey()] ?? null;

            if ($user !== null) {
                $pending->on($user);
            }

            if (is_string($identifier)) {
                $pending->withIdentifier($identifier);
            }

            return $pending->event(CapturedActivity::SIGN_IN_FAILED)->by(null)->failed();
        });
    }

    /**
     * A lockout: denied, no actor and no subject, the client the request came
     * from, and the identifier the request gave under the configured key when
     * it is a string. The key is read as one name, as a failed sign-in reads
     * its credentials, never as a path into nested input, so the two hash the
     * same identifier.
     *
     * @param  \Illuminate\Auth\Events\Lockout  $event
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function lockout(#[\SensitiveParameter] Lockout $event): \Closure
    {
        return self::unlessExcluded(null, static function (#[\SensitiveParameter] PendingRecord $pending, CaptureSettings $settings) use ($event): PendingRecord {
            $request    = $event->request;
            $key        = $settings->identifierKey();
            $input      = $request->input();
            $identifier = is_array($input) ? $input[$key] ?? null : null;

            $pending->fillClient($request->ip(), $request->userAgent());

            if (is_string($identifier)) {
                $pending->withIdentifier($identifier);
            }

            return $pending->event(CapturedActivity::LOCKED_OUT)->by(null)->denied();
        });
    }

    /**
     * A sign-out or an account event: the user as actor and subject, or no
     * actor and no subject when the event has no user; an account event names
     * no guard.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $guard
     * @param  mixed  $user
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity  $code
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function userEvent(mixed $guard, #[\SensitiveParameter] mixed $user, CapturedActivity $code): \Closure
    {
        return self::unlessExcluded($guard, static function (#[\SensitiveParameter] PendingRecord $pending) use ($code, $user): PendingRecord {
            $pending->event($code);

            return self::actedOnThemselves($pending, UserReference::of($user));
        });
    }

    /**
     * A reset link sent: the user as subject and no actor, since whoever asked
     * for it is not known to be that user.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $user
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function resetLink(#[\SensitiveParameter] mixed $user): \Closure
    {
        return self::unlessExcluded(null, static function (#[\SensitiveParameter] PendingRecord $pending) use ($user): PendingRecord {
            $reference = UserReference::of($user);

            if ($reference !== null) {
                $pending->on($reference);
            }

            return $pending->event(CapturedActivity::PASSWORD_RESET_REQUESTED)->by(null);
        });
    }

    /**
     * The description, skipped when the guard is one not recorded, and given
     * the guard and the capture settings otherwise; a guard that is not a
     * string is no guard. The settings are read when the event is described,
     * inside the capture, so a malformed one is contained.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $guard
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord, \SineMacula\Laravel\AuditLog\Capture\CaptureSettings): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $describe
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function unlessExcluded(mixed $guard, #[\SensitiveParameter] \Closure $describe): \Closure
    {
        $guard = is_string($guard) ? $guard : null;

        return static function (#[\SensitiveParameter] PendingRecord $pending) use ($guard, $describe): ?PendingRecord {
            $settings = Container::getInstance()->make(CaptureSettings::class);

            if ($settings->excludesGuard($guard)) {
                return null;
            }

            $pending->fillGuard($guard);

            return $describe($pending, $settings);
        };
    }

    /**
     * The builder with the user as actor and subject, or with no actor and no
     * subject when there is no user to name.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $user
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function actedOnThemselves(#[\SensitiveParameter] PendingRecord $pending, ?Reference $user): PendingRecord
    {
        $pending->by($user);

        return $user === null ? $pending : $pending->on($user);
    }

    /**
     * Whether the sign-in came from the remember-me cookie: the guard it names
     * is a session guard that says so. Any other guard did not, a guard
     * `auth.guards` does not configure is never asked, since the manager would
     * refuse it, and a configured guard the manager fails to build, such as one
     * of a driver never registered or with no user provider, is no restore.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $guard
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function restoresSession(mixed $guard): bool
    {
        $container = Container::getInstance();

        if (!is_string($guard) || !is_array($container->make(Repository::class)->get("auth.guards.{$guard}"))) {
            return false;
        }

        try {
            $resolved = $container->make(Factory::class)->guard($guard);
        } catch (\Throwable) {
            // A guard that cannot be built signed no one in from its cookie,
            // and the sign-in is recorded as one
            return false;
        }

        return $resolved instanceof SessionGuard && $resolved->viaRemember();
    }
}
