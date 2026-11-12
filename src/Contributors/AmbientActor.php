<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CachedUser;
use SineMacula\Laravel\AuditLog\Runtime\ContextSettings;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Who the guards already hold, read without loading anyone: the guards in
 * `audit-log.actor.guards` in order, or the default guard, read from
 * configuration so `Auth::shouldUse()` counts.
 *
 * The first guard holding a user decides; if that user cannot be read there is
 * no ambient actor, since a later guard could name a different person.
 *
 * Laravel's guards outlive a job on a worker, so a user one already held when
 * the job started is treated as no user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AmbientActor
{
    /** @var string The key naming the default guard. */
    private const string DEFAULT_GUARD = 'auth.defaults.guard';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ContextSettings  $settings
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\HeldActorReader  $reader
     */
    public function __construct(

        /** Gives each guard by name. */
        private Factory $auth,

        /** The guards the actor is read from. */
        private ContextSettings $settings,

        /** Configuration the default guard's name is read from on every call. */
        private Repository $config,

        /** What the current code is running in, and the users left on the guards. */
        private ExecutionFrames $frames,

        /** Reads a guard that does not use `GuardHelpers`, when an integration binds one. */
        private ?HeldActorReader $reader = null,
    ) {}

    /**
     * The actor the first guard holding a user gives, with that guard's name;
     * `null` when no guard holds one or that guard's user cannot be read. A
     * guard holding only a user left on it by an earlier job holds nobody.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     *
     * @throws \InvalidArgumentException
     */
    public function current(): ?ActorSnapshot
    {
        foreach ($this->guardNames() as $name) {

            $guard = $this->auth->guard($name);

            if ($guard->hasUser() && !$this->isLeftOn($guard, $name)) {
                return $this->snapshotOf($guard, $name);
            }
        }

        return null;
    }

    /**
     * The users the guards the actor is read from hold now, by guard: what a
     * job on a worker finds there when it starts, none of it the job's own. A
     * guard whose user cannot be read is left out, and it names nobody anyway.
     *
     * @return array<string, object>
     *
     * @throws \InvalidArgumentException
     */
    public function held(): array
    {
        $held = [];

        foreach ($this->guardNames() as $name) {

            $user = CachedUser::of($this->auth->guard($name));

            if ($user === null) {
                continue;
            }

            $held[$name] = $user;
        }

        return $held;
    }

    /**
     * The names of the guards to walk: the configured list, or the default
     * guard alone. A default that is no string is asked for by an empty name,
     * which `AuthManager` refuses as it refuses any guard not configured.
     *
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function guardNames(): array
    {
        $default = $this->config->get(self::DEFAULT_GUARD);

        return $this->settings->guards() ?? [is_string($default) ? $default : ''];
    }

    /**
     * Whether the guard's user was already there when a job on the stack
     * started.
     *
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @param  string  $name
     * @return bool
     */
    private function isLeftOn(Guard $guard, string $name): bool
    {
        $user = CachedUser::of($guard);

        return $user !== null && $this->frames->isLeftover($name, $user);
    }

    /**
     * The actor the bound reader reads from the guard, else the one its
     * `GuardHelpers` user gives, or `null` when neither gives one: a user that
     * cannot be referred to is no actor, not a failed record.
     *
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @param  string  $name
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     */
    private function snapshotOf(Guard $guard, string $name): ?ActorSnapshot
    {
        try {
            $held = $this->reader?->read($name, $guard);

            if ($held === null) {
                $reference = self::referenceTo(CachedUser::of($guard));
                $held      = $reference === null ? null : new HeldActor($reference);
            }

            return $held === null ? null : new ActorSnapshot($held, $name);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * A reference to the user: an Eloquent model through its morph class and
     * key, an `Authenticatable` through its class and identifier, and `null`
     * for anything else.
     *
     * @param  ?object  $user
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceTo(?object $user): ?Reference
    {
        if ($user instanceof Model) {
            return Reference::to($user);
        }

        if (!$user instanceof Authenticatable) {
            return null;
        }

        $identifier = $user->getAuthIdentifier();

        return is_int($identifier) || is_string($identifier) ? Reference::of($user::class, $identifier) : null;
    }
}
