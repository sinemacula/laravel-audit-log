<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Fills the actor, the guard that gave it and the principal, tenant and session
 * that go with it: the ambient actor or, while a job frame is anywhere on the
 * stack, the actor the job carried from whoever dispatched it.
 *
 * An open actor is filled with all of it. An actor already settled to that same
 * actor gets the principal, tenant and session, never the guard, which a
 * capture names itself; one settled to anyone else, `by(null)` included, gets
 * nothing, so another person's context never lands on the record. A readable
 * guard user the job did not inherit beats the carried actor, which is never
 * resolved: it says who started the work. The carried actor is the one the
 * job's frame kept, since a sync job inside it leaves its own in Context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActorContributor implements ContextContributor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contributors\AmbientActor  $ambient
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     */
    public function __construct(

        /** The actor the guards already hold. */
        private AmbientActor $ambient,

        /** What the current code is running in, and what a job carried. */
        private ExecutionFrames $frames,
    ) {}

    /**
     * Fill the ambient or the carried actor and its context, unless the actor
     * is settled to someone else.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        if ($contribution->isActorSettled() && !$contribution->hasActor()) {
            return;
        }

        $actor = $this->ambient->current() ?? $this->frames->carriedActor();

        if ($actor === null) {
            return;
        }

        $held = $actor->held;

        if (!$contribution->isActorSettled()) {
            $contribution->fillActor($held->actor);
            $contribution->fillGuard($actor->guard);
        } elseif ($contribution->actor()?->equals($held->actor) !== true) {
            return;
        }

        $contribution->fillPrincipal($held->principal);
        $contribution->fillTenant($held->tenant);
        $contribution->fillSession($held->session);
    }
}
