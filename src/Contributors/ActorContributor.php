<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Fills the actor, its guard, credential and the principal, tenant and session
 * that go with it: the ambient actor or, inside a job frame, the actor the job
 * carried.
 *
 * An actor settled to that same actor gets all but the guard and credential,
 * and one settled to anyone else gets nothing, so another person's context
 * never lands on the record. A guard user the job did not inherit beats the
 * carried actor: it says who started the work.
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

        $actor = $this->actorFor($contribution);

        if ($actor === null) {
            return;
        }

        $held = $actor->held;

        if (!$contribution->isActorSettled()) {
            $contribution->fillActor($held->actor);
            $contribution->fillGuard($actor->guard);
            $contribution->fillCredential($held->credentialId);
        } elseif ($contribution->actor()?->equals($held->actor) !== true) {
            return;
        }

        $contribution->fillPrincipal($held->principal);
        $contribution->fillTenant($held->tenant);
        $contribution->fillSession($held->session);
    }

    /**
     * The ambient or the carried actor; for a record whose actor is already
     * settled, guards that cannot be read give none rather than fail it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     *
     * @throws \InvalidArgumentException
     */
    private function actorFor(Contribution $contribution): ?ActorSnapshot
    {
        try {
            return $this->ambient->current() ?? $this->frames->carriedActor();
        } catch (\InvalidArgumentException $exception) {
            if ($contribution->isActorSettled()) {
                return null;
            }

            throw $exception;
        }
    }
}
