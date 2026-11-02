<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Log\Context\Repository;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What the package keeps in hidden Context, so that it travels with a queued
 * job: the request id, the trace id and the actor's envelope.
 *
 * Only scalars travel: three strings for the actor, never a model. A job reads
 * them back from a payload, so nothing is trusted: a missing, partial or
 * malformed envelope is no actor, never an exception, and nothing is resolved.
 * Every other key in Context belongs to the application and is left alone.
 *
 * Hidden Context stays out of the logs, but it travels in the queue payload
 * unencrypted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CarriedContext
{
    /** @var string The hidden key of the request id. */
    public const string REQUEST_ID = 'audit-log.request_id';

    /** @var string The hidden key of the trace id. */
    public const string TRACE_ID = 'audit-log.trace_id';

    /** @var string The hidden key of the actor's type. */
    public const string ACTOR_TYPE = 'audit-log.actor_type';

    /** @var string The hidden key of the actor's id. */
    public const string ACTOR_ID = 'audit-log.actor_id';

    /** @var string The hidden key of the name of the guard that gave the actor. */
    public const string ACTOR_GUARD = 'audit-log.actor_guard';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The actor the context carries, or `null` when its envelope is missing,
     * partial or malformed.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     */
    public static function actor(Repository $context): ?ActorSnapshot
    {
        $type  = $context->getHidden(self::ACTOR_TYPE);
        $id    = $context->getHidden(self::ACTOR_ID);
        $guard = $context->getHidden(self::ACTOR_GUARD);

        if (!is_string($type) || !is_string($id) || !is_string($guard)) {
            return null;
        }

        try {
            return new ActorSnapshot(Reference::of($type, $id), $guard);
        } catch (\InvalidArgumentException) {
            // A malformed envelope is ignored, never trusted and never an error
            return null;
        }
    }

    /**
     * Carry the actor in the context, as three strings.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot  $actor
     * @return void
     */
    public static function carryActor(Repository $context, ActorSnapshot $actor): void
    {
        $context->addHidden([
            self::ACTOR_TYPE  => $actor->reference->type,
            self::ACTOR_ID    => $actor->reference->id,
            self::ACTOR_GUARD => $actor->guard,
        ]);
    }

    /**
     * Stop the context carrying an actor, leaving everything else in it.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    public static function forgetActor(Repository $context): void
    {
        $context->forgetHidden([self::ACTOR_TYPE, self::ACTOR_ID, self::ACTOR_GUARD]);
    }
}
