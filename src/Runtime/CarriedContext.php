<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Log\Context\Repository;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What the package keeps in hidden Context, so that it travels with a queued
 * job: the request id, the trace id and the actor's envelope.
 *
 * Only scalars travel: strings for the actor, its guard and any principal,
 * tenant and session reference, never a model. A job reads them back from a
 * payload, so nothing is trusted: a missing, partial or malformed envelope is
 * no actor, never an exception, and nothing is resolved. Every other key in
 * Context belongs to the application and is left alone.
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

    /** @var string The hidden key of the principal's type. */
    public const string PRINCIPAL_TYPE = 'audit-log.principal_type';

    /** @var string The hidden key of the principal's id. */
    public const string PRINCIPAL_ID = 'audit-log.principal_id';

    /** @var string The hidden key of the tenant's type. */
    public const string TENANT_TYPE = 'audit-log.tenant_type';

    /** @var string The hidden key of the tenant's id. */
    public const string TENANT_ID = 'audit-log.tenant_id';

    /** @var string The hidden key of the session reference. */
    public const string SESSION = 'audit-log.session';

    /** @var list<string> Every hidden key of the actor's envelope. */
    private const array ACTOR_KEYS = [
        self::ACTOR_TYPE, self::ACTOR_ID, self::ACTOR_GUARD,
        self::PRINCIPAL_TYPE, self::PRINCIPAL_ID, self::TENANT_TYPE, self::TENANT_ID, self::SESSION,
    ];

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
        try {
            $held = new HeldActor(
                self::referenceIn($context, self::ACTOR_TYPE, self::ACTOR_ID, true),
                self::referenceIn($context, self::PRINCIPAL_TYPE, self::PRINCIPAL_ID),
                self::referenceIn($context, self::TENANT_TYPE, self::TENANT_ID),
                self::stringIn($context, self::SESSION),
            );

            return new ActorSnapshot($held, self::stringIn($context, self::ACTOR_GUARD) ?? '');
        } catch (\InvalidArgumentException) {
            // A malformed envelope is ignored, never trusted and never an error
            return null;
        }
    }

    /**
     * Carry the actor in the context, as strings, replacing any envelope there.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot  $actor
     * @return void
     */
    public static function carryActor(Repository $context, ActorSnapshot $actor): void
    {
        $held = $actor->held;

        self::forgetActor($context);

        $context->addHidden(array_filter([
            self::ACTOR_TYPE     => $held->actor->type,
            self::ACTOR_ID       => $held->actor->id,
            self::ACTOR_GUARD    => $actor->guard,
            self::PRINCIPAL_TYPE => $held->principal?->type,
            self::PRINCIPAL_ID   => $held->principal?->id,
            self::TENANT_TYPE    => $held->tenant?->type,
            self::TENANT_ID      => $held->tenant?->id,
            self::SESSION        => $held->session,
        ], static fn (?string $value): bool => $value !== null));
    }

    /**
     * Stop the context carrying an actor, leaving everything else in it.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    public static function forgetActor(Repository $context): void
    {
        $context->forgetHidden(self::ACTOR_KEYS);
    }

    /**
     * The reference the pair of keys carries, or `null` when neither is there
     * and it is not required.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  string  $typeKey
     * @param  string  $idKey
     * @param  bool  $required
     * @return ($required is true ? \SineMacula\Laravel\AuditLog\Records\Reference : ?\SineMacula\Laravel\AuditLog\Records\Reference)
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceIn(Repository $context, string $typeKey, string $idKey, bool $required = false): ?Reference
    {
        $type = self::stringIn($context, $typeKey);
        $id   = self::stringIn($context, $idKey);

        if (!$required && $type === null && $id === null) {
            return null;
        }

        return Reference::of($type ?? '', $id ?? '');
    }

    /**
     * The string the key carries, or `null` when the key is not there.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function stringIn(Repository $context, string $key): ?string
    {
        if (!$context->hasHidden($key)) {
            return null;
        }

        $value = $context->getHidden($key);

        return is_string($value) ? $value : throw new \InvalidArgumentException(sprintf('The carried %s is not a string.', $key));
    }
}
