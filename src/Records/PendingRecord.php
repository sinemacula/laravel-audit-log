<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Records\Concerns\ChoosesDelivery;
use SineMacula\Laravel\AuditLog\Records\Concerns\DescribesTheActivity;
use SineMacula\Laravel\AuditLog\Records\Concerns\FillsAmbientContext;
use SineMacula\Laravel\AuditLog\Records\Concerns\SetsTheOutcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * A record being described, built fluently and recorded once with `record()`,
 * which returns the captured record; nothing is written without it.
 *
 * Its public methods describe the activity (`event()`, `on()`, `by()`,
 * `asPrincipal()`, `forTenant()`, `usingCredential()`, `correlatedWith()`,
 * `withProperties()`, `withNote()` and `withIdentifier()`), set its outcome
 * (`succeeded()`, the default, `failed()` and `denied()`), and choose its
 * delivery (`afterCommit()`, `immediately()`, `transactional()` and
 * `failClosed()`).
 * Setting one field twice keeps the last value given, except that properties
 * merge at the top level, later keys replacing earlier ones; different calls
 * never interact, so the record does not depend on the order they are made in.
 * Every value is validated and normalised as it is given, so its properties and
 * context hold only strings, integers, booleans, `null`, lists and maps and
 * every other field a validated value; a programming error is an
 * `\InvalidArgumentException` or a `\LogicException` whatever the configured
 * failure mode. A record names no provenance: the package sets it.
 *
 * A builder is used once: after its record is built, every further call is a
 * `\LogicException`.
 *
 * The recorder is the seam `record()` hands the builder to, and it returns the
 * captured record; the package's recorder passes its own write method. A
 * builder made without one can be described and inspected but not recorded.
 *
 * Callers see this builder and contributors see `Contribution`, a narrow view
 * of it. The `fill*` methods the view delegates to are `@internal`: public only
 * so the view can reach them, and an application never calls them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PendingRecord
{
    use ChoosesDelivery, DescribesTheActivity, FillsAmbientContext, SetsTheOutcome;

    /** @var int Longest note kept, in bytes, cut on a character boundary. */
    public const int NOTE_MAX_BYTES = 1024;

    /** @var bool Whether the builder has been used up by building its record. */
    private bool $consumed = false;

    /**
     * Constructor.
     *
     * @param  ?\Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\AuditRecord  $recorder
     *
     * @internal
     */
    public function __construct(

        /** The recorder `record()` hands the builder to. */
        private readonly ?\Closure $recorder = null,
    ) {}

    /**
     * Record the activity: hand the builder to its recorder, which writes it
     * according to its timing, and return the captured record. A builder is
     * recorded once.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \LogicException
     */
    public function record(): AuditRecord
    {
        $this->assertUsable();

        if ($this->recorder === null) {
            throw new \LogicException('This pending record has no recorder; make one with `AuditLog::event()`.');
        }

        return ($this->recorder)($this);
    }

    /**
     * The builder's state now, with its timing resolved: a fail-closed record
     * with no timing is written immediately, and a record with neither has no
     * timing yet, the recorder applying its default. The builder stays usable.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function snapshot(): PendingSnapshot
    {
        $this->assertUsable();

        return new PendingSnapshot(
            code: $this->code,
            subject: $this->subject,
            actor: $this->actor,
            principal: $this->principal,
            tenant: $this->tenant,
            credentialId: $this->credentialId,
            correlationId: $this->correlationId,
            outcome: $this->outcome,
            reason: $this->reason,
            properties: $this->properties === [] ? null : $this->properties,
            note: $this->note,
            noteOwner: $this->noteOwner,
            guard: $this->guard,
            sessionId: $this->sessionId,
            requestId: $this->requestId,
            traceId: $this->traceId,
            ip: $this->ip,
            userAgent: $this->userAgent,
            origin: $this->origin,
            context: $this->context === [] ? null : $this->context,
            timing: $this->timing ?? ($this->failClosed ? Timing::IMMEDIATE : null),
            connection: $this->connection,
            failClosed: $this->failClosed,
            collisions: $this->collisions,
            collisionCount: $this->collisionCount,
            identifier: $this->identifier,
            contextCollisions: $this->contextCollisions,
            contextCollisionCount: $this->contextCollisionCount,
        );
    }

    /**
     * The builder's final state, which uses the builder up: every later call is
     * refused. Only the captured record calls it, as it is built.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function consume(): PendingSnapshot
    {
        $snapshot = $this->snapshot();

        if ($this->code === null) {
            throw new \LogicException('A pending record needs an event code before it is recorded; set one with `event()`.');
        }

        $this->consumed = true;

        return $snapshot;
    }

    /**
     * Whether the builder has been used up by building its record.
     *
     * @return bool
     *
     * @internal
     */
    public function isConsumed(): bool
    {
        return $this->consumed;
    }

    /**
     * Refuse any use of a builder whose record has been built.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertUsable(): void
    {
        if ($this->consumed) {
            throw new \LogicException('A pending record is recorded once, and this one has already been recorded.');
        }
    }
}
