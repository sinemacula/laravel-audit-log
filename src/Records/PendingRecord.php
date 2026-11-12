<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Concerns\ChoosesDelivery;
use SineMacula\Laravel\AuditLog\Records\Concerns\DescribesTheActivity;
use SineMacula\Laravel\AuditLog\Records\Concerns\FillsAmbientContext;
use SineMacula\Laravel\AuditLog\Records\Concerns\SetsTheOutcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * A record described fluently and recorded once with `record()`; its `fill*`
 * methods are public only so `Contribution` can delegate to them.
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

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Manifest What a bulk operation affected; `null` for any other record. */
    private ?Manifest $manifest = null;

    /** @var ?string The id the package gave its own record; `null` for a fresh one. */
    private ?string $id = null;

    /**
     * Constructor.
     *
     * @param  ?\Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\AuditRecord  $recorder
     * @param  ?\Closure(iterable<\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>): \SineMacula\Laravel\AuditLog\Records\Manifest  $manifests
     *
     * @internal
     */
    public function __construct(

        /** The recorder `record()` hands the builder to. */
        private readonly ?\Closure $recorder = null,

        /** What builds `covering()`'s manifest, bounded, for the bound store. */
        private readonly ?\Closure $manifests = null,
    ) {}

    /**
     * Hand the builder to its recorder, which writes it by its timing, and
     * return the captured record.
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
     * Name what happened with one of the package's own codes; only the
     * package's read path calls it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function forPackage(PackageActivity $activity): self
    {
        $this->assertUsable();

        $this->code = EventCode::package($activity);

        return $this;
    }

    /**
     * Use the given lower-case UUID as the record's id, so a lifecycle record
     * derived from what it records is written at most once.
     *
     * @param  string  $id
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @internal
     */
    public function identifiedAs(string $id): self
    {
        $this->assertUsable();

        $this->id = self::checkedId($id);

        return $this;
    }

    /**
     * Carry the manifest of the subjects a bulk operation covers; refused over
     * the configured bounds or when the store keeps no attachment.
     *
     * @param  iterable<\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function covering(#[\SensitiveParameter] iterable $subjects): self
    {
        $this->assertUsable();

        $manifests = $this->manifests ?? throw new \LogicException('This builder has no source of manifests, so it cannot cover subjects.');

        return $this->withManifest($manifests($subjects));
    }

    /**
     * Carry the manifest of what the record covers; a builder has one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @return self
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function withManifest(#[\SensitiveParameter] Manifest $manifest): self
    {
        $this->assertUsable();

        if ($this->manifest !== null) {
            throw new \LogicException('A bulk operation has one manifest.');
        }

        $this->manifest = $manifest;

        return $this;
    }

    /**
     * The builder's state now, a fail-closed record with no timing resolved to
     * immediate; the builder stays usable.
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
            manifest: $this->manifest,
            id: $this->id,
        );
    }

    /**
     * The builder's final state, using the builder up.
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

    /**
     * The id given, refused unless it is a lower-case UUID.
     *
     * @param  string  $id
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedId(string $id): string
    {
        if (preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/', $id) !== 1) {
            throw new \InvalidArgumentException('A pending record\'s id is a lower-case UUID.');
        }

        return $id;
    }
}
