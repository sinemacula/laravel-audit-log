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
 * A record being described, built fluently and recorded once with `record()`,
 * which returns the captured record; nothing is written without it.
 *
 * Its public methods describe the activity (`event()`, `on()`, `by()`,
 * `asPrincipal()`, `forTenant()`, `viaGuard()`, `inSession()`, `fromClient()`,
 * `usingCredential()`, `correlatedWith()`, `withProperties()`, `withNote()` and
 * `withIdentifier()`), set its outcome (`succeeded()`, the default, `failed()`
 * and `denied()`), and choose its delivery (`afterCommit()`, `immediately()`,
 * `transactional()` and `failClosed()`). Setting one field twice keeps the last
 * value given, except that properties merge at the top level, later keys
 * replacing earlier ones; different calls never interact, so the record does
 * not depend on the order they are made in. Every value is validated and
 * normalised as it is given, so its properties and context hold only strings,
 * integers, booleans, `null`, lists and maps and every other field a validated
 * value; a programming error is an `\InvalidArgumentException` or a
 * `\LogicException` whatever the configured failure mode. A record names no
 * provenance: the package sets it.
 *
 * A builder is used once: after its record is built, every further call is a
 * `\LogicException`.
 *
 * A bulk builder carries its manifest, what the operation affected, which its
 * record seals as an attachment and describes in `properties._audit.manifest`.
 * `covering()` gives a builder one, from the application or a mapper; the
 * package's own read records carry theirs too.
 *
 * Only the package's own read path names one of its codes, with `forPackage()`.
 * A builder the facade made is refused when it is recorded with a code under
 * the reserved prefix, because only the package's write path may record one, so
 * `forPackage()` is no public way to record a package code.
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
     * Name what happened with one of the package's own codes, under the
     * reserved prefix. Only the package's read path calls it; the last code
     * given wins, as with `event()`.
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
     * Give the record the id given, a lower-case UUID, in place of a fresh one:
     * one of the package's own records whose id is derived from what it
     * records, so that record is written at most once. Only the package's
     * lifecycle records call it.
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
     * Make the record a bulk operation's: carry the manifest of the subjects it
     * covers, each a model or a reference, kept once whatever the order or
     * repetition they come in. A manifest over the configured bounds is
     * refused, never truncated, and so is any manifest while the bound store
     * keeps no attachment. The application covers a builder from
     * `AuditLog::event()`, and a mapper the builder it was handed; a builder
     * made without a source of manifests cannot cover anything.
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
     * Carry the manifest of what the record covers: a bulk operation's members,
     * or the package's own read records' disclosure or export. A builder has
     * one manifest, given before its record is built.
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
            manifest: $this->manifest,
            id: $this->id,
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
