<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Privacy\KeyStoreUse;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The audit trail as a viewer reads it: immutable filters, then a page, a
 * count, an export or the verification of an export.
 *
 * A bad filter is refused naming the filter, never the value. Every terminal
 * call asks the policy afresh and records the read before returning anything.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditTrail
{
    /** @var string Refusal of holdingDataOf() under a foreign encrypter. */
    private const string FOREIGN_KEYS = 'holdingDataOf() finds an owner\'s entries through the package\'s key store, which the bound field encrypter, %s, does not use.';

    /** @var \SineMacula\Laravel\AuditLog\Querying\TrailFilters What the trail is narrowed to. */
    private TrailFilters $filters;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailReader  $reader
     * @param  \SineMacula\Laravel\AuditLog\Querying\Exporter  $exporter
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportVerifier  $verifier
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     *
     * @internal
     */
    public function __construct(

        /** Reads a page of the trail or counts it. */
        private TrailReader $reader,

        /** Exports the trail. */
        private Exporter $exporter,

        /** Verifies an export. */
        private ExportVerifier $verifier,

        /** Says whether the package's key store is in use; never called. */
        private FieldEncrypter $encrypter,

        // Not promoted: `null` defaults to no filters
        ?TrailFilters $filters = null,

        /** Who the trail is read for, or `null` until `visibleTo()` names them. */
        #[\SensitiveParameter]
        private ?Viewer $viewer = null,
    ) {
        $this->filters = $filters ?? TrailFilters::none();
    }

    /**
     * The trail narrowed to the entries whose actor is the model or the
     * reference, replacing any earlier actor.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forActor(Model|Reference $actor): self
    {
        return $this->narrowed($this->filters->withReference('actor', self::referenceOf($actor)));
    }

    /**
     * The trail narrowed to the entries whose subject is the model or the
     * reference, replacing any earlier subject.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forSubject(Model|Reference $subject): self
    {
        return $this->narrowed($this->filters->withReference('subject', self::referenceOf($subject)));
    }

    /**
     * The trail narrowed to the entries whose principal is the model or the
     * reference, replacing any earlier principal.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forPrincipal(Model|Reference $principal): self
    {
        return $this->narrowed($this->filters->withReference('principal', self::referenceOf($principal)));
    }

    /**
     * The trail narrowed to the entries in the tenant, the model or the
     * reference, replacing any earlier tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forTenant(Model|Reference $tenant): self
    {
        return $this->narrowed($this->filters->withReference('tenant', self::referenceOf($tenant)));
    }

    /**
     * The trail narrowed to these exact codes, replacing any codes or prefix.
     *
     * @param  \BackedEnum|string  ...$codes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forEvent(\BackedEnum|string ...$codes): self
    {
        return $this->narrowed($this->filters->withEvents(array_values($codes)));
    }

    /**
     * The trail narrowed to codes under the prefix, such as `invoice.`,
     * replacing any codes or prefix.
     *
     * @param  string  $prefix
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function forEventsUnder(string $prefix): self
    {
        return $this->narrowed($this->filters->withEventPrefix($prefix));
    }

    /**
     * The trail narrowed to these categories, replacing any earlier ones.
     *
     * @param  string  ...$categories
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function inCategory(string ...$categories): self
    {
        return $this->narrowed($this->filters->withCategories(array_values($categories)));
    }

    /**
     * The trail narrowed to these outcomes, replacing any earlier ones.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  ...$outcomes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withOutcome(Outcome ...$outcomes): self
    {
        return $this->narrowed($this->filters->withOutcomes(array_values($outcomes)));
    }

    /**
     * The trail narrowed to `[from, to)`; `null` is unbounded, and both `null`
     * clears the window.
     *
     * @param  ?\DateTimeInterface  $from
     * @param  ?\DateTimeInterface  $to
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function between(?\DateTimeInterface $from, ?\DateTimeInterface $to): self
    {
        return $this->narrowed($this->filters->withWindow($from, $to));
    }

    /**
     * The trail narrowed to the correlation id, replacing any earlier one.
     *
     * @param  string  $correlationId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function correlatedWith(string $correlationId): self
    {
        return $this->narrowed($this->filters->withCorrelation($correlationId));
    }

    /**
     * The trail narrowed to entries holding a fragment sealed under one of the
     * owner's keys; refused unless the package's key store is in use.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return self
     *
     * @throws \LogicException
     */
    public function holdingDataOf(#[\SensitiveParameter] Model|Reference $owner): self
    {
        if (!KeyStoreUse::covers($this->encrypter)) {
            throw new \LogicException(sprintf(self::FOREIGN_KEYS, KeyStoreUse::describe($this->encrypter)));
        }

        return $this->narrowed($this->filters->withHoldingDataOf(self::referenceOf($owner)));
    }

    /**
     * The trail read for the authenticated viewer; a reference asserts who is
     * reading and proves nothing, and an unreferenceable viewer is refused.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function visibleTo(#[\SensitiveParameter] Authenticatable|Reference $viewer): self
    {
        return new self($this->reader, $this->exporter, $this->verifier, $this->encrypter, $this->filters, Viewer::of($viewer));
    }

    /**
     * A page of the entries the viewer may see, newest first, after the cursor
     * if given; a denied viewer sees an empty page.
     *
     * Its size is 1 to `read.max_per_page`, or 50 (capped at that) when `null`.
     *
     * @param  ?int  $perPage
     * @param  ?string  $cursor
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailPage
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    public function cursorPaginate(?int $perPage = null, ?string $cursor = null): TrailPage
    {
        return $this->reader->page($this->viewer(), $this->filters, $perPage, $cursor);
    }

    /**
     * How many entries the viewer may see; none for a denied viewer.
     *
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function count(): int
    {
        return $this->reader->count($this->viewer(), $this->filters);
    }

    /**
     * Export the entries the viewer may see, oldest first, with a bundle at
     * `<path>.manifest.json`; a denied viewer gets an empty export.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  bool  $force
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function export(string $path, ExportFormat $format = ExportFormat::NDJSON, bool $force = false): ExportResult
    {
        return $this->exporter->export($this->viewer(), $this->filters, $path, $format, $force);
    }

    /**
     * Verify the export at the path and its bundle; the trail's filters play no
     * part, and a denied viewer sees the export entry missing.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportVerification
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function verifyExport(string $path): ExportVerification
    {
        return $this->verifier->verify($this->viewer(), $path);
    }

    /**
     * The viewer, refused before anything is queried when none was named.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Viewer
     *
     * @throws \LogicException
     */
    private function viewer(): Viewer
    {
        return $this->viewer ?? throw new \LogicException('A read of the audit trail names its viewer; call visibleTo() first.');
    }

    /**
     * This trail narrowed to the filters.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return self
     */
    private function narrowed(TrailFilters $filters): self
    {
        return new self($this->reader, $this->exporter, $this->verifier, $this->encrypter, $filters, $this->viewer);
    }

    /**
     * The model's reference as capture refers to it, or the reference as given.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceOf(Model|Reference $reference): Reference
    {
        return $reference instanceof Model ? Reference::to($reference) : $reference;
    }
}
