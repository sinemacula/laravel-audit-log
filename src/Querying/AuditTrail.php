<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The audit trail as a viewer reads it: filters that narrow it, the viewer it
 * is read for, and the terminal calls that read it, a page of entries newest
 * first, a count, an export to a file, or the verification of an export.
 *
 * A trail is immutable: every filter and `visibleTo()` return a new trail and
 * leave this one as it was, so a trail kept and shared leaks no filter. Each
 * filter is validated as it is given and refused with an
 * `InvalidArgumentException` that names the filter, never the value; each
 * dimension replaces itself, and exact codes and a prefix are one dimension. A
 * model given as a reference is referred to exactly as capture refers to it.
 *
 * Every terminal call names its viewer, refused with a `LogicException` before
 * anything is queried when none was given, and is authorised on its own: the
 * access policy is asked for the viewer's scope on every call, a denied scope
 * reads as nothing, and the read is recorded before anything it found is
 * returned. There is no way to ask whether a viewer may read without reading,
 * and a page never says how many entries there are in all.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditTrail
{
    /** @var \SineMacula\Laravel\AuditLog\Querying\TrailFilters What the trail is narrowed to. */
    private TrailFilters $filters;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailReader  $reader
     * @param  \SineMacula\Laravel\AuditLog\Querying\Exporter  $exporter
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportVerifier  $verifier
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     *
     * @internal
     */
    public function __construct(

        /** What reads a page of the trail or counts it. */
        private TrailReader $reader,

        /** What exports the trail for the export call. */
        private Exporter $exporter,

        /** What verifies an export for the verification call. */
        private ExportVerifier $verifier,

        // What the trail is narrowed to, or nothing for an unfiltered trail.
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
     * The trail narrowed to the entries with these exact codes, at least one,
     * the package's own included, replacing any earlier codes and any prefix.
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
     * The trail narrowed to the entries whose code begins with the prefix,
     * lower-case dotted segments ending in a dot such as `invoice.`, replacing
     * any earlier prefix and any exact codes.
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
     * The trail narrowed to the entries in these categories, at least one,
     * replacing any earlier ones.
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
     * The trail narrowed to the entries with these outcomes, at least one,
     * replacing any earlier ones.
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
     * The trail narrowed to the entries that occurred from the first time,
     * inclusive, before the second, exclusive; either may be `null` for no
     * limit, and both `null` clears the window.
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
     * The trail narrowed to the entries carrying the namespaced correlation id,
     * replacing any earlier one.
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
     * The trail read for the viewer, whom the application has authenticated: a
     * model or another authenticatable user, referenced as capture references a
     * user, or a reference, which asserts who is reading and proves nothing. A
     * viewer that cannot be referenced is refused, never read as anonymous.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function visibleTo(#[\SensitiveParameter] Authenticatable|Reference $viewer): self
    {
        return new self($this->reader, $this->exporter, $this->verifier, $this->filters, Viewer::of($viewer));
    }

    /**
     * A page of the entries the viewer may see, newest first, from 1 to
     * `read.max_per_page` of them, 50 when no size is given, or
     * `read.max_per_page` when that is fewer, after the position the cursor of
     * an earlier page holds, or from the newest without one. A denied viewer
     * sees an empty page.
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
     * Export the entries the viewer may see to the path, oldest first, in the
     * format, with its bundle beside it at the path with `.manifest.json`
     * added, replacing what is there only with `force`, and return what was
     * published once the export is journalled. A denied viewer is given an
     * empty export.
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
     * Verify the export at the path, with its bundle beside it, for the viewer,
     * and return what the verification found once it is recorded; the trail's
     * filters play no part. A denied viewer sees the export entry missing.
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
     * The viewer a terminal call reads for, refused before anything is queried
     * when none was named.
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
     * A trail of the same readers and viewer narrowed to the filters.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return self
     */
    private function narrowed(TrailFilters $filters): self
    {
        return new self($this->reader, $this->exporter, $this->verifier, $filters, $this->viewer);
    }

    /**
     * The reference of the model, exactly as capture refers to it, or the
     * reference as given.
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
