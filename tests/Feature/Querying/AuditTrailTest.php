<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;
use SineMacula\Laravel\AuditLog\Querying\ExportVerification;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the audit trail as an application reads it: every filter
 * and the viewer return a new trail and leave the old one as it was, each
 * dimension replaces itself, a model is referred to as capture refers to it,
 * the package's own codes can be filtered on but never recorded, the viewer is
 * referenced as capture references a user and never read as anonymous, and a
 * terminal call without a viewer or with a page size outside the range is
 * refused before anything is queried or recorded; an export and its
 * verification read through the exporter and the verifier, for the trail's
 * viewer; there is no probe of whether a viewer may read. The entries holding
 * an owner's encrypted fragments are found through the package's key store, in
 * a page, a count and an export alike, bound into a page's cursor, and refused
 * naming the bound encrypter when the encrypter keeps its keys elsewhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditTrail::class)]
final class AuditTrailTest extends TestCase
{
    use InteractsWithAuditStore, MakesSubjectKeys, ReadsTheTrail;

    /** @var string What a terminal call without a viewer is refused with. */
    private const string NO_VIEWER = 'A read of the audit trail names its viewer; call visibleTo() first.';

    /** @var string What an unreferenceable viewer is refused with. */
    private const string UNREFERENCEABLE = 'A viewer must be a model with a key, an authenticatable user with a string or integer identifier,'
        . ' or a reference; it is never read as anonymous.';

    /**
     * Bind the read path.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
    }

    /**
     * Rows of `[filter]`: each filter, applied to a trail.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail}>
     */
    public static function provideFilters(): iterable
    {
        yield from [
            'actor'       => [static fn (AuditTrail $trail): AuditTrail => $trail->forActor(Reference::of('user', '42'))],
            'subject'     => [static fn (AuditTrail $trail): AuditTrail => $trail->forSubject(Reference::of('invoice', 'inv_0042'))],
            'principal'   => [static fn (AuditTrail $trail): AuditTrail => $trail->forPrincipal(Reference::of('team', 't_1'))],
            'tenant'      => [static fn (AuditTrail $trail): AuditTrail => $trail->forTenant(Reference::of('organisation', 'org_01'))],
            'codes'       => [static fn (AuditTrail $trail): AuditTrail => $trail->forEvent('invoice.approved')],
            'prefix'      => [static fn (AuditTrail $trail): AuditTrail => $trail->forEventsUnder('invoice.')],
            'category'    => [static fn (AuditTrail $trail): AuditTrail => $trail->inCategory('finance')],
            'outcome'     => [static fn (AuditTrail $trail): AuditTrail => $trail->withOutcome(Outcome::DENIED)],
            'window'      => [static fn (AuditTrail $trail): AuditTrail => $trail->between(new CarbonImmutable('2026-11-01T00:00:00Z'), null)],
            'correlation' => [static fn (AuditTrail $trail): AuditTrail => $trail->correlatedWith('app:ticket-123')],
            'holding'     => [static fn (AuditTrail $trail): AuditTrail => $trail->holdingDataOf(Reference::of('App\Models\User', '42'))],
            'viewer'      => [static fn (AuditTrail $trail): AuditTrail => $trail->visibleTo(Reference::of('App\Models\User', '7'))],
        ];
    }

    /**
     * Each filter, and the viewer, returns a new trail and leaves the trail it
     * was called on unfiltered and without a viewer.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $filter
     * @return void
     */
    #[DataProvider('provideFilters')]
    public function testEveryFilterReturnsANewTrail(\Closure $filter): void
    {
        $trail    = app(AuditTrail::class);
        $filtered = $filter($trail);

        self::assertNotSame($trail, $filtered);
        self::assertSame(TrailFilters::none()->normalised(), self::filtersOf($trail));
        self::assertNull(self::viewerOf($trail));
        self::assertTrue(self::filtersOf($filtered) !== TrailFilters::none()->normalised() || self::viewerOf($filtered) !== null);
    }

    /**
     * A trail kept and narrowed two ways leaks neither narrowing into the
     * other, nor into itself, and keeps its viewer in both.
     *
     * @return void
     */
    public function testASharedTrailLeaksNoFilter(): void
    {
        $shared  = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
        $byActor = $shared->forActor(Reference::of('user', '42'));
        $denied  = $shared->withOutcome(Outcome::DENIED);

        self::assertSame(['finance'], self::filtersOf($shared)['categories']);
        self::assertNull(self::filtersOf($shared)['actor']);
        self::assertSame([], self::filtersOf($shared)['outcomes']);
        self::assertSame([['user', '42'], []], [self::filtersOf($byActor)['actor'], self::filtersOf($byActor)['outcomes']]);
        self::assertSame([null, ['denied']], [self::filtersOf($denied)['actor'], self::filtersOf($denied)['outcomes']]);
        self::assertSame(['finance'], self::filtersOf($denied)['categories']);
        self::assertSame(self::viewerOf($shared), self::viewerOf($byActor));
    }

    /**
     * Each dimension given again replaces itself, never merging with what was
     * given before, and a later window clears with `null` on both ends.
     *
     * @return void
     */
    public function testEachDimensionReplacesItself(): void
    {
        $filters = self::filtersOf(app(AuditTrail::class)
            ->forActor(Reference::of('user', '1'))->forActor(Reference::of('user', '2'))
            ->forSubject(Reference::of('invoice', 'a'))->forSubject(Reference::of('invoice', 'b'))
            ->forPrincipal(Reference::of('team', 'a'))->forPrincipal(Reference::of('team', 'b'))
            ->forTenant(Reference::of('organisation', 'a'))->forTenant(Reference::of('organisation', 'b'))
            ->forEvent('invoice.approved', 'invoice.paid')->forEvent('invoice.voided')
            ->inCategory('finance', 'hr')->inCategory('security')
            ->withOutcome(Outcome::DENIED, Outcome::FAILURE)->withOutcome(Outcome::SUCCESS)
            ->between(new CarbonImmutable('2026-11-01T00:00:00Z'), new CarbonImmutable('2026-11-02T00:00:00Z'))->between(null, null)
            ->correlatedWith('app:ticket-1')->correlatedWith('app:ticket-2')
            ->holdingDataOf(Reference::of('App\Models\User', '1'))->holdingDataOf(Reference::of('App\Models\User', '2')));

        self::assertSame([
            'actor'           => ['user', '2'],
            'categories'      => ['security'],
            'correlation_id'  => 'app:ticket-2',
            'event_prefix'    => null,
            'events'          => ['invoice.voided'],
            'from'            => null,
            'holding_data_of' => ['App\Models\User', '2'],
            'outcomes'        => ['success'],
            'principal'       => ['team', 'b'],
            'subject'         => ['invoice', 'b'],
            'tenant'          => ['organisation', 'b'],
            'to'              => null,
        ], $filters);
    }

    /**
     * Exact codes and a prefix are one dimension: a prefix replaces the codes,
     * and codes replace a prefix.
     *
     * @return void
     */
    public function testAnEventPrefixReplacesExactCodes(): void
    {
        $prefixed = self::filtersOf(app(AuditTrail::class)->forEvent('invoice.approved')->forEventsUnder('invoice.'));
        $exact    = self::filtersOf(app(AuditTrail::class)->forEventsUnder('invoice.')->forEvent('invoice.approved'));

        self::assertSame([[], 'invoice.'], [$prefixed['events'], $prefixed['event_prefix']]);
        self::assertSame([['invoice.approved'], null], [$exact['events'], $exact['event_prefix']]);
    }

    /**
     * A model given to a reference filter becomes its reference exactly as
     * capture builds it, by its morph class and its key as a string.
     *
     * @return void
     */
    public function testAModelBecomesItsReferenceAsCaptureBuildsIt(): void
    {
        $model = (new StubAuthUser)->forceFill(['id' => 42]);
        $built = Reference::to($model);

        $filters = self::filtersOf(app(AuditTrail::class)->forActor($model)->forSubject($model)->forPrincipal($model)->forTenant($model));

        foreach (['actor', 'subject', 'principal', 'tenant'] as $dimension) {
            self::assertSame([$built->type, $built->id], $filters[$dimension], $dimension);
        }

        self::assertSame([$built->type, $built->id], self::filtersOf(app(AuditTrail::class)->holdingDataOf($model))['holding_data_of']);

        self::assertSame([StubAuthUser::class, '42'], [$built->type, $built->id]);
    }

    /**
     * A filter is validated as it is given, before any viewer or terminal call,
     * naming the filter and never the value.
     *
     * @return void
     */
    public function testAFilterIsRefusedAsItIsGiven(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A category filter\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');

        app(AuditTrail::class)->inCategory('Not A Category');
    }

    /**
     * The codes of the package's own reads can be filtered on, by their enum or
     * by name, and a read filtered on them finds the records of earlier reads.
     *
     * @return void
     */
    public function testAReservedCodeCanBeFilteredOn(): void
    {
        $this->allowEverything();

        $byEnum = app(AuditTrail::class)->forEvent(PackageActivity::TRAIL_READ);
        $byName = app(AuditTrail::class)->forEvent('audit_log.trail_counted')->forEventsUnder('audit_log.');

        self::assertSame(['audit_log.trail_read'], self::filtersOf($byEnum)['events']);
        self::assertSame('audit_log.', self::filtersOf($byName)['event_prefix']);

        $byEnum->visibleTo($this->viewer())->count();

        self::assertSame(1, $byEnum->visibleTo($this->viewer())->forEvent(PackageActivity::TRAIL_COUNTED)->count());
    }

    /**
     * A package code is never recorded through the facade: by name it is
     * refused as reserved, and naming it with `forPackage()` on a builder the
     * facade made is refused when it is recorded, with nothing stored.
     *
     * @return void
     */
    public function testRecordingAReservedCodeIsStillRefused(): void
    {
        $this->assertThrows(
            static fn () => AuditLog::record('audit_log.trail_read'),
            \InvalidArgumentException::class,
            'The `audit_log.` prefix is reserved for the package\'s own event codes.',
        );

        $this->assertThrows(
            static fn () => AuditLog::event('invoice.approved')->forPackage(PackageActivity::TRAIL_READ)->immediately()->record(),
            \LogicException::class,
            'A code under the reserved prefix is written only by the package\'s own activity.',
        );

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[terminal call]`: a page and a count.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)}>
     */
    public static function provideTerminals(): iterable
    {
        yield from [
            'a page'  => [static fn (AuditTrail $trail): TrailPage => $trail->cursorPaginate()],
            'a count' => [static fn (AuditTrail $trail): int => $trail->count()],
        ];
    }

    /**
     * A terminal call without a viewer is refused before the policy is asked or
     * anything is queried, and is not recorded.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $terminal
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testATerminalWithoutAViewerIsRefusedBeforeAnyQuery(\Closure $terminal): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        try {
            $terminal(app(AuditTrail::class)->inCategory('finance'));

            self::fail('Expected the read to be refused.');
        } catch (\LogicException $refusal) {
            self::assertSame(self::NO_VIEWER, $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->readRecords());
    }

    /**
     * A model viewer is handed to the policy as it was given, and the read is
     * recorded under its reference as capture builds it.
     *
     * @return void
     */
    public function testAModelViewerIsReferencedAsCaptureReferencesIt(): void
    {
        $viewer = (new StubAuthUser)->forceFill(['id' => 7]);

        $this->assertReadAs($viewer, [StubAuthUser::class, '7']);
    }

    /**
     * Another authenticatable viewer is handed to the policy as it was given,
     * and the read is recorded under its class and its identifier.
     *
     * @return void
     */
    public function testAnAuthenticatableViewerIsReferencedByItsIdentifier(): void
    {
        $viewer = new GenericUser(['id' => 'user-7']);

        $this->assertReadAs($viewer, [GenericUser::class, 'user-7']);
    }

    /**
     * A reference viewer is handed to the policy and recorded exactly as it was
     * given.
     *
     * @return void
     */
    public function testAReferenceViewerIsKeptAsGiven(): void
    {
        $viewer = Reference::of('App\Models\Auditor', 'auditor-3');

        $this->assertReadAs($viewer, ['App\Models\Auditor', 'auditor-3']);
    }

    /**
     * Rows of `[viewer]`: a model without a key, and an authenticatable user
     * whose identifier is neither a string nor an integer.
     *
     * @return iterable<string, array{0: \Illuminate\Contracts\Auth\Authenticatable}>
     */
    public static function provideUnreferenceableViewers(): iterable
    {
        yield from [
            'a model without a key'   => [new StubAuthUser],
            'a fractional identifier' => [new GenericUser(['id' => 1.5])],
            'a null identifier'       => [new GenericUser(['id' => null])],
        ];
    }

    /**
     * A viewer that cannot be referenced is refused as it is given, never read
     * as anonymous, and nothing is queried or recorded.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $viewer
     * @return void
     */
    #[DataProvider('provideUnreferenceableViewers')]
    public function testAnUnreferenceableViewerIsRefusedNotAnonymous(Authenticatable $viewer): void
    {
        $this->captureQueries();

        try {
            app(AuditTrail::class)->visibleTo($viewer);

            self::fail('Expected the viewer to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame(self::UNREFERENCEABLE, $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
    }

    /**
     * There is no way to ask whether a viewer may read without reading: no
     * probe, and no terminal call but a page, a count, an export and the
     * verification of one.
     *
     * @return void
     */
    public function testThereIsNoPermittedProbe(): void
    {
        foreach (['permitted', 'isPermitted', 'can', 'allows', 'exists', 'get', 'all', 'first', 'paginate', 'simplePaginate', 'total'] as $method) {
            self::assertFalse(method_exists(AuditTrail::class, $method), "The trail has a {$method}() method.");
        }
    }

    /**
     * An export and the verification of one without a viewer are refused before
     * the policy is asked, anything is queried or any file is written, and are
     * not recorded.
     *
     * @return void
     */
    public function testExportAndVerifyNeedAViewer(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $target = uniqid(sys_get_temp_dir() . '/audit-log-trail-', true) . '.ndjson';

        $this->captureQueries();

        $terminals = [
            static fn (AuditTrail $trail): ExportResult => $trail->export($target),
            static fn (AuditTrail $trail): ExportVerification => $trail->verifyExport($target),
        ];

        foreach ($terminals as $terminal) {
            try {
                $terminal(app(AuditTrail::class)->inCategory('finance'));

                self::fail('Expected the read to be refused.');
            } catch (\LogicException $refusal) {
                self::assertSame(self::NO_VIEWER, $refusal->getMessage());
            }
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->readRecords());
        self::assertFileDoesNotExist($target);
        self::assertSame([], glob(dirname($target) . '/.' . basename($target) . '.*') ?: []);
    }

    /**
     * An export reads through the exporter with the trail's filters and viewer,
     * in the format given, and the verification of it through the verifier for
     * the same viewer.
     *
     * @return void
     */
    public function testExportAndVerifyDelegate(): void
    {
        $this->allowEverything();

        $denied = $this->seedEntry(['outcome' => Outcome::DENIED->value, 'reason' => 'locked']);

        $this->seedEntries(2);

        $directory = uniqid(sys_get_temp_dir() . '/audit-log-trail-', true);

        mkdir($directory, 0700);

        $target = $directory . '/trail.ndjson';
        $trail  = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->withOutcome(Outcome::DENIED);

        try {
            $result       = $trail->export($target, ExportFormat::CEF);
            $verification = $trail->verifyExport($target);
            $contents     = (string) file_get_contents($target);
        } finally {
            array_map(unlink(...), glob($directory . '/*') ?: []);
            rmdir($directory);
        }

        self::assertSame([ExportFormat::CEF, 1], [$result->format, $result->lines]);
        self::assertStringContainsString('externalId=' . $denied, $contents);
        self::assertTrue($verification->isVerified());
        self::assertSame($result->entryId, $verification->entryId);
        self::assertSame(['audit_log.trail_exported', 'audit_log.export_verified'], array_column($this->readRecords(), 'event'));
        $filters = TrailFilters::none()->withCategories(['finance'])->withOutcomes([Outcome::DENIED]);

        self::assertSame(self::termsOf($filters, null)->queryFingerprint, self::propertiesOf($this->readRecords()[0])['query_fingerprint']);
    }

    /**
     * Rows of `[page size, the greatest configured or null for the default,
     * the greatest the message names]`.
     *
     * @return iterable<string, array{0: int, 1: ?int, 2: int}>
     */
    public static function providePageSizesOutsideTheRange(): iterable
    {
        yield from [
            'none'                        => [0, null, 100],
            'negative'                    => [-1, null, 100],
            'one over the default'        => [101, null, 100],
            'one over the hard cap'       => [501, 500, 500],
            'one over a configured limit' => [11, 10, 10],
        ];
    }

    /**
     * A page size outside 1 to `read.max_per_page` is refused, naming the
     * range, before the policy is asked or anything is queried, and is not
     * recorded.
     *
     * @param  int  $perPage
     * @param  ?int  $configured
     * @param  int  $most
     * @return void
     */
    #[DataProvider('providePageSizesOutsideTheRange')]
    public function testAPageSizeOutsideTheRangeIsRefusedBeforeAnyQuery(int $perPage, ?int $configured, int $most): void
    {
        if ($configured !== null) {
            app(ConfigRepository::class)->set('audit-log.read.max_per_page', $configured);
        }

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        try {
            app(AuditTrail::class)->visibleTo($this->viewer())->cursorPaginate($perPage);

            self::fail('Expected the page size to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame(sprintf('A page of the audit trail holds from 1 to %d entries.', $most), $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->readRecords());
    }

    /**
     * A page size at either end of the range is read.
     *
     * @return void
     */
    public function testAPageSizeAtEitherEndOfTheRangeIsRead(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $trail = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');

        self::assertCount(1, $trail->cursorPaginate(1)->entries);
        self::assertCount(2, $trail->cursorPaginate(100)->entries);
        self::assertCount(2, $trail->cursorPaginate()->entries);
        self::assertSame(50, $trail->cursorPaginate()->perPage);
    }

    /**
     * The terminal calls read through the reader with the trail's filters and
     * viewer: a page and a count of what the filters select.
     *
     * @return void
     */
    public function testTheTerminalsReadTheFilteredTrail(): void
    {
        $this->allowEverything();

        $denied = $this->seedEntry(['outcome' => Outcome::DENIED->value, 'reason' => 'locked'], '2026-11-01T12:00:00.000002Z');

        $this->seedEntries(2);

        $trail = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->withOutcome(Outcome::DENIED);
        $page  = $trail->cursorPaginate();

        self::assertSame([$denied], array_map(static fn ($entry): string => $entry->id, $page->entries));
        self::assertSame(1, $trail->count());
        self::assertSame(3, $trail->withOutcome(Outcome::SUCCESS, Outcome::DENIED)->count());
    }

    /**
     * A trail holding the data of an owner reads the entries holding one of its
     * encrypted fragments, whichever field holds it and whatever else the entry
     * holds, given by a model or by its reference, and no entry holding only
     * another owner's fragments or none.
     *
     * @return void
     */
    public function testHoldingDataOfFindsEntriesHoldingTheOwnersFragments(): void
    {
        $this->allowEverything();

        $model = (new StubAuthUser)->forceFill(['id' => 42]);
        $owner = Reference::to($model);
        $other = Reference::of('App\Models\User', '43');

        $own  = $this->seedHolding([$owner]);
        $both = $this->seedHolding([$other, $owner]);

        $this->seedHolding([$other]);
        $this->seedEntry();

        $trail = app(AuditTrail::class)->visibleTo($this->viewer());

        self::assertSame(self::sorted([$own, $both]), self::sorted(self::idsOf($trail->holdingDataOf($model)->cursorPaginate())));
        self::assertSame(self::sorted([$own, $both]), self::sorted(self::idsOf($trail->holdingDataOf($owner)->cursorPaginate())));
        self::assertSame(self::sorted([$own, $both]), self::sorted(self::idsOf($trail->holdingDataOf($other)->holdingDataOf($owner)->cursorPaginate())));
        self::assertSame([], self::idsOf($trail->holdingDataOf(Reference::of('App\Models\User', '44'))->cursorPaginate()));
    }

    /**
     * With a field encrypter bound that keeps its keys outside the package's
     * key store, an anonymous one included, the filter is refused naming the
     * bound class, before anything is queried; the package's encrypter and the
     * one that never encrypts are accepted.
     *
     * @return void
     */
    public function testACustomEncrypterThrowsNamingTheBinding(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        $this->keyWrapper();
        $this->captureQueries();

        $anonymous = new class implements FieldEncrypter {
            /**
             * No envelope.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
             * @param  string  $plaintext
             * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
             * @return null
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): null
            {
                return null;
            }
        };

        $refusals = [RecordingFieldEncrypter::class => new RecordingFieldEncrypter, FieldEncrypter::class . '@anonymous' => $anonymous];

        foreach ($refusals as $named => $encrypter) {
            app()->instance(FieldEncrypter::class, $encrypter);

            try {
                app(AuditTrail::class)->visibleTo($this->viewer())->holdingDataOf($owner);

                self::fail("Expected {$named} to be refused.");
            } catch (\LogicException $refusal) {
                $message = 'holdingDataOf() finds an owner\'s entries through the package\'s key store, which the bound field encrypter, %s, does not use.';

                self::assertSame(sprintf($message, $named), $refusal->getMessage());
            }
        }

        self::assertSame([], $this->capturedQueries());

        foreach ([NoFieldEncrypter::class, SubjectKeyEncrypter::class] as $covered) {
            app()->bind(FieldEncrypter::class, $covered);

            self::assertSame([$owner->type, $owner->id], self::filtersOf(app(AuditTrail::class)->holdingDataOf($owner))['holding_data_of'], $covered);
        }
    }

    /**
     * The encrypter is the one bound when the trail was made, carried by every
     * filter and by the viewer, never looked up again: a trail made under a
     * custom encrypter is refused after the binding changes, and one made under
     * the package's store is not.
     *
     * @return void
     */
    public function testTheTrailKeepsTheEncrypterItWasMadeWith(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $custom = app(AuditTrail::class)->inCategory('finance')->visibleTo($this->viewer())->forActor(Reference::of('user', '42'));

        app()->instance(FieldEncrypter::class, new NoFieldEncrypter);

        $package = app(AuditTrail::class)->inCategory('finance')->visibleTo($this->viewer());

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        self::assertSame([$owner->type, $owner->id], self::filtersOf($package->forActor(Reference::of('user', '42'))->holdingDataOf($owner))['holding_data_of']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(RecordingFieldEncrypter::class);

        $custom->holdingDataOf($owner);
    }

    /**
     * A count and an export of the trail holding an owner's data apply it as a
     * page does: each counts or writes only the entries holding the owner's
     * fragments.
     *
     * @return void
     */
    public function testTheCountAndTheExportApplyIt(): void
    {
        $this->allowEverything();

        $owner = Reference::of('App\Models\User', '42');
        $held  = [$this->seedHolding([$owner]), $this->seedHolding([$owner, Reference::of('App\Models\User', '43')])];
        $other = $this->seedHolding([Reference::of('App\Models\User', '43')]);

        $this->seedEntry();

        $trail     = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
        $directory = uniqid(sys_get_temp_dir() . '/audit-log-trail-', true);

        mkdir($directory, 0700);

        try {
            $result   = $trail->holdingDataOf($owner)->export($directory . '/trail.ndjson');
            $contents = (string) file_get_contents($directory . '/trail.ndjson');
        } finally {
            array_map(unlink(...), glob($directory . '/*') ?: []);
            rmdir($directory);
        }

        self::assertSame(2, $trail->holdingDataOf($owner)->count());
        self::assertSame(4, $trail->count());
        self::assertSame(2, $result->lines);

        foreach ($held as $id) {
            self::assertStringContainsString($id, $contents);
        }

        self::assertStringNotContainsString($other, $contents);
    }

    /**
     * An erased owner's entries are still found: erasure destroys its keys and
     * leaves the key uses, so the entries holding its now unreadable fragments
     * can still be reviewed.
     *
     * @return void
     */
    public function testAnErasedOwnersEntriesAreStillFound(): void
    {
        $this->allowEverything();

        $owner = Reference::of('App\Models\User', '42');
        $ids   = [$this->seedHolding([$owner]), $this->seedHolding([$owner, Reference::of('App\Models\User', '43')])];

        $this->seedHolding([Reference::of('App\Models\User', '43')]);
        $this->eraseByHand($owner);

        $trail = app(AuditTrail::class)->visibleTo($this->viewer())->holdingDataOf($owner);

        self::assertSame(self::sorted($ids), self::sorted(self::idsOf($trail->cursorPaginate())));
        self::assertSame(2, $trail->count());
    }

    /**
     * A page's cursor is bound to the owner whose data the trail holds: it
     * opens the next page of the same owner's entries and is refused for
     * another owner's, or for the trail without the owner.
     *
     * @return void
     */
    public function testTheCursorBindsTheOwner(): void
    {
        $this->allowEverything();

        $owner = Reference::of('App\Models\User', '42');
        $other = Reference::of('App\Models\User', '43');
        $ids   = [$this->seedHolding([$owner, $other]), $this->seedHolding([$owner, $other]), $this->seedHolding([$owner, $other])];
        $trail = app(AuditTrail::class)->visibleTo($this->viewer());
        $first = $trail->holdingDataOf($owner)->cursorPaginate(2);

        self::assertIsString($first->nextCursor);

        $next = $trail->holdingDataOf($owner)->cursorPaginate(2, $first->nextCursor);

        self::assertSame(self::sorted($ids), self::sorted([...self::idsOf($first), ...self::idsOf($next)]));

        foreach ([$trail->holdingDataOf($other), $trail] as $index => $another) {
            try {
                $another->cursorPaginate(2, $first->nextCursor);

                self::fail("Expected read {$index} to refuse the cursor.");
            } catch (InvalidCursorException $refusal) {
                self::assertEquals(InvalidCursorException::refused(), $refusal);
            }
        }
    }

    /**
     * Read a count and a page as the viewer, and assert the policy was handed
     * the viewer itself each time and the reads were recorded under the
     * reference given.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  array{0: string, 1: string}  $reference
     * @return void
     */
    private function assertReadAs(Authenticatable|Reference $viewer, array $reference): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $trail  = app(AuditTrail::class)->visibleTo($viewer)->inCategory('finance');

        $trail->count();
        $trail->cursorPaginate();

        self::assertCount(2, $policy->asked());
        self::assertSame($viewer, $policy->asked()[0][0]);
        self::assertSame($viewer, $policy->asked()[1][0]);

        foreach ($this->readRecords() as $record) {
            self::assertSame($reference, [$record['actor_type'], $record['actor_id']]);
        }

        self::assertCount(2, $this->readRecords());
    }

    /**
     * Store an entry holding a fragment of each owner, each sealed under the
     * owner's key in a field of its own, and return its id.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     * @return string
     */
    private function seedHolding(array $owners): string
    {
        $id         = Str::uuid7()->toString();
        $properties = [];

        foreach ($owners as $index => $owner) {
            [$key, $dataKey] = $this->makeSubjectKey($owner);

            $properties['field_' . $index] = $this->sealEnvelope($dataKey, $key->id, 'fragment ' . $index, $id, ['properties', 'field_' . $index]);
        }

        return $this->seedEntry(['properties' => $properties], id: $id);
    }

    /**
     * The ids of the entries the page shows, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return list<string>
     */
    private static function idsOf(TrailPage $page): array
    {
        return array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);
    }

    /**
     * The ids, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        sort($ids, SORT_STRING);

        return $ids;
    }

    /**
     * The trail's filters in their normalised form.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return array<string, array{0: string, 1: string}|list<string>|string|null>
     */
    private static function filtersOf(AuditTrail $trail): array
    {
        $filters = (new \ReflectionProperty(AuditTrail::class, 'filters'))->getValue($trail);

        self::assertInstanceOf(TrailFilters::class, $filters);

        return $filters->normalised();
    }

    /**
     * The trail's viewer, or `null` without one.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return ?object
     */
    private static function viewerOf(AuditTrail $trail): ?object
    {
        $viewer = (new \ReflectionProperty(AuditTrail::class, 'viewer'))->getValue($trail);

        return is_object($viewer) ? $viewer : null;
    }
}
