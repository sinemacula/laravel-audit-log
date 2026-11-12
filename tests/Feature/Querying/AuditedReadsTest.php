<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\AccessEvidence;
use SineMacula\Laravel\AuditLog\Querying\AccessRecorder;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\Concerns\InteractsWithAuditLog;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;

/**
 * Feature tests for the records the trail's reads leave.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
#[CoversClass(AccessRecorder::class)]
#[CoversClass(AccessEvidence::class)]
final class AuditedReadsTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditLog, ReadsTheTrail;

    /** @var list<string> The evidence a page's record holds, in this order. */
    private const array PAGE_EVIDENCE = [
        'purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'reveal', 'fields', 'outcome',
    ];

    /** @var list<string> The evidence a count's record holds, in this order. */
    private const array COUNT_EVIDENCE = ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'returned', 'outcome'];

    /**
     * Bind the read path and capture every line logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->captureLogLines();
    }

    /**
     * A page read is recorded once, as a success, and leaves nothing else.
     *
     * @return void
     */
    public function testAPageReadIsRecordedOnce(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $page = $this->financeTrail()->cursorPaginate();

        $records = $this->readRecords();

        self::assertCount(3, $page->entries);
        self::assertSame([['audit_log.trail_read', 'success']], array_map(static fn (array $record): array => [$record['event'], $record['outcome']], $records));
        self::assertSame(4, $this->entryTotal());
        self::assertSame([], $this->spillLines());
    }

    /**
     * Each terminal call is recorded on its own, the same page twice included.
     *
     * @return void
     */
    public function testEachReadIsRecordedOnItsOwn(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $this->financeTrail()->cursorPaginate();
        $this->financeTrail()->cursorPaginate();

        self::assertCount(2, $this->readRecords('audit_log.trail_read'));
    }

    /**
     * A denied read returns an empty page and is recorded once as `no_scope`.
     *
     * @return void
     */
    public function testADeniedReadReturnsEmptyAndIsRecordedOnce(): void
    {
        $this->seedEntries(3);

        $page    = $this->financeTrail()->cursorPaginate(10);
        $records = $this->readRecords();

        self::assertSame([[], null, false], [$page->entries, $page->nextCursor, $page->hasMore()]);
        self::assertCount(1, $records);
        self::assertSame(['audit_log.trail_read', 'denied', 'no_scope'], [$records[0]['event'], $records[0]['outcome'], $records[0]['reason']]);
        self::assertSame(0, self::propertiesOf($records[0])['returned']);
        self::assertSame([], $this->disclosureOf(self::idOf($records[0]))['members']);
    }

    /**
     * Reading the read records records only that read, never its own record.
     *
     * @return void
     */
    public function testReadingTheReadRecordsRecordsOnlyThatRead(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->financeTrail()->cursorPaginate();

        $first   = $this->readRecords('audit_log.trail_read')[0]['id'];
        $reads   = app(AuditTrail::class)->visibleTo($this->viewer())->forEvent('audit_log.trail_read');
        $page    = $reads->cursorPaginate();
        $records = $this->readRecords();

        self::assertSame([$first], self::idsOf($page));
        self::assertCount(2, $records);
        self::assertSame([$first, $page->entries[0]->hmac], $this->disclosureOf(self::idOf($records[1]))['members'][0]);

        self::assertSame(2, $reads->count());
        self::assertSame(['audit_log.trail_read', 'audit_log.trail_read', 'audit_log.trail_counted'], array_column($this->readRecords(), 'event'));
    }

    /**
     * A page's record holds exactly the read's evidence, in order.
     *
     * @return void
     */
    public function testTheReadRecordHoldsTheEvidence(): void
    {
        $scope = AccessScope::tenants(Reference::of('organisation', 'org_01'));

        $this->usePolicy(static fn (): AccessScope => $scope);
        $this->seedEntries(3);

        $this->financeTrail()->cursorPaginate(2);

        $properties = self::propertiesOf($this->readRecords('audit_log.trail_read')[0]);
        $audit      = $properties['_audit'] ?? null;

        unset($properties['_audit']);

        self::assertSamePropertyKeys(self::PAGE_EVIDENCE, $properties);
        $terms = self::termsOf(TrailFilters::none()->withCategories(['finance']), $scope);

        self::assertSameProperties([
            'purpose'           => 'read',
            'query_fingerprint' => $terms->queryFingerprint,
            'scope_fingerprint' => $terms->scopeFingerprint,
            'fingerprint_key'   => app(KeyRing::class)->signingKey()->id,
            'policy'            => ClosurePolicy::class,
            'page'              => 'first',
            'per_page'          => 2,
            'returned'          => 2,
            'reveal'            => false,
            'fields'            => ['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0],
            'outcome'           => 'success',
        ], $properties);
        self::assertIsArray($audit);
        self::assertSame(['manifest'], array_keys($audit));
        self::assertSame(ArtifactKind::DISCLOSURE->value, $audit['manifest']['kind'] ?? null);
        self::assertSame(2, $audit['manifest']['count'] ?? null);
    }

    /**
     * A multi-tenant read row holds keyed fingerprints, never a tenant's id.
     *
     * @return void
     */
    public function testReadersOfTheReadRowSeeFingerprintsNotTenantIds(): void
    {
        $tenant  = Reference::of('organisation', 'org_01');
        $scope   = AccessScope::tenants($tenant, Reference::of('organisation', 'org_77'));
        $filters = TrailFilters::none()->withCategories(['finance'])->withReference('tenant', $tenant);

        $this->usePolicy(static fn (): AccessScope => $scope);
        $this->seedEntry();
        $this->financeTrail()->forTenant($tenant)->cursorPaginate();

        $record = $this->readRecords('audit_log.trail_read')[0];
        $id     = $record['id'];

        self::assertSame([null, null], [$record['tenant_type'], $record['tenant_id']]);

        $this->allowEverything();

        $shown = app(AuditTrail::class)->visibleTo(Reference::of('App\Models\User', '8'))->forEvent('audit_log.trail_read')->cursorPaginate()->entries[0];

        $columns = [
            'the entry'       => DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->first(),
            'the artifact'    => DB::connection(StorageConnection::name())->table(EntrySettings::artifactsTable())->where('entry_id', $id)->first(),
            'the shown entry' => $shown->toArray(),
        ];

        self::assertSame($id, $shown->id);
        $terms = self::termsOf($filters, $scope);

        self::assertSame([$terms->scopeFingerprint, $terms->queryFingerprint], [$shown->properties['scope_fingerprint'] ?? null, $shown->properties['query_fingerprint'] ?? null]);
        self::assertNotSame(hash('sha256', CanonicalEncoder::encode($filters->normalised())), $terms->queryFingerprint);
        self::assertNotSame(hash('sha256', CanonicalEncoder::encode($scope->toArray())), $terms->scopeFingerprint);
        self::assertNotSame($scope->fingerprint(), $terms->scopeFingerprint);

        foreach ($columns as $name => $columnsOf) {
            $json = json_encode($columnsOf, JSON_THROW_ON_ERROR);

            self::assertStringNotContainsString('org_77', $json, "The columns of {$name} name a tenant of the scope.");
            self::assertStringNotContainsString('org_01', $json, "The columns of {$name} name the tenant of the filter.");
        }

        $disclosure = $this->disclosureOf($id);

        self::assertSame($scope->toArray(), $disclosure['scope']);
        self::assertSame($filters->normalised(), $disclosure['filters']);
    }

    /**
     * An owner filter is fingerprinted in the read row, never named.
     *
     * @return void
     */
    public function testTheOwnerHoldingDataIsFingerprintedNeverNamed(): void
    {
        $owner   = Reference::of('App\Models\User', 'owner_9917');
        $filters = TrailFilters::none()->withCategories(['finance'])->withHoldingDataOf($owner);

        $this->allowEverything();
        $this->seedEntry();
        $this->financeTrail()->holdingDataOf($owner)->cursorPaginate();
        $this->financeTrail()->cursorPaginate();

        [$record, $without] = $this->readRecords('audit_log.trail_read');

        $columns = [
            'the entry'    => DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $record['id'])->first(),
            'the artifact' => DB::connection(StorageConnection::name())->table(EntrySettings::artifactsTable())->where('entry_id', $record['id'])->first(),
        ];

        foreach ($columns as $name => $columnsOf) {
            self::assertStringNotContainsString('owner_9917', json_encode($columnsOf, JSON_THROW_ON_ERROR), "The columns of {$name} name the owner.");
        }

        $fingerprint = self::propertiesOf($record)['query_fingerprint'];

        self::assertSame(self::termsOf($filters, AccessScope::all())->queryFingerprint, $fingerprint);
        self::assertNotSame(self::propertiesOf($without)['query_fingerprint'], $fingerprint);
        self::assertSame(['App\Models\User', 'owner_9917'], $this->disclosureOf(self::idOf($record))['filters']['holding_data_of']);
        self::assertNull($this->disclosureOf(self::idOf($without))['filters']['holding_data_of']);
    }

    /**
     * The disclosure lists the id and HMAC of each returned entry, in order.
     *
     * @return void
     */
    public function testTheDisclosureListsTheReturnedPairs(): void
    {
        $this->allowEverything();

        $ids  = $this->seedEntries(3);
        $page = $this->financeTrail()->cursorPaginate(2);

        $disclosure = $this->disclosureOf(self::idOf($this->readRecords('audit_log.trail_read')[0]));

        self::assertSame(array_map(static fn (TrailEntry $entry): array => [$entry->id, $entry->hmac], $page->entries), $disclosure['members']);
        self::assertSame([$ids[2], $ids[1]], array_column($disclosure['members'], 0));
        self::assertSame(1, $disclosure['disclosure_version']);
        self::assertSame(TrailFilters::none()->withCategories(['finance'])->normalised(), $disclosure['filters']);
        self::assertSame(AccessScope::all()->toArray(), $disclosure['scope']);
    }

    /**
     * A count is recorded once with what it counted and no page.
     *
     * @return void
     */
    public function testACountIsRecordedWithItsResult(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        self::assertSame(3, $this->financeTrail()->count());

        $record     = $this->readRecords('audit_log.trail_counted')[0];
        $properties = self::propertiesOf($record);

        unset($properties['_audit']);

        self::assertCount(1, $this->readRecords());
        self::assertSamePropertyKeys(self::COUNT_EVIDENCE, $properties);
        self::assertSame(['count', 3, 'success'], [$properties['purpose'], $properties['returned'], $properties['outcome']]);
        self::assertSame([], $this->disclosureOf(self::idOf($record))['members']);
    }

    /**
     * Under the `report` failure mode, a read whose record fails is refused.
     *
     * @return void
     */
    public function testAReadIsFailClosedUnderTheReportMode(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'report');

        $this->allowEverything();
        $this->seedEntries(2);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        self::assertInstanceOf(AuditRecord::class, AuditLog::record('invoice.approved'));

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->financeTrail()->cursorPaginate();
    }

    /**
     * Under the fake, a read returns its rows and its record is assertable.
     *
     * @return void
     */
    public function testUnderTheFakeAReadIsAssertable(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        AuditLog::fake();

        self::assertCount(2, $this->financeTrail()->cursorPaginate()->entries);
        self::assertSame(2, $this->financeTrail()->count());

        $this->assertAuditedTimes('audit_log.trail_read', 1)
            ->assertAuditedTimes('audit_log.trail_counted', 1)
            ->assertAudited('audit_log.trail_read', static fn (AuditRecord $record): bool => $record->outcome === 'success' && $record->actorId === '7')
            ->assertNotAudited('audit_log.trail_exported');
    }

    /**
     * A read record's actor is the viewer, never the signed-in user.
     *
     * @return void
     */
    public function testTheActorIsTheViewerNeverTheSignedInUser(): void
    {
        $this->allowEverything();
        $this->actingAs(new GenericUser(['id' => 'signed-in-99']));

        $this->financeTrail()->cursorPaginate();

        $record = $this->readRecords('audit_log.trail_read')[0];

        self::assertSame(['App\Models\User', '7'], [$record['actor_type'], $record['actor_id']]);
        self::assertStringNotContainsString('signed-in-99', json_encode($record, JSON_THROW_ON_ERROR));
    }

    /**
     * Every read record is in the `audit` category at version 1.
     *
     * @return void
     */
    public function testTheReadRecordsCategoryIsAudit(): void
    {
        $this->financeTrail()->cursorPaginate();
        $this->financeTrail()->count();
        $this->allowEverything();
        $this->financeTrail()->cursorPaginate();
        $this->financeTrail()->count();

        $records = $this->readRecords();

        self::assertCount(4, $records);

        foreach ($records as $record) {
            $code = json_encode($record['event'], JSON_THROW_ON_ERROR);

            self::assertSame(['audit', 1], [$record['category'], $record['event_version']], "{$code} is not in the audit category at version 1.");
        }
    }

    /**
     * How many rows the entries table holds, of every code.
     *
     * @return int
     */
    private function entryTotal(): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->count();
    }
}
