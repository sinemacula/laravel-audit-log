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
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
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
 * Feature tests for the records the reads of the trail leave, through the read
 * API alone: each read recorded once, a denial included, and a read of the read
 * records recording only that read; the evidence each record holds, its readers
 * seeing fingerprints and never the tenants of another scope, and its
 * disclosure listing what was returned; a count recorded with what it counted;
 * a read fail-closed under the `report` failure mode, assertable under the
 * fake, by the viewer whoever is signed in, and in the `audit` category.
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
     * A page read is recorded once, as a success, and leaves nothing else: no
     * other record, and no spilled line.
     *
     * @return void
     */
    public function testAPageReadIsRecordedOnce(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $page = $this->trail()->cursorPaginate();

        $records = $this->readRecords();

        self::assertCount(3, $page->entries);
        self::assertSame([['audit_log.trail_read', 'success']], array_map(static fn (array $record): array => [$record['event'], $record['outcome']], $records));
        self::assertSame(4, $this->entryTotal());
        self::assertSame([], $this->spillLines());
    }

    /**
     * Each terminal call is authorised and recorded on its own: the same page
     * read twice is recorded twice.
     *
     * @return void
     */
    public function testEachReadIsRecordedOnItsOwn(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $this->trail()->cursorPaginate();
        $this->trail()->cursorPaginate();

        self::assertCount(2, $this->readRecords('audit_log.trail_read'));
    }

    /**
     * A denied read returns an empty page and is recorded once, as a denial
     * with `no_scope`, having returned nothing.
     *
     * @return void
     */
    public function testADeniedReadReturnsEmptyAndIsRecordedOnce(): void
    {
        $this->seedEntries(3);

        $page    = $this->trail()->cursorPaginate(10);
        $records = $this->readRecords();

        self::assertSame([[], null, false], [$page->entries, $page->nextCursor, $page->hasMore()]);
        self::assertCount(1, $records);
        self::assertSame(['audit_log.trail_read', 'denied', 'no_scope'], [$records[0]['event'], $records[0]['outcome'], $records[0]['reason']]);
        self::assertSame(0, self::propertiesOf($records[0])['returned']);
        self::assertSame([], $this->disclosureOf($records[0]['id'])['members']);
    }

    /**
     * A read of the read records shows the records made before it, and is
     * itself recorded once: it records no read of its own record, and reading
     * that record again records only that read.
     *
     * @return void
     */
    public function testReadingTheReadRecordsRecordsOnlyThatRead(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->trail()->cursorPaginate();

        $first   = $this->readRecords('audit_log.trail_read')[0]['id'];
        $reads   = app(AuditTrail::class)->visibleTo($this->viewer())->forEvent('audit_log.trail_read');
        $page    = $reads->cursorPaginate();
        $records = $this->readRecords();

        self::assertSame([$first], self::idsOf($page));
        self::assertCount(2, $records);
        self::assertSame([$first, $page->entries[0]->hmac], $this->disclosureOf($records[1]['id'])['members'][0]);

        self::assertSame(2, $reads->count());
        self::assertSame(['audit_log.trail_read', 'audit_log.trail_read', 'audit_log.trail_counted'], array_column($this->readRecords(), 'event'));
    }

    /**
     * The record of a page holds exactly the evidence of the read, in order:
     * the purpose, the fingerprints of the filters and the scope, the policy,
     * the page and its size, what it returned and the outcome; `_audit` holds
     * the disclosure's descriptor alone.
     *
     * @return void
     */
    public function testTheReadRecordHoldsTheEvidence(): void
    {
        $scope = AccessScope::tenants(Reference::of('organisation', 'org_01'));

        $this->usePolicy(static fn (): AccessScope => $scope);
        $this->seedEntries(3);

        $this->trail()->cursorPaginate(2);

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
     * The read row of a scope of several tenants names none of them: it is in
     * no tenant, its evidence holds keyed fingerprints, which no reader without
     * the key can reverse by hashing candidate filters or scopes, and neither
     * its columns, its artifact's columns nor the entry another viewer reads of
     * it hold a tenant's id, which only the decrypted disclosure does.
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
        $this->trail()->forTenant($tenant)->cursorPaginate();

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
     * A read of the entries holding an owner's data names the owner only in its
     * encrypted disclosure: the read row and its artifact hold the keyed
     * fingerprint of the filters, which differs from the same read's without
     * the owner, and no column of either names the owner's id.
     *
     * @return void
     */
    public function testTheOwnerHoldingDataIsFingerprintedNeverNamed(): void
    {
        $owner   = Reference::of('App\Models\User', 'owner_9917');
        $filters = TrailFilters::none()->withCategories(['finance'])->withHoldingDataOf($owner);

        $this->allowEverything();
        $this->seedEntry();
        $this->trail()->holdingDataOf($owner)->cursorPaginate();
        $this->trail()->cursorPaginate();

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
        self::assertSame(['App\Models\User', 'owner_9917'], $this->disclosureOf($record['id'])['filters']['holding_data_of']);
        self::assertNull($this->disclosureOf($without['id'])['filters']['holding_data_of']);
    }

    /**
     * The disclosure lists the id and HMAC of each entry the page returned, in
     * the order returned, beside the normalised filters and the whole scope,
     * and nothing of the entries the page did not return.
     *
     * @return void
     */
    public function testTheDisclosureListsTheReturnedPairs(): void
    {
        $this->allowEverything();

        $ids  = $this->seedEntries(3);
        $page = $this->trail()->cursorPaginate(2);

        $disclosure = $this->disclosureOf($this->readRecords('audit_log.trail_read')[0]['id']);

        self::assertSame(array_map(static fn (TrailEntry $entry): array => [$entry->id, $entry->hmac], $page->entries), $disclosure['members']);
        self::assertSame([$ids[2], $ids[1]], array_column($disclosure['members'], 0));
        self::assertSame(1, $disclosure['disclosure_version']);
        self::assertSame(TrailFilters::none()->withCategories(['finance'])->normalised(), $disclosure['filters']);
        self::assertSame(AccessScope::all()->toArray(), $disclosure['scope']);
    }

    /**
     * A count is recorded once with what it counted, its purpose and its own
     * evidence, which has no page, and a disclosure of no entry.
     *
     * @return void
     */
    public function testACountIsRecordedWithItsResult(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        self::assertSame(3, $this->trail()->count());

        $record     = $this->readRecords('audit_log.trail_counted')[0];
        $properties = self::propertiesOf($record);

        unset($properties['_audit']);

        self::assertCount(1, $this->readRecords());
        self::assertSamePropertyKeys(self::COUNT_EVIDENCE, $properties);
        self::assertSame(['count', 3, 'success'], [$properties['purpose'], $properties['returned'], $properties['outcome']]);
        self::assertSame([], $this->disclosureOf($record['id'])['members']);
    }

    /**
     * Under the `report` failure mode, where an application's record whose
     * write fails goes on, a read whose record fails is refused and returns
     * nothing.
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

        $this->trail()->cursorPaginate();
    }

    /**
     * Under the fake, which acknowledges at once, a read returns what it found
     * and its record can be asserted by its code and its outcome.
     *
     * @return void
     */
    public function testUnderTheFakeAReadIsAssertable(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        AuditLog::fake();

        self::assertCount(2, $this->trail()->cursorPaginate()->entries);
        self::assertSame(2, $this->trail()->count());

        $this->assertAuditedTimes('audit_log.trail_read', 1)
            ->assertAuditedTimes('audit_log.trail_counted', 1)
            ->assertAudited('audit_log.trail_read', static fn (AuditRecord $record): bool => $record->outcome === 'success' && $record->actorId === '7')
            ->assertNotAudited('audit_log.trail_exported');
    }

    /**
     * The read record's actor is the viewer the read named, never the user
     * signed in to the request, who is not named anywhere in it.
     *
     * @return void
     */
    public function testTheActorIsTheViewerNeverTheSignedInUser(): void
    {
        $this->allowEverything();
        $this->actingAs(new GenericUser(['id' => 'signed-in-99']));

        $this->trail()->cursorPaginate();

        $record = $this->readRecords('audit_log.trail_read')[0];

        self::assertSame(['App\Models\User', '7'], [$record['actor_type'], $record['actor_id']]);
        self::assertStringNotContainsString('signed-in-99', json_encode($record, JSON_THROW_ON_ERROR));
    }

    /**
     * Every read record is in the `audit` category, at version 1 of its code, a
     * page's and a count's, a success's and a denial's.
     *
     * @return void
     */
    public function testTheReadRecordsCategoryIsAudit(): void
    {
        $this->trail()->cursorPaginate();
        $this->trail()->count();
        $this->allowEverything();
        $this->trail()->cursorPaginate();
        $this->trail()->count();

        $records = $this->readRecords();

        self::assertCount(4, $records);

        foreach ($records as $record) {
            $code = json_encode($record['event'], JSON_THROW_ON_ERROR);

            self::assertSame(['audit', 1], [$record['category'], $record['event_version']], "{$code} is not in the audit category at version 1.");
        }
    }

    /**
     * The trail, in the `finance` category the seeded entries are in, read for
     * the viewer, so the records of the reads themselves are never among what
     * is read.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
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
}
