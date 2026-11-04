<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\ExportBundle;
use SineMacula\Laravel\AuditLog\Querying\Exporter;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportVerifier;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\TestCase;

/**
 * End-to-end proofs of exporting the trail and verifying the export, through
 * the trail alone: an export verifies, a changed or reordered line fails its
 * verification, a denied export is published empty and journalled as a denial,
 * an export limited to a tenant holds that tenant alone and is verified only by
 * a viewer whose scope reaches its journal, a verification by a denied viewer
 * is recorded as a denial that finds the entry missing, an export never holds
 * its own journal and still verifies once the trail has grown, and a page, a
 * count and an export under one scope and one set of filters see the same
 * entries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Exporter::class)]
#[CoversClass(ExportVerifier::class)]
final class ExportProofsTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail, SeedsArtifacts;

    /** @var string The code of an export's journal. */
    private const string TRAIL_EXPORTED = 'audit_log.trail_exported';

    /** @var string The code of a verification's record. */
    private const string EXPORT_VERIFIED = 'audit_log.export_verified';

    /** @var string The tenant the tests' entries are recorded in. */
    private const string TENANT = 'org_01';

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /**
     * Bind the read path and make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-proofs-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory and everything in it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $path) {
            if (!is_file($path)) {
                continue;
            }

            unlink($path);
        }

        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }

        parent::tearDown();
    }

    /**
     * An export of captured and bulk entries verifies with no finding, naming
     * its journal and its lines, and the verification is recorded as a success
     * with the verdict `verified`.
     *
     * @return void
     */
    public function testAnExportVerifies(): void
    {
        $this->allowEverything();

        $ids = [...$this->seedEntries(3), $this->seedBundle(2)];

        $result       = $this->trail()->export($this->target());
        $verification = $this->trail()->verifyExport($this->target());

        self::assertTrue($verification->isVerified());
        self::assertSame([], $verification->findings);
        self::assertSame($result->entryId, $verification->entryId);
        self::assertSame(4, $verification->lines);
        self::assertSame($ids, $this->exportedIds());

        $record = $this->readRecords(self::EXPORT_VERIFIED)[0];

        self::assertSame(['success', null], [$record['outcome'], $record['reason']]);
        $properties = self::propertiesOf($record);

        self::assertSame(['verified', [], $result->entryId], [$properties['verdict'], $properties['findings'], $properties['export_entry']]);
    }

    /**
     * Changing one value of one line, re-encoded canonically so the line is
     * still well formed, fails the verification: the file's digest no longer
     * matches and the line's HMAC no longer verifies, and the verification is
     * recorded with the verdict `not_verified` and those findings.
     *
     * @return void
     */
    public function testChangingOneLineFailsVerification(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);
        $this->trail()->export($this->target());

        $lines = $this->lines();

        $lines[1] = self::edited($lines[1], static fn (array $line): array => ['reason' => 'edited'] + $line);

        $this->writeLines($lines);

        $verification = $this->trail()->verifyExport($this->target());

        self::assertFalse($verification->isVerified());
        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::LINE_TAMPERED], $verification->findings);

        $properties = self::propertiesOf($this->readRecords(self::EXPORT_VERIFIED)[0]);

        self::assertSame(['not_verified', ['file_mismatch', 'line_tampered'], 'success'], [$properties['verdict'], $properties['findings'], $properties['outcome']]);
    }

    /**
     * Swapping two untouched lines keeps every line's HMAC whole and the count
     * the same, yet fails the verification: the file's digest and the
     * membership digest bind the order.
     *
     * @return void
     */
    public function testReorderingTheLinesFailsVerification(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);
        $this->trail()->export($this->target());

        $lines = $this->lines();

        [$lines[0], $lines[2]] = [$lines[2], $lines[0]];

        $this->writeLines($lines);

        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH], $this->trail()->verifyExport($this->target())->findings);
    }

    /**
     * A viewer the default policy denies is given an empty export, published
     * with its bundle, journalled as `denied` with `no_scope` and an `export`
     * artifact of no member; the journal has no tenant, and a viewer who may
     * see it verifies the empty export.
     *
     * @return void
     */
    public function testADeniedExportIsRecorded(): void
    {
        $this->seedEntries(2);

        $result = $this->trail()->export($this->target());

        self::assertSame(0, $result->lines);
        self::assertSame('', file_get_contents($this->target()));
        self::assertFileExists($this->target() . ExportFile::MANIFEST_SUFFIX);

        $journal    = $this->readRecords(self::TRAIL_EXPORTED)[0];
        $properties = self::propertiesOf($journal);

        self::assertSame($result->entryId, $journal['id']);
        self::assertSame(['denied', 'no_scope', null, null], [$journal['outcome'], $journal['reason'], $journal['tenant_type'], $journal['tenant_id']]);
        self::assertSame(
            [0, hash('sha256', ''), self::termsOf(null, AccessScope::none())->scopeFingerprint, 'denied'],
            [$properties['returned'], $properties['file_sha256'], $properties['scope_fingerprint'], $properties['outcome']],
        );

        $artifact = $this->artifactOf($result->entryId);

        self::assertNotNull($artifact);
        self::assertSame([ArtifactKind::EXPORT->value, 0], [$artifact['kind'], (int) $artifact['member_count']]);

        $this->allowEverything();

        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());
    }

    /**
     * An export by a viewer limited to one tenant holds that tenant's entries
     * alone, neither another tenant's nor those of no tenant; its journal is
     * recorded in that tenant, its manifest names the tenant's scope, the same
     * viewer verifies it, and a viewer of another tenant finds its journal
     * missing.
     *
     * @return void
     */
    public function testAnExportLimitedToATenantHoldsOnlyThatTenant(): void
    {
        $tenant = Reference::of('organisation', self::TENANT);

        $this->allowTenants($tenant);

        $kept = [$this->seedEntry([], '2026-11-01T12:00:00.000001Z'), $this->seedEntry([], '2026-11-01T12:00:00.000004Z')];

        $this->seedEntry(['tenant_id' => 'org_02'], '2026-11-01T12:00:00.000002Z');
        $this->seedEntry(['tenant_type' => null, 'tenant_id' => null], '2026-11-01T12:00:00.000003Z');

        $result = $this->trail()->export($this->target());

        self::assertSame($kept, $this->exportedIds());

        $journal = $this->storedRow($result->entryId);

        self::assertSame(['organisation', self::TENANT], [$journal['tenant_type'], $journal['tenant_id']]);
        self::assertSame(self::termsOf(null, AccessScope::tenants($tenant))->scopeFingerprint, $this->manifest()['scope_fingerprint']);
        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());

        $this->allowTenants(Reference::of('organisation', 'org_02'));

        self::assertSame([ExportFinding::ENTRY_MISSING], $this->trail()->verifyExport($this->target())->findings);
    }

    /**
     * A verification by a viewer the policy denies finds the export entry
     * missing, though the result names the entry the bundle claims, and is
     * recorded as `denied` with `no_scope`, under the denied scope's
     * fingerprint, naming no export entry and disclosing none.
     *
     * @return void
     */
    public function testAVerificationByADeniedViewerIsRecorded(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $result = $this->trail()->export($this->target());

        app()->instance(AuditAccessPolicy::class, new DenyAllPolicy);

        $verification = $this->trail()->verifyExport($this->target());

        self::assertSame([ExportFinding::ENTRY_MISSING], $verification->findings);
        self::assertSame($result->entryId, $verification->entryId);

        $records = $this->readRecords(self::EXPORT_VERIFIED);

        self::assertCount(1, $records);
        self::assertSame(['denied', 'no_scope', 'audit'], [$records[0]['outcome'], $records[0]['reason'], $records[0]['category']]);
        self::assertSameProperties([
            'purpose'           => 'verify',
            'scope_fingerprint' => self::termsOf(null, AccessScope::none())->scopeFingerprint,
            'fingerprint_key'   => app(KeyRing::class)->signingKey()->id,
            'policy'            => DenyAllPolicy::class,
            'export_entry'      => null,
            'verdict'           => 'not_verified',
            'findings'          => ['entry_missing'],
            'outcome'           => 'denied',
        ], array_diff_key(self::propertiesOf($records[0]), ['_audit' => true]));
        self::assertSame([], $this->disclosureOf($records[0]['id'])['members']);
    }

    /**
     * An export never holds its own journal, which is written once its snapshot
     * has ended, but a later export holds the earlier one's journal and the
     * read records made since.
     *
     * @return void
     */
    public function testAnExportNeverHoldsItsOwnJournal(): void
    {
        $this->allowEverything();

        $seeded = $this->seedEntries(2);
        $first  = $this->trail()->export($this->target());

        self::assertSame($seeded, $this->exportedIds());

        $second = $this->trail()->export($this->directory . '/again.ndjson');
        $again  = $this->exportedIds($this->directory . '/again.ndjson');

        self::assertSame([...$seeded, $first->entryId], $again);
        self::assertNotContains($second->entryId, $again);
    }

    /**
     * An export still verifies once the trail has grown: entries recorded, read
     * and verified since are not in its snapshot and change nothing it proves.
     *
     * @return void
     */
    public function testAnExportStillVerifiesOnceTheTrailHasGrown(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->trail()->export($this->target());

        $this->seedEntries(3);
        $this->trail()->cursorPaginate();

        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());
        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());
        self::assertCount(2, $this->readRecords(self::EXPORT_VERIFIED));
    }

    /**
     * Under one scope, of a tenant and its entries of no tenant, without the
     * package's own records, and one set of filters, a page, a count and an
     * export see exactly the same entries, though entries of another tenant, of
     * no tenant, of another actor and of another category are there, and every
     * read records itself as it goes.
     *
     * @return void
     */
    public function testAPageACountAndAnExportSeeTheSameRows(): void
    {
        $tenant = Reference::of('organisation', self::TENANT);

        $this->usePolicy(static fn (): AccessScope => AccessScope::tenants($tenant)->withTenantless()->exceptCategories('audit'));

        $expected = [
            $this->seedEntry([], '2026-11-01T12:00:00.000001Z'),
            $this->seedEntry(['tenant_type' => null, 'tenant_id' => null], '2026-11-01T12:00:00.000002Z'),
            $this->seedEntry([], '2026-11-01T12:00:00.000003Z'),
        ];

        $this->seedEntry(['tenant_id' => 'org_02'], '2026-11-01T12:00:00.000004Z');
        $this->seedEntry(['actor_id' => '43'], '2026-11-01T12:00:00.000005Z');
        $this->seedEntry(['category' => 'security'], '2026-11-01T12:00:00.000006Z');

        $trail = $this->trail()->forActor(Reference::of('user', '42'))->inCategory('finance', 'audit');

        $page   = $trail->cursorPaginate(100);
        $count  = $trail->count();
        $result = $trail->export($this->target());

        $paged = array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);

        self::assertSame(array_reverse($expected), $paged);
        self::assertSame(3, $count);
        self::assertSame(3, $result->lines);
        self::assertSame($expected, $this->exportedIds());
        self::assertCount(1, $this->readRecords('audit_log.trail_read'));
        self::assertCount(1, $this->readRecords('audit_log.trail_counted'));
    }

    /**
     * The trail the tests read, for the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer());
    }

    /**
     * Where the tests export to.
     *
     * @return string
     */
    private function target(): string
    {
        return $this->directory . '/trail.ndjson';
    }

    /**
     * The lines of the export at the path, or the target, without their line
     * feeds.
     *
     * @param  ?string  $path
     * @return list<string>
     */
    private function lines(?string $path = null): array
    {
        $contents = (string) file_get_contents($path ?? $this->target());

        return $contents === '' ? [] : explode("\n", substr($contents, 0, -1));
    }

    /**
     * Write the lines to the target, each with its line feed.
     *
     * @param  list<string>  $lines
     * @return void
     */
    private function writeLines(array $lines): void
    {
        file_put_contents($this->target(), implode('', array_map(static fn (string $line): string => $line . "\n", $lines)));
    }

    /**
     * The ids of the NDJSON lines of the export at the path, or the target, in
     * order.
     *
     * @param  ?string  $path
     * @return list<string>
     */
    private function exportedIds(?string $path = null): array
    {
        return array_map(static function (string $line): string {
            $decoded = json_decode($line, true, 513, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);
            self::assertIsString($decoded['id'] ?? null);

            return $decoded['id'];
        }, $this->lines($path));
    }

    /**
     * The fields of the manifest the target's bundle carries.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     */
    private function manifest(): array
    {
        $bundle = ExportBundle::decode((string) file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));

        self::assertNotNull($bundle);

        $read = ExportManifest::read($bundle['manifest']);

        self::assertNotNull($read);

        return $read['fields'];
    }

    /**
     * The NDJSON line with its envelope as the edit gives it, in the canonical
     * encoding an export writes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $line
     * @param  \Closure(array<array-key, mixed>): array<array-key, mixed>  $edit
     * @return string
     */
    private static function edited(string $line, \Closure $edit): string
    {
        $decoded = json_decode($line, false, 513, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $decoded);

        return CanonicalEncoder::encode($edit(get_object_vars($decoded)));
    }
}
