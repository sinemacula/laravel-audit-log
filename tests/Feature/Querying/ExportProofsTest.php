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
 * End-to-end proofs of exporting the trail and verifying the export.
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
     * An export verifies with no finding and is recorded `verified`.
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
     * Changing one line fails verification on its digest and its HMAC.
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
     * Reordering lines fails verification: the digests bind the order.
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
     * A denied export is published empty and journalled as `denied`.
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
     * A tenant-limited export holds that tenant alone, verifiable in its scope.
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
     * A denied viewer's verification finds the entry missing and is recorded.
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
        self::assertSame([], $this->disclosureOf(self::idOf($records[0]))['members']);
    }

    /**
     * An export never holds its own journal, written after its snapshot ends.
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
     * An export still verifies once the trail has grown.
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
     * A page, a count and an export see the same rows under one scope.
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
     * The lines of the export at the path, or the target, without line feeds.
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
     * @param  array<int, string>  $lines
     * @return void
     */
    private function writeLines(array $lines): void
    {
        file_put_contents($this->target(), implode('', array_map(static fn (string $line): string => $line . "\n", $lines)));
    }

    /**
     * The ids of the export's lines at the path, or the target, in order.
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
     * The NDJSON line with its envelope edited, canonically encoded.
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
