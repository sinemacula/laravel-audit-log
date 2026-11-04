<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportVerifier;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Export\GoldenExport;
use Tests\TestCase;

/**
 * Feature tests for the golden version 1 export: its files are exactly the ones
 * generated once, pinned by their digests so a regeneration shows in review,
 * and once its journal's rows are stored, an export made by an earlier release
 * verifies through the trail, every line by its own versions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportVerifier::class)]
final class GoldenExportTest extends TestCase
{
    use ReadsTheTrail;

    /** @var string The directory the golden files are in. */
    private const string DIRECTORY = __DIR__ . '/../../Fixtures/Export/golden-v1';

    /** @var array<string, string> The SHA-256 of each golden file, by its name. */
    private const array DIGESTS = [
        'export.ndjson'               => '3cbabe53fa05731a956034f9d31d6d1c3bb67186606993de35c15d05effe0eb2',
        'export.ndjson.manifest.json' => '84c49790cba5baf903ccc9b23aa19c43c62d4ee3c3f604ab6a95d770f124cd45',
        'journal.json'                => '3c15632c5432ab22b118b222c44fc1b0d2acfd05df8c0650fee6df6787584f0c',
    ];

    /**
     * Bind the read path and let every viewer see everything.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();
    }

    /**
     * Each golden file is byte for byte the one generated once.
     *
     * @return void
     */
    public function testTheGoldenFilesAreUnchanged(): void
    {
        $files = array_map(basename(...), glob(self::DIRECTORY . '/*') ?: []);

        sort($files);

        self::assertSame(array_keys(self::DIGESTS), $files);

        foreach (self::DIGESTS as $file => $digest) {
            self::assertSame($digest, hash_file('sha256', self::DIRECTORY . '/' . $file), $file);
        }

        self::assertSame(GoldenExport::FILE . ExportFile::MANIFEST_SUFFIX, array_keys(self::DIGESTS)[1]);
    }

    /**
     * Each line of the golden export is a stored entry's 37 columns, the source
     * digest among them, `null` on these captured entries.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEveryLineCarriesEveryColumn(): void
    {
        $lines = file(self::DIRECTORY . '/' . GoldenExport::FILE, FILE_IGNORE_NEW_LINES) ?: [];

        self::assertCount(3, $lines);

        foreach ($lines as $line) {
            $columns = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($columns);
            self::assertCount(37, $columns);
            self::assertArrayHasKey('source_digest', $columns);
            self::assertNull($columns['source_digest']);
        }
    }

    /**
     * With its journal's entry and artifact stored as an earlier release stored
     * them, the golden export verifies through the trail: the entry's HMAC, its
     * descriptor, the artifact, the manifest, the file, its membership and
     * every line.
     *
     * @return void
     */
    public function testTheGoldenVersionOneExportVerifies(): void
    {
        $journal = $this->insertJournal();

        $auditor      = Reference::of(GoldenExport::VIEWER_TYPE, GoldenExport::VIEWER_ID);
        $verification = app(AuditTrail::class)->visibleTo($auditor)->verifyExport(self::DIRECTORY . '/' . GoldenExport::FILE);

        self::assertSame([], $verification->findings);
        self::assertTrue($verification->isVerified());
        self::assertSame($journal, $verification->entryId);
        self::assertSame(3, $verification->lines);
        self::assertSame('verified', self::propertiesOf($this->readRecords('audit_log.export_verified')[0])['verdict']);
    }

    /**
     * The golden export's manifest names the scope it was made under by the
     * keyed fingerprint of that scope's normalised form, the grant to reveal
     * the encrypted fields included: an auditor who sees every entry and
     * reveals nothing.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheManifestNamesTheScopeWithItsGrant(): void
    {
        $bundle   = json_decode((string) file_get_contents(self::DIRECTORY . '/' . GoldenExport::FILE . ExportFile::MANIFEST_SUFFIX), true, 512, JSON_THROW_ON_ERROR);
        $terms    = self::termsOf(TrailFilters::none(), AccessScope::all());
        $revealed = self::termsOf(TrailFilters::none(), AccessScope::all()->revealingEncryptedFields());

        self::assertIsArray($bundle);
        self::assertIsArray($bundle['entry']['properties'] ?? null);
        self::assertSame($terms->scopeFingerprint, $bundle['entry']['properties']['scope_fingerprint'] ?? null);
        self::assertNotSame($revealed->scopeFingerprint, $bundle['entry']['properties']['scope_fingerprint']);
    }

    /**
     * Without its journal stored, the golden export's entry is missing, and its
     * file still matches the bundle's manifest.
     *
     * @return void
     */
    public function testWithoutItsJournalTheEntryIsMissing(): void
    {
        $verification = app(AuditTrail::class)->visibleTo($this->viewer())->verifyExport(self::DIRECTORY . '/' . GoldenExport::FILE);

        self::assertSame(['entry_missing'], array_column($verification->findings, 'value'));
        self::assertSame(3, $verification->lines);
    }

    /**
     * Store the journal's entry and artifact rows, as the golden journal holds
     * them, and return the entry's id.
     *
     * @return string
     */
    private function insertJournal(): string
    {
        $journal = json_decode((string) file_get_contents(self::DIRECTORY . '/' . GoldenExport::JOURNAL), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($journal);
        self::assertIsArray($journal['entry'] ?? null);
        self::assertIsArray($journal['artifact'] ?? null);
        self::assertIsString($journal['entry']['id'] ?? null);

        $connection = DB::connection(StorageConnection::name());

        $connection->table(EntrySettings::artifactsTable())->insert($journal['artifact']);
        $connection->table(EntrySettings::table())->insert($journal['entry']);

        return $journal['entry']['id'];
    }
}
