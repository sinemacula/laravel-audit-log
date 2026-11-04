<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportVerifier;
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
        'export.ndjson'               => '8c02a6133aebc6a630fedbfee4bdcda4d3d3ba679a237d2bbbcfd4efc10254a7',
        'export.ndjson.manifest.json' => '5d1e870420edeb0bc48f0092890ff76e97b5438508c751380f107f8543c58560',
        'journal.json'                => 'ccb536080839d57eab39bc61ffb9161b0b5315998d19916cf1c3c51032a90f97',
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
