<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;
use SineMacula\Laravel\AuditLog\Querying\ExportBundle;
use SineMacula\Laravel\AuditLog\Querying\Exporter;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportSnapshot;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Export\ReservedKeyMapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\Fixtures\Querying\RevealingFieldReader;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the exporter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Exporter::class)]
final class ExporterTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, ReadsTheTrail, SeedsArtifacts;

    /** @var string The code of an export's journal. */
    private const string TRAIL_EXPORTED = 'audit_log.trail_exported';

    /** @var string What a reader would reveal of a card, which no hex, base64url or UUID holds by chance. */
    private const string REVEALED_CARD = 'revealed-card-s3cr3t';

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /** @var bool Whether a read of the entries table on the storage connection fails. */
    private bool $failEntryReads = false;

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Bind the read path, report to a recording handler and make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();

        $this->reporter  = new RecordingExceptionHandler;
        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-export-', true);

        app()->instance(ExceptionHandler::class, $this->reporter);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory and restore the entries table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $path) {
            if (!is_file($path) && !is_link($path)) {
                continue;
            }

            unlink($path);
        }

        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }

        $this->removeProbeTable();

        parent::tearDown();
    }

    /**
     * The policy is asked once for the viewer and the purpose `export`.
     *
     * @return void
     */
    public function testTheExportIsAuthorisedForTheExportPurpose(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $viewer = $this->viewer();

        app(AuditTrail::class)->visibleTo($viewer)->export($this->target());

        self::assertCount(1, $policy->asked());
        self::assertSame($viewer, $policy->asked()[0][0]);
        self::assertSame(ReadPurpose::EXPORT, $policy->asked()[0][1]);
    }

    /**
     * Each NDJSON line is the stored envelope untouched, so its HMAC verifies.
     *
     * @return void
     */
    public function testAnNdjsonLineIsTheStoredEnvelopeUntouched(): void
    {
        $this->allowEverything();

        $id = $this->seedEntry(['properties' => ['amount' => '1200.00', 'note' => ['kept' => true]]]);

        $this->trail()->export($this->target());

        $lines = $this->lines();

        self::assertSame([CanonicalEncoder::encode($this->storedRow($id))], $lines);

        $decoded = json_decode($lines[0], false, 513, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $decoded);
        self::assertTrue(app(RecordSigner::class)->verifies(get_object_vars($decoded)));
    }

    /**
     * Lines are in ascending recorded order, ties broken by id.
     *
     * @return void
     */
    public function testLinesAreInAscendingRecordedOrder(): void
    {
        $this->allowEverything();

        $late  = $this->seedEntry([], '2026-11-01T12:00:00.000003Z', '01932b4e-a000-7000-8000-000000000001');
        $tieB  = $this->seedEntry([], '2026-11-01T12:00:00.000002Z', '01932b4e-a000-7000-8000-00000000000b');
        $tieA  = $this->seedEntry([], '2026-11-01T12:00:00.000002Z', '01932b4e-a000-7000-8000-00000000000a');
        $early = $this->seedEntry([], '2026-11-01T12:00:00.000001Z', '01932b4e-a000-7000-8000-000000000009');

        $this->trail()->export($this->target());

        self::assertSame([$early, $tieA, $tieB, $late], $this->exportedIds());
    }

    /**
     * Chunks follow recorded order, not occurrence; the seeded order matches
     * neither, so ordering by occurrence would fail.
     *
     * @return void
     */
    public function testChunksFollowTheRecordedOrderNotTheOccurrence(): void
    {
        app(ConfigRepository::class)->set('audit-log.export.chunk', 100);

        $this->allowEverything();

        $byRecord = [];

        for ($index = 0; $index < 250; $index++) {
            $slot       = ($index * 7) % 250;
            $recordedAt = sprintf('2026-11-01T13:00:00.%06dZ', $slot);
            $finalised  = $this->finaliser($recordedAt)->finalise(RecordFactory::captured(occurredAt: sprintf('2026-11-01T12:00:00.%06dZ', $index)));

            app(DatabaseAuditStore::class)->store($finalised);

            $byRecord[$slot] = [$recordedAt, $finalised->record->id];
        }

        ksort($byRecord);

        $this->trail()->export($this->target());

        $manifest = json_decode($this->bundle()['manifest'], true, 16, JSON_THROW_ON_ERROR);

        self::assertIsArray($manifest);
        self::assertSame(array_column($byRecord, 1), $this->exportedIds());
        self::assertSame([$byRecord[0], $byRecord[249]], [$manifest['first'] ?? null, $manifest['last'] ?? null]);
    }

    /**
     * A malformed `export.chunk` refuses the export before anything else.
     *
     * @return void
     */
    public function testAMalformedChunkIsRefusedBeforeAnything(): void
    {
        app(ConfigRepository::class)->set('audit-log.export.chunk', 99);

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(2);
        $this->captureQueries();

        try {
            $this->trail()->export($this->target());
            self::fail('Expected the export to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertStringContainsString('`audit-log.export.chunk`', $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->readRecords());
        self::assertFileDoesNotExist($this->target());
        self::assertSame([], $this->temporaries());
    }

    /**
     * An unbuildable manifest is recorded as `format_failed` and refused.
     *
     * @return void
     */
    public function testAManifestThatCannotBeBuiltIsRecordedAndRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $storage  = DB::connection(StorageConnection::name());
        $database = $storage->getDatabaseName();
        $begins   = array_map(static fn (array $statements): string => $statements[array_key_last($statements)], ExportSnapshot::BEGIN);

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($begins): void {
            if (!in_array($query->sql, $begins, true)) {
                return;
            }

            $query->connection->setDatabaseName('');
        });

        try {
            $this->trail()->export($this->target());
            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(\InvalidArgumentException::class)->getMessage(), $refusal->getMessage());
        } finally {
            $storage->setDatabaseName($database);
        }

        $journal = $this->readRecords('audit_log.trail_exported');

        self::assertCount(1, $journal);
        self::assertSame(['failure', 'format_failed'], [$journal[0]['outcome'], $journal[0]['reason']]);
        self::assertFileDoesNotExist($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temporaries());
    }

    /**
     * The file is prepared, then journalled, then published with its bundle.
     *
     * @return void
     */
    public function testPrepareJournalPublishInOrder(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $seen = null;

        $this->onJournal(function () use (&$seen): void {
            $seen = [$this->temporaries(), file_exists($this->target()), file_exists($this->target() . ExportFile::MANIFEST_SUFFIX)];
        });

        $this->trail()->export($this->target());

        self::assertIsArray($seen);
        self::assertCount(1, $seen[0]);
        self::assertSame([false, false], [$seen[1], $seen[2]]);
        self::assertFileExists($this->target());
        self::assertFileExists($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temporaries());
    }

    /**
     * The snapshot is committed before the journal is written.
     *
     * @return void
     */
    public function testTheJournalIsWrittenAfterTheSnapshotEnds(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->captureQueries();

        $this->trail()->export($this->target());

        $begun      = ExportSnapshot::BEGIN[$this->driver()];
        $statements = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());
        $begin      = array_search($begun[count($begun) - 1], $statements, true);
        $commit     = array_search('COMMIT', $statements, true);
        $writes     = array_keys(array_filter($statements, static fn (string $sql): bool => str_starts_with(strtolower($sql), 'insert')));

        self::assertIsInt($begin);
        self::assertIsInt($commit);
        self::assertNotSame([], $writes);
        self::assertMatchesRegularExpression('/order by .recorded_at. desc, .id. desc limit 1$/', $statements[$begin + 1]);
        self::assertCount(2, array_filter(array_slice($statements, $begin + 1, $commit - $begin - 1), static fn (string $sql): bool => str_starts_with($sql, 'select')));
        self::assertGreaterThan($commit, min($writes));
    }

    /**
     * The journal's artifact is the export's manifest.
     *
     * @return void
     */
    public function testTheManifestIsTheJournalsArtifact(): void
    {
        $this->allowEverything();

        $ids    = $this->seedEntries(2);
        $result = $this->trail()->export($this->target());

        $artifact = $this->artifactOf($result->entryId);

        self::assertNotNull($artifact);
        self::assertSame([ArtifactKind::EXPORT->value, 2], [$artifact['kind'], (int) $artifact['member_count']]);

        $plaintext = app(StringEncrypter::class)->decryptString((string) $artifact['members']);
        $read      = ExportManifest::read($plaintext);

        self::assertNotNull($read);
        self::assertSame($this->bundle()['manifest'], $plaintext);
        self::assertSame(2, $read['fields']['lines']);
        self::assertSame(hash_file('sha256', $this->target()), $read['fields']['file_sha256']);
        self::assertSame(hash('sha256', $ids[0] . "\n" . $ids[1] . "\n"), $read['fields']['membership_sha256']);
        self::assertSame('ndjson', $read['fields']['format']);
        self::assertSame(['id' => '7', 'type' => 'App\Models\User'], $read['fields']['viewer']);
        self::assertSame(self::termsOf(null, AccessScope::all())->scopeFingerprint, $read['fields']['scope_fingerprint']);
        self::assertSame(ExportSnapshot::CONSISTENCY[$this->driver()], $read['fields']['snapshot']['consistency']);
    }

    /**
     * The bundle holds the envelope the store acknowledged.
     *
     * @return void
     */
    public function testTheBundleHoldsTheJournalledEnvelope(): void
    {
        $this->allowEverything();
        $this->seedEntries(1);

        $result = $this->trail()->export($this->target());
        $stored = $this->storedRow($result->entryId);
        $bundle = $this->bundle();

        self::assertSame(CanonicalEncoder::encode($stored), CanonicalEncoder::encode($bundle['entry']));
        self::assertSame(self::TRAIL_EXPORTED, $bundle['entry']['event']);
        $signed = StoredEntry::fromRow($this->rawRow($result->entryId), new RowCodec)->descriptor() ?? [];

        ksort($signed);

        self::assertSame($signed, $bundle['descriptor']);
    }

    /**
     * An export of nothing publishes an empty file that verifies.
     *
     * @return void
     */
    public function testAZeroRowExportPublishesAnEmptyFileAndVerifies(): void
    {
        $this->allowEverything();

        $result = $this->trail()->inCategory('finance')->export($this->target());

        self::assertSame('', file_get_contents($this->target()));
        self::assertSame(0, $result->lines);
        self::assertSame(hash('sha256', ''), $result->fileSha256);
        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());
    }

    /**
     * A denied viewer gets an empty export, journalled as `denied`.
     *
     * @return void
     */
    public function testADeniedExportPublishesAnEmptyExportAndJournalsTheDenial(): void
    {
        $this->seedEntries(2);
        $this->captureQueries();

        $result = $this->trail()->export($this->target());

        self::assertSame([], $this->entryReads());
        self::assertSame('', file_get_contents($this->target()));
        self::assertFileExists($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame(0, $result->lines);

        $record = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame(['denied', 'no_scope', 0], [$record['outcome'], $record['reason'], self::propertiesOf($record)['returned']]);
        $artifact = $this->artifactOf($result->entryId);

        self::assertNotNull($artifact);
        self::assertSame([ArtifactKind::EXPORT->value, 0], [$artifact['kind'], (int) $artifact['member_count']]);
    }

    /**
     * A scope the filters cannot meet reads nothing and succeeds.
     *
     * @return void
     */
    public function testADisjointExportReadsNothingAndSucceeds(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));
        $this->seedEntries(2);
        $this->captureQueries();

        $result = $this->trail()->forTenant(Reference::of('organisation', 'org_02'))->export($this->target());

        self::assertSame([], $this->entryReads());
        self::assertSame(0, $result->lines);
        self::assertSame(['success', null], [$this->readRecords(self::TRAIL_EXPORTED)[0]['outcome'], $this->readRecords(self::TRAIL_EXPORTED)[0]['reason']]);
    }

    /**
     * A one-tenant scope exports only that tenant, journalled in it.
     *
     * @return void
     */
    public function testAnExportOfOneTenantHoldsOnlyThatTenant(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));

        $kept = $this->seedEntry();

        $this->seedEntry(['tenant_id' => 'org_02']);

        $result = $this->trail()->export($this->target());

        self::assertSame([$kept], $this->exportedIds());
        self::assertSame(['organisation', 'org_01'], [$this->storedRow($result->entryId)['tenant_type'], $this->storedRow($result->entryId)['tenant_id']]);
    }

    /**
     * Rows of `[what is already there]`: the target, and the bundle alone.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideExistingPaths(): iterable
    {
        yield from [
            'the target' => [''],
            'its bundle' => [ExportFile::MANIFEST_SUFFIX],
        ];
    }

    /**
     * An existing target or bundle is refused without `force`, untouched.
     *
     * @param  string  $suffix
     * @return void
     */
    #[DataProvider('provideExistingPaths')]
    public function testAnExistingTargetIsRefusedWithoutForce(string $suffix): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        file_put_contents($this->target() . $suffix, 'kept');

        $this->captureQueries();

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame('The export target already exists; pass force to replace it.', $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->readRecords());
        self::assertSame('kept', file_get_contents($this->target() . $suffix));
        self::assertSame([], $this->temporaries());
    }

    /**
     * With `force` an existing target and bundle are replaced by the export's.
     *
     * @return void
     */
    public function testForceReplacesTheTarget(): void
    {
        $this->allowEverything();

        $id = $this->seedEntry();

        file_put_contents($this->target(), 'old');
        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, 'old');

        $this->trail()->export($this->target(), ExportFormat::NDJSON, true);

        self::assertSame([$id], $this->exportedIds());
        self::assertNotNull(ExportBundle::decode((string) file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX)));
    }

    /**
     * A target in a missing directory is refused before anything.
     *
     * @return void
     */
    public function testAMissingDirectoryIsRefusedBeforeAnything(): void
    {
        $this->allowEverything();
        $this->captureQueries();

        try {
            $this->trail()->export($this->directory . '/missing/trail.ndjson');

            self::fail('Expected the export to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame('The export target\'s directory does not exist or is not writable.', $refusal->getMessage());
        }

        self::assertSame([], $this->capturedQueries());
    }

    /**
     * An engine an export cannot read is refused before anything.
     *
     * @return void
     */
    public function testAnUnsupportedEngineIsRefusedBeforeAnything(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $config = app(ConfigRepository::class);

        $config->set('database.connections.elsewhere', ['driver' => 'sqlsrv', 'host' => '127.0.0.1', 'database' => 'audit', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'elsewhere');

        $this->captureQueries();

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (\LogicException $refusal) {
            self::assertSame('An export reads MySQL, PostgreSQL or SQLite, and the [elsewhere] connection is sqlsrv.', $refusal->getMessage());
        } finally {
            $config->set('audit-log.storage.connection', null);
        }

        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->temporaries());
    }

    /**
     * An export during a read of the trail is refused by the gate first.
     *
     * @return void
     */
    public function testTheGateRefusesBeforeThePolicy(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $refusal = app(ReadGuard::class)->during(function (): ?AuditReadRefusedException {
            try {
                $this->trail()->export($this->target());
            } catch (AuditReadRefusedException $refusal) {
                return $refusal;
            }

            return null;
        });

        self::assertInstanceOf(AuditReadRefusedException::class, $refusal);
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->temporaries());
        self::assertFileDoesNotExist($this->target());
    }

    /**
     * A failed journal refuses the export and leaves no file behind.
     *
     * @return void
     */
    public function testNoFileIsPublishedWhenTheJournalFails(): void
    {
        $this->allowEverything();
        $this->pointAtProbeTable();

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $refusal->getMessage());
        }

        self::assertFileDoesNotExist($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temporaries());
    }

    /**
     * A throwing policy is recorded as `policy_failed` and rethrown unchanged.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAThrowingPolicyIsRecordedAsAFailureAndRethrown(): void
    {
        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): never => throw $thrown);

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the policy\'s exception.');
        } catch (\RuntimeException $caught) {
            self::assertSame($thrown, $caught);
        }

        $record = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame(['failure', 'policy_failed'], [$record['outcome'], $record['reason']]);
        self::assertNull(self::propertiesOf($record)['scope_fingerprint']);
        self::assertSame([], $this->temporaries());
    }

    /**
     * A line that cannot be written is recorded as `format_failed` and refused.
     *
     * @return void
     */
    public function testAFormattingFailureIsRecordedAsAFailure(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(2);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $ids[1])->update(['properties' => '{"amount":1.5}']);

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }

        $record = $this->readRecords(self::TRAIL_EXPORTED)[0];

        $properties = self::propertiesOf($record);

        self::assertSame(['failure', 'format_failed', 0, null], [$record['outcome'], $record['reason'], $properties['returned'], $properties['file_sha256']]);
        self::assertSame([], $this->disclosureOf(self::idOf($record))['members']);
        self::assertSame([], $this->temporaries());
        self::assertFileDoesNotExist($this->target());
    }

    /**
     * A throwing formatter is recorded as `format_failed`.
     *
     * @return void
     */
    public function testAThrowingFormatterIsRecordedAsAFormattingFailure(): void
    {
        $this->allowEverything();
        $this->seedEntries(1);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for('invoice.approved')->ocsf(ReservedKeyMapper::class));

        app()->instance(EventCatalogue::class, $catalogue);

        try {
            $this->trail()->export($this->target(), ExportFormat::OCSF);

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
        }

        self::assertSame('format_failed', $this->readRecords(self::TRAIL_EXPORTED)[0]['reason']);
    }

    /**
     * A failing query is recorded and refused, naming only the failing class.
     *
     * @return void
     */
    public function testAQueryFailureIsRecordedAsAFailure(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->failEntryReads();

        try {
            $this->trail()->correlatedWith('app:kept-out-of-every-refusal')->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(QueryException::class)->getMessage(), $refusal->getMessage());
            self::assertStringNotContainsString('kept-out-of-every-refusal', $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }

        $this->failEntryReads = false;

        $record = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame(['failure', 'query_failed'], [$record['outcome'], $record['reason']]);
        self::assertSame([], $this->temporaries());
        self::assertFileDoesNotExist($this->target());
    }

    /**
     * A failed publication is recorded and refused, never replacing the target.
     *
     * @return void
     */
    public function testAPublicationFailureIsRecordedAndRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(1);

        $this->onJournal(function (): void {
            file_put_contents($this->target(), 'appeared');
        });

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::publishFailed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
        }

        $journal = $this->readRecords(self::TRAIL_EXPORTED)[0];
        $failure = $this->readRecords('audit_log.export_publish_failed')[0];

        self::assertSame(['failure', 'publish_failed'], [$failure['outcome'], $failure['reason']]);
        self::assertSameProperties(['export_entry' => $journal['id'], 'outcome' => 'failure'], self::propertiesOf($failure));
        self::assertSame('appeared', file_get_contents($this->target()));
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temporaries());
    }

    /**
     * A failed publication whose record fails is still refused, and reported.
     *
     * @return void
     */
    public function testAPublicationFailureWhoseRecordFailsIsStillRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(1);
        $this->pointAtProbeTable();

        $config  = app(ConfigRepository::class);
        $entries = EntrySettings::DEFAULT_TABLE;

        $config->set('audit-log.entries.table', $entries);

        $this->onJournal(function () use ($config): void {
            file_put_contents($this->target(), 'appeared');

            $config->set('audit-log.entries.table', self::PROBE_TABLE);
        });

        try {
            $this->trail()->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::publishFailed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
        }

        $reports = array_map(static fn (\Throwable $report): string => $report->getMessage(), $this->reporter?->reports() ?? []);

        self::assertNotSame([], $reports);
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A bulk entry's members are never read or exported.
     *
     * @return void
     */
    public function testABulkEntrysMembersAreNotExported(): void
    {
        $this->allowEverything();

        $id = $this->seedBundle(3);

        $this->captureQueries();

        $this->trail()->export($this->target());

        $artifacts = array_filter($this->capturedQueries(), static fn (QueryExecuted $query): bool => str_contains($query->sql, EntrySettings::artifactsTable()));

        foreach ($artifacts as $query) {
            self::assertStringStartsWith('insert', $query->sql);
        }

        $line = json_decode($this->lines()[0], true, 513, JSON_THROW_ON_ERROR);

        self::assertSame([$id], $this->exportedIds());
        self::assertIsArray($line);

        $manifest = $line['properties']['_audit']['manifest'] ?? null;

        self::assertIsArray($manifest);
        self::assertSame(['artifact_id', 'count', 'digest', 'kind'], array_keys($manifest));
        self::assertStringNotContainsString(RecordFactory::MEMBER_TYPE, $this->lines()[0]);
    }

    /**
     * Rows of `[format, the formatter's class]`: the projections.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat, 1: class-string<\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter>}>
     */
    public static function provideProjections(): iterable
    {
        yield from [
            'OCSF' => [ExportFormat::OCSF, OcsfFormatter::class],
            'CEF'  => [ExportFormat::CEF, CefFormatter::class],
        ];
    }

    /**
     * OCSF and CEF lines are the formatters' projections, in recorded order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter>  $formatter
     * @return void
     */
    #[DataProvider('provideProjections')]
    public function testOcsfAndCefLinesAreTheFormattersProjections(ExportFormat $format, string $formatter): void
    {
        $this->allowEverything();

        $ids    = $this->seedEntries(2);
        $result = $this->trail()->export($this->target(), $format);

        $expected = array_map(fn (string $id): string => app($formatter)->format(StoredEntry::fromRow($this->rawRow($id), new RowCodec)->finalised()), $ids);

        self::assertSame($expected, $this->lines());
        self::assertSame($format, $result->format);
    }

    /**
     * In outbox mode the journal is a committed outbox row, named accepted.
     *
     * @return void
     */
    public function testInOutboxModeTheJournalIsAccepted(): void
    {
        $this->allowEverything();
        $this->seedEntries(1);

        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $result = $this->trail()->export($this->target());

        self::assertSame(Acknowledgement::ACCEPTED, $result->acknowledgement);
        self::assertNotNull($this->outboxRow($result->entryId));
        self::assertSame([], $this->readRecords(self::TRAIL_EXPORTED));
        self::assertSame($result->entryId, $this->bundle()['entry']['id']);
    }

    /**
     * The result names the journal entry, files, format, lines and digest.
     *
     * @return void
     */
    public function testTheResultStatesItsAcknowledgement(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $result = $this->trail()->export($this->target());

        self::assertSame(Acknowledgement::STORED, $result->acknowledgement);
        self::assertSame($this->readRecords(self::TRAIL_EXPORTED)[0]['id'], $result->entryId);
        self::assertSame($this->target(), $result->path);
        self::assertSame($this->target() . ExportFile::MANIFEST_SUFFIX, $result->manifestPath);
        self::assertSame(ExportFormat::NDJSON, $result->format);
        self::assertSame(3, $result->lines);
        self::assertSame(hash_file('sha256', $this->target()), $result->fileSha256);
    }

    /**
     * The journal keeps the export's evidence.
     *
     * @return void
     */
    public function testTheJournalKeepsTheExportsEvidence(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $result = $this->trail()->inCategory('finance')->export($this->target(), ExportFormat::CEF);

        $properties = self::propertiesOf($this->storedRow($result->entryId));

        unset($properties['_audit']);

        self::assertSameProperties([
            'purpose'           => 'export',
            'query_fingerprint' => self::termsOf(TrailFilters::none()->withCategories(['finance']), null)->queryFingerprint,
            'scope_fingerprint' => self::termsOf(null, AccessScope::all())->scopeFingerprint,
            'fingerprint_key'   => app(KeyRing::class)->signingKey()->id,
            'policy'            => ClosurePolicy::class,
            'format'            => 'cef',
            'returned'          => 2,
            'file_sha256'       => $result->fileSha256,
            'outcome'           => 'success',
        ], $properties);
    }

    /**
     * A revealing scope exports stored envelopes and asks no field reader.
     *
     * @return void
     */
    public function testARevealingScopeExportsTheStoredEnvelopesAndAsksNoReader(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => self::REVEALED_CARD]);

        app()->instance(FieldReader::class, $reader);

        $this->revealEverything();

        $id     = $this->seedEntry(['properties' => ['card' => ['v' => 1, 'k' => 'key_42', 'c' => 'Y2FyZA']]]);
        $result = $this->trail()->export($this->target());

        $properties = self::propertiesOf($this->storedRow($result->entryId));
        $revealing  = self::termsOf(null, AccessScope::all()->revealingEncryptedFields())->scopeFingerprint;

        self::assertSame(0, $reader->calls());
        self::assertSame([CanonicalEncoder::encode($this->storedRow($id))], $this->lines());
        self::assertStringContainsString('Y2FyZA', $this->lines()[0]);
        self::assertStringNotContainsString(self::REVEALED_CARD, $this->lines()[0]);
        self::assertSame($revealing, $properties['scope_fingerprint']);
        self::assertNotSame(self::termsOf(null, AccessScope::all())->scopeFingerprint, $revealing);
        self::assertArrayNotHasKey('reveal', $properties);
        self::assertArrayNotHasKey('fields', $properties);
    }

    /**
     * With a chunk of 100, 250 entries are read in four statements.
     *
     * @return void
     */
    public function testExtractionReadsInChunks(): void
    {
        app(ConfigRepository::class)->set('audit-log.export.chunk', 100);

        $this->allowEverything();

        $ids = $this->seedEntries(250);

        $this->captureQueries();

        $this->trail()->export($this->target());

        $statements = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());
        $commit     = array_search('COMMIT', $statements, true);

        self::assertIsInt($commit);
        $reads = array_filter(array_slice($statements, 0, $commit), static fn (string $sql): bool => str_starts_with($sql, 'select') && str_contains($sql, EntrySettings::table()));

        self::assertCount(4, $reads);
        self::assertSame($ids, $this->exportedIds());
    }

    /**
     * The trail the tests export, read for the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer());
    }

    /**
     * The engine of the storage connection.
     *
     * @return 'mysql'|'pgsql'|'sqlite'
     */
    private function driver(): string
    {
        $driver = DB::connection(StorageConnection::name())->getDriverName();

        self::assertContains($driver, ['mysql', 'pgsql', 'sqlite']);

        return $driver;
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
     * The exported file's lines, without their line feeds.
     *
     * @return list<string>
     */
    private function lines(): array
    {
        $contents = (string) file_get_contents($this->target());

        return $contents === '' ? [] : explode("\n", substr($contents, 0, -1));
    }

    /**
     * The ids of the NDJSON file's lines, in order.
     *
     * @return list<string>
     */
    private function exportedIds(): array
    {
        return array_map(static function (string $line): string {
            $decoded = json_decode($line, true, 513, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);
            self::assertIsString($decoded['id'] ?? null);

            return $decoded['id'];
        }, $this->lines());
    }

    /**
     * The published bundle, decoded; it must be one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}
     */
    private function bundle(): array
    {
        $bundle = ExportBundle::decode((string) file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));

        self::assertNotNull($bundle);

        return $bundle;
    }

    /**
     * The temporary files in the directory.
     *
     * @return list<string>
     */
    private function temporaries(): array
    {
        return glob($this->directory . '/.*.tmp') ?: [];
    }

    /**
     * The stored row of the entry, as the engine returned it; it must exist.
     *
     * @param  string  $id
     * @return array<string, scalar|null>
     */
    private function rawRow(string $id): array
    {
        $row = DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->first();

        self::assertNotNull($row);

        /** @var array<string, scalar|null> */
        return (array) $row;
    }

    /**
     * Run the callback once, right after an export's journal is inserted.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function onJournal(\Closure $callback): void
    {
        $ran = false;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$ran, $callback): void {
            if ($ran || !str_starts_with($query->sql, 'insert') || !str_contains($query->sql, EntrySettings::table()) || !in_array(self::TRAIL_EXPORTED, $query->bindings, true)) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * Make every entries table read, on any connection, fail until cleared.
     *
     * @return void
     */
    private function failEntryReads(): void
    {
        $this->failEntryReads = true;

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            if (!$this->failEntryReads || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            throw new QueryException($query->connectionName, $query->sql, $query->bindings, new \PDOException('SQLSTATE[HY000]: General error: the read failed'));
        });
    }
}
