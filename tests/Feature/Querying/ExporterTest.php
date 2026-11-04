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
 * Feature tests for the exporter: the export authorised for its purpose, each
 * NDJSON line the stored envelope untouched and the lines in ascending recorded
 * order, read in chunks inside the snapshot, the file prepared, then journalled
 * once the snapshot has ended, then published with a bundle built from the
 * journalled envelope, an empty export for a denied viewer, an existing target
 * refused without `force` and replaced with it, nothing published when the
 * journal fails, a failing statement, line or publication recorded as a
 * failure, bulk members never read, OCSF and CEF lines the formatters'
 * projections, and the acknowledgement the result names.
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
     * Remove the directory and everything in it, and put the entries table
     * back.
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
     * The policy is asked for the viewer, as given, and the purpose `export`,
     * once.
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
     * Each NDJSON line is the canonical encoding of the stored envelope,
     * untouched, so its HMAC verifies against the line itself.
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
     * The lines are in ascending recorded order, and entries recorded at the
     * same instant follow by id, whatever order they were written in.
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
     * Entries recorded in another order than they occurred, as late deliveries
     * from queues, the outbox and imports are, are exported in recorded order
     * across several chunks, each chunk carrying the keyset on to the next by
     * recorded time and id, and the manifest's first and last positions are the
     * recorded positions of the first and last lines. The recording order here
     * follows neither the occurrence order nor its reverse, so a chunk ordered
     * or carried on by occurrence would export the wrong rows.
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
     * A malformed `export.chunk` refuses the export before anything else, with
     * the refusal naming the key: no statement runs, the policy is not asked,
     * nothing is recorded and no file is made.
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
     * A manifest that cannot be built of what the snapshot and the file hold,
     * here a session that names no database, as a MySQL connection with no
     * default database does, removes the temporary file, is recorded as a
     * failure with `format_failed`, and refuses the export naming the class
     * that failed; nothing is published.
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
     * When the journal is written, the temporary file exists beside the target
     * and the target does not; once the export returns, the target and its
     * bundle are published and no temporary file is left.
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
     * The snapshot is begun, the bound is its first statement, the chunks
     * follow, and it is committed before the journal is written, so no write
     * runs inside it.
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
     * The journal's artifact is the export's manifest: its plaintext is the
     * bundle's manifest exactly, of kind `export`, counting the file's lines,
     * with the file's digest and membership digest.
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
     * The bundle holds the very envelope the store acknowledged, the stored
     * journal's columns, and the descriptor the journal signed.
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
     * An export that finds nothing publishes an empty file, journalled with no
     * line and the digests of nothing, and it verifies.
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
     * A viewer the policy denies is given an empty export, published with its
     * bundle and an `export` artifact of no member, journalled as `denied` with
     * `no_scope`, and no entry is read.
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
     * A scope the filters cannot meet reads no entry, and its empty export is a
     * success.
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
     * A scope of one tenant exports only that tenant's entries, and the journal
     * is recorded in that tenant.
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
     * An export to a target, or a bundle, that exists is refused without
     * `force` before the policy is asked or anything is queried, and is not
     * recorded; what is there is left as it was.
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
     * A target whose directory does not exist is refused before anything, and
     * is not recorded.
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
     * An engine an export cannot read is refused before the policy is asked or
     * anything is queried, and is not recorded.
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
     * An export entered while a read of the trail is running is refused by the
     * gate before the policy is asked, and nothing is written.
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
     * A journal that cannot be written refuses the export as unrecorded, and no
     * file, bundle or temporary file is left.
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
     * A policy that throws is recorded as a failure with `policy_failed` and no
     * scope, what it threw propagates unchanged, and nothing is written.
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
     * A row whose line cannot be written, here because its properties hold a
     * number with a fraction, which has no canonical form, is recorded as a
     * failure with `format_failed`, which discloses no entry, the export is
     * refused naming the class that failed, and the temporary file is removed.
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
        self::assertSame([], $this->disclosureOf($record['id'])['members']);
        self::assertSame([], $this->temporaries());
        self::assertFileDoesNotExist($this->target());
    }

    /**
     * A formatter that throws, here because the code's OCSF mapper returns an
     * attribute the formatter sets, is recorded as a failure with
     * `format_failed`.
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
     * A statement that fails is recorded as a failure with `query_failed`, the
     * export is refused naming the class that failed and nothing it held, and
     * the temporary file is removed.
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
     * A publication that fails, because the target appeared once the export was
     * journalled, is recorded as `audit_log.export_publish_failed` naming the
     * export entry, the export is refused, and what appeared is never replaced.
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
     * A publication that fails and whose own record cannot be written is still
     * refused as a failed publication, and the failure to record it is
     * reported.
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
     * An export of bulk entries reads nothing of the artifacts table before its
     * journal: the members they reference are never exported, and each line
     * carries the entry's descriptor alone.
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
        self::assertSame(['artifact_id', 'count', 'digest', 'kind'], array_keys($line['properties']['_audit']['manifest'] ?? []));
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
     * Each OCSF and CEF line is the formatter's projection of the stored entry,
     * in ascending recorded order, and the result names the format.
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
     * In outbox mode the journal is a committed outbox row, and the result
     * names it accepted: the store does not hold it yet.
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
     * The result names the journal entry, where the file and its bundle were
     * published, the format, the lines, the file's digest, and, in sync mode,
     * that the journal is stored.
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
     * The journal keeps the export's evidence: its purpose, fingerprints,
     * policy, format, the lines it returned and the file's digest.
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
     * An export under a scope that reveals the encrypted fields decrypts
     * nothing: no field reader is asked, each envelope is exported as stored,
     * and the journal keeps its evidence as it is, its scope fingerprint the
     * granted scope's, which differs from the same scope's without the grant.
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
     * With a chunk of 100, 250 entries are read in four statements inside the
     * snapshot: the bound, then chunks of 100, 100 and 50, and every entry is
     * exported once.
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
     * Run the callback once, right after an export's journal is inserted into
     * the entries table.
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
     * Make every read of the entries table, on any connection, the export's own
     * session included, fail with the engine's exception, which holds the
     * statement and its bindings, until the flag is cleared.
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
