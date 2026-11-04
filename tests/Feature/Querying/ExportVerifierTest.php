<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\ExportBundle;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;
use SineMacula\Laravel\AuditLog\Querying\ExportVerification;
use SineMacula\Laravel\AuditLog\Querying\ExportVerifier;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\TestCase;

/**
 * Feature tests for the verification of an export: an untouched export of each
 * format verifies, the viewer is authorised for `verify` and the verification
 * recorded with what it found, a denied viewer sees the entry missing exactly
 * as one outside the scope does, the entry is looked up under the scope, every
 * tampering along the chain has its own finding, OCSF and CEF lines are checked
 * by their ids, a policy or a statement that fails is recorded as a failure, no
 * result is returned unrecorded, and the file is read a line at a time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportVerifier::class)]
final class ExportVerifierTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail, SeedsArtifacts;

    /** @var string The code of a verification's record. */
    private const string EXPORT_VERIFIED = 'audit_log.export_verified';

    /** @var string A key id no ring holds. */
    private const string UNKNOWN_KEY = 'unknown-key';

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /** @var bool Whether a read of the entries table on the storage connection fails. */
    private bool $failEntryReads = false;

    /**
     * Bind the read path, let every viewer see everything and make the
     * directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-verify-', true);

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
            if (!is_file($path)) {
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
     * Rows of `[format]`: each format an export is written in.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat}>
     */
    public static function provideFormats(): iterable
    {
        yield from [
            'NDJSON' => [ExportFormat::NDJSON],
            'OCSF'   => [ExportFormat::OCSF],
            'CEF'    => [ExportFormat::CEF],
        ];
    }

    /**
     * An untouched export verifies, in every format, naming its entry and its
     * lines.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return void
     */
    #[DataProvider('provideFormats')]
    public function testAnUntouchedExportVerifies(ExportFormat $format): void
    {
        $result       = $this->export($format);
        $verification = $this->verify();

        self::assertTrue($verification->isVerified());
        self::assertSame([], $verification->findings);
        self::assertSame($result->entryId, $verification->entryId);
        self::assertSame(3, $verification->lines);
    }

    /**
     * The export entry and its artifact are looked up on the storage
     * connection's writer, never its reader, so a replica that has not caught
     * up, here one that holds no table at all, is never taken for an entry that
     * was not stored: the export still verifies.
     *
     * @return void
     */
    public function testTheLookupsReadTheWriterNotAReplica(): void
    {
        $result     = $this->export();
        $connection = DB::connection(StorageConnection::name());

        $this->captureQueries();

        $connection->setReadPdo(new \PDO('sqlite::memory:'));

        try {
            $verification = $this->verify();
        } finally {
            $connection->setReadPdo(null);
        }

        self::assertTrue($verification->isVerified());
        self::assertSame($result->entryId, $verification->entryId);
        self::assertCount(2, $this->entryOrArtifactReads());
    }

    /**
     * The policy is asked for the viewer, as given, and the purpose `verify`.
     *
     * @return void
     */
    public function testTheViewerIsAuthorisedForVerify(): void
    {
        $this->export();

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $viewer = $this->viewer();

        app(AuditTrail::class)->visibleTo($viewer)->verifyExport($this->target());

        self::assertCount(1, $policy->asked());
        self::assertSame($viewer, $policy->asked()[0][0]);
        self::assertSame(ReadPurpose::VERIFY, $policy->asked()[0][1]);
    }

    /**
     * The verification is recorded as `audit_log.export_verified`, a success
     * naming the export entry, its verdict and no finding, and disclosing the
     * export entry's id and HMAC.
     *
     * @return void
     */
    public function testAVerificationIsRecorded(): void
    {
        $result = $this->export();

        $this->verify();

        $record = $this->readRecords(self::EXPORT_VERIFIED)[0];
        $stored = $this->storedRow($result->entryId);

        self::assertSame(['success', null], [$record['outcome'], $record['reason']]);
        self::assertSameProperties([
            'purpose'           => 'verify',
            'scope_fingerprint' => self::termsOf(null, AccessScope::all())->scopeFingerprint,
            'fingerprint_key'   => app(KeyRing::class)->signingKey()->id,
            'policy'            => get_debug_type(app(AuditAccessPolicy::class)),
            'export_entry'      => $result->entryId,
            'verdict'           => 'verified',
            'findings'          => [],
            'outcome'           => 'success',
        ], array_diff_key(self::propertiesOf($record), ['_audit' => true]));
        self::assertSame([[$result->entryId, $stored['hmac']]], $this->disclosureOf($record['id'])['members']);
    }

    /**
     * A verification that finds anything is still a success, naming the
     * findings in chain order and the verdict `not_verified`.
     *
     * @return void
     */
    public function testAFailedVerificationIsRecordedWithItsFindings(): void
    {
        $this->export();
        $this->editLine(1, static fn (array $line): array => ['user_agent' => 'edited'] + $line);

        $this->verify();

        $properties = self::propertiesOf($this->readRecords(self::EXPORT_VERIFIED)[0]);

        self::assertSame('not_verified', $properties['verdict']);
        self::assertSame(['file_mismatch', 'line_tampered'], $properties['findings']);
        self::assertSame('success', $properties['outcome']);
    }

    /**
     * A viewer the policy denies runs no statement on the entries table and
     * sees the entry missing, exactly as a viewer whose scope leaves the entry
     * out does; the denial is recorded as `denied` with `no_scope`.
     *
     * @return void
     */
    public function testADeniedViewerSeesTheEntryMissing(): void
    {
        $this->export();

        app()->instance(AuditAccessPolicy::class, new DenyAllPolicy);

        $this->captureQueries();

        $denied = $this->verify();

        self::assertSame([], $this->entryReads());

        $this->allowTenants(Reference::of('organisation', 'org_99'));

        $outside = $this->verify();

        self::assertSame([ExportFinding::ENTRY_MISSING], $denied->findings);
        self::assertEquals($outside, $denied);

        $records = $this->readRecords(self::EXPORT_VERIFIED);

        self::assertSame(['denied', 'no_scope'], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame(['success', null], [$records[1]['outcome'], $records[1]['reason']]);
        self::assertNull(self::propertiesOf($records[0])['export_entry']);
    }

    /**
     * The export entry is looked up under the viewer's scope: a scope of a
     * tenant the tenantless journal is not in finds it missing, in one
     * statement, and reads no artifact.
     *
     * @return void
     */
    public function testTheEntryIsLookedUpUnderTheScope(): void
    {
        $this->export();
        $this->allowTenants(Reference::of('organisation', 'org_01'));
        $this->captureQueries();

        $verification = $this->verify();

        self::assertSame([ExportFinding::ENTRY_MISSING], $verification->findings);
        self::assertCount(1, $this->entryReads());
        self::assertMatchesRegularExpression('/.tenant_type. = \?/', $this->entryReads()[0]);
        self::assertSame([], $this->artifactReads());
        self::assertSame(3, $verification->lines);
    }

    /**
     * Rows of `[how the test tampers with the export, the findings]`: one per
     * finding, each built by the test.
     *
     * @return iterable<string, array{0: \Closure(self): void, 1: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>}>
     */
    public static function provideTamperings(): iterable
    {
        yield from [
            'a malformed bundle' => [
                static function (self $test): void {
                    file_put_contents($test->target() . ExportFile::MANIFEST_SUFFIX, "{}\n");
                },
                [ExportFinding::BUNDLE_MALFORMED],
            ],
            'a deleted entry' => [
                static function (self $test): void {
                    $test->entriesTable()->where('id', $test->entryId())->delete();
                },
                [ExportFinding::ENTRY_MISSING],
            ],
            'an entry signed by an unknown key' => [
                static fn (self $test) => $test->editEntry(['key_id' => self::UNKNOWN_KEY]),
                [ExportFinding::ENTRY_UNVERIFIABLE],
            ],
            'an edited entry' => [
                static fn (self $test) => $test->editEntry(['user_agent' => 'edited']),
                [ExportFinding::ENTRY_TAMPERED],
            ],
            'another export\'s entry in the bundle' => [
                static fn (self $test) => $test->editBundle(static fn (array $bundle): array => ['entry' => ['id' => $test->entryId()] + $test->otherExport()['entry']] + $bundle),
                [ExportFinding::ENTRY_SWAPPED],
            ],
            'an edited descriptor' => [
                static fn (self $test) => $test->editBundle(static fn (array $bundle): array => ['descriptor' => ['count' => 4] + $bundle['descriptor']] + $bundle),
                [ExportFinding::DESCRIPTOR_MISMATCH],
            ],
            'a deleted artifact' => [
                static function (self $test): void {
                    $test->artifactsTable()->where('entry_id', $test->entryId())->delete();
                },
                [ExportFinding::ARTIFACT_MISSING],
            ],
            'swapped artifacts' => [
                static fn (self $test) => $test->swapArtifacts($test->entryId(), $test->otherExport()['entry']['id']),
                [ExportFinding::ARTIFACT_SWAPPED],
            ],
            'a kind changed in the column' => [
                static fn (self $test) => $test->tamperWithArtifact($test->entryId(), ['kind' => 'disclosure']),
                [ExportFinding::ARTIFACT_WRONG_KIND],
            ],
            'a count changed in the column' => [
                static fn (self $test) => $test->tamperWithArtifact($test->entryId(), ['member_count' => 4]),
                [ExportFinding::ARTIFACT_MISMATCH],
            ],
            'members re-encrypted under another key' => [
                static function (self $test): void {
                    $other = new Encrypter(str_repeat('k', 32), 'aes-256-cbc');

                    $test->tamperWithArtifact($test->entryId(), ['members' => $other->encryptString($test->manifest())]);
                },
                [ExportFinding::ARTIFACT_UNDECRYPTABLE],
            ],
            'malformed members' => [
                static fn (self $test) => $test->tamperWithArtifact($test->entryId(), ['members' => app(StringEncrypter::class)->encryptString('{"export_manifest_version":1}')]),
                [ExportFinding::ARTIFACT_MALFORMED],
            ],
            'members of another manifest' => [
                static fn (self $test) => $test->tamperWithArtifact($test->entryId(), ['members' => app(StringEncrypter::class)->encryptString($test->otherExport()['manifest'])]),
                [ExportFinding::ARTIFACT_TAMPERED],
            ],
            'a bundle manifest edited' => [
                static fn (self $test) => $test->editBundle(static fn (array $bundle): array => ['manifest' => $test->otherExport()['manifest']] + $bundle),
                [ExportFinding::MANIFEST_MISMATCH],
            ],
            'a file byte changed' => [
                static fn (self $test) => $test->writeLines(array_map(static fn (string $line): string => '{ ' . substr($line, 1), $test->lines())),
                [ExportFinding::FILE_MISMATCH],
            ],
            'a line removed' => [
                static fn (self $test) => $test->writeLines(array_slice($test->lines(), 1)),
                [ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH],
            ],
            'a line that is not JSON' => [
                static fn (self $test) => $test->writeLines([$test->lines()[0], 'not json', $test->lines()[2]]),
                [ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH, ExportFinding::LINE_MALFORMED],
            ],
            'a line signed by an unknown key' => [
                static fn (self $test) => $test->editLine(1, static fn (array $line): array => ['key_id' => self::UNKNOWN_KEY] + $line),
                [ExportFinding::FILE_MISMATCH, ExportFinding::LINE_UNVERIFIABLE],
            ],
            'a line\'s value changed' => [
                static fn (self $test) => $test->editLine(1, static fn (array $line): array => ['user_agent' => 'edited'] + $line),
                [ExportFinding::FILE_MISMATCH, ExportFinding::LINE_TAMPERED],
            ],
        ];
    }

    /**
     * Each tampering along the chain has its own finding, listed once and in
     * chain order, and every finding is some tampering's.
     *
     * @param  \Closure(self): void  $tamper
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>  $findings
     * @return void
     */
    #[DataProvider('provideTamperings')]
    public function testEachTamperingHasItsOwnFinding(\Closure $tamper, array $findings): void
    {
        $this->export();

        $tamper($this);

        $verification = $this->verify();

        self::assertSame($findings, $verification->findings);
        self::assertFalse($verification->isVerified());
    }

    /**
     * The tamperings cover every finding.
     *
     * @return void
     */
    public function testEveryFindingHasATampering(): void
    {
        $covered = [];

        foreach (self::provideTamperings() as [, $findings]) {
            foreach ($findings as $finding) {
                $covered[$finding->value] = $finding;
            }
        }

        $values = array_column(ExportFinding::cases(), 'value');

        self::assertSame($values, array_values(array_filter($values, static fn (string $value): bool => isset($covered[$value]))));
    }

    /**
     * Changing one line of an NDJSON export, even one byte of a value, fails
     * its verification.
     *
     * @return void
     */
    public function testChangingOneLineFailsVerification(): void
    {
        $this->export();
        $this->editLine(2, static fn (array $line): array => ['reason' => 'x'] + $line);

        $verification = $this->verify();

        self::assertFalse($verification->isVerified());
        self::assertContains(ExportFinding::LINE_TAMPERED, $verification->findings);
    }

    /**
     * The entry found being the record of a read, not an export's journal, is
     * swapped, and neither its descriptor nor its digest are the bundle's.
     *
     * @return void
     */
    public function testAReadRecordInTheBundleIsSwapped(): void
    {
        $this->export();

        app(AuditTrail::class)->visibleTo($this->viewer())->cursorPaginate();

        $read = $this->readRecords('audit_log.trail_read')[0];

        $this->editBundle(static fn (array $bundle): array => ['entry' => $read] + $bundle);

        self::assertSame([ExportFinding::ENTRY_SWAPPED, ExportFinding::DESCRIPTOR_MISMATCH, ExportFinding::MANIFEST_MISMATCH], $this->verify()->findings);
    }

    /**
     * A bundle naming an entry by something other than a lower-case UUID finds
     * it missing, with no statement on the entries table.
     *
     * @return void
     */
    public function testABundleNamingNoEntryIdFindsItMissing(): void
    {
        $this->export();
        $this->editBundle(static fn (array $bundle): array => ['entry' => ['id' => 'NOT-A-UUID'] + $bundle['entry']] + $bundle);
        $this->captureQueries();

        $verification = $this->verify();

        self::assertSame([ExportFinding::ENTRY_MISSING], $verification->findings);
        self::assertNull($verification->entryId);
        self::assertSame([], $this->entryReads());
    }

    /**
     * A file that is not there matches nothing, and no line is read.
     *
     * @return void
     */
    public function testAMissingFileIsAFileMismatch(): void
    {
        $this->export();

        unlink($this->target());

        $verification = $this->verify();

        self::assertSame([ExportFinding::FILE_MISMATCH], $verification->findings);
        self::assertSame(0, $verification->lines);
    }

    /**
     * A bundle that is not there is malformed, and nothing else is checked.
     *
     * @return void
     */
    public function testAMissingBundleIsMalformed(): void
    {
        $this->export();

        unlink($this->target() . ExportFile::MANIFEST_SUFFIX);

        $this->captureQueries();

        $verification = $this->verify();

        self::assertSame([ExportFinding::BUNDLE_MALFORMED], $verification->findings);
        self::assertSame([null, 0], [$verification->entryId, $verification->lines]);
        self::assertSame([], $this->entryReads());
    }

    /**
     * An OCSF export is checked by each line's `metadata.uid`: a changed uid
     * changes the membership, and any other change the file's digest alone.
     *
     * @return void
     */
    public function testAnOcsfExportIsCheckedByMetadataUid(): void
    {
        $this->export(ExportFormat::OCSF);

        $lines = $this->lines();

        $this->writeLines([self::withJson($lines[0], static fn (array $event): array => ['message' => 'edited'] + $event), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH], $this->verify()->findings);

        $uid = '01932b4e-a000-7000-8000-000000000999';

        $this->writeLines([self::withJson($lines[0], static fn (array $event): array => ['metadata' => ['uid' => $uid] + $event['metadata']] + $event), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH], $this->verify()->findings);

        $this->writeLines([self::withJson($lines[0], static fn (array $event): array => array_diff_key($event, ['metadata' => true])), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH, ExportFinding::LINE_MALFORMED], $this->verify()->findings);
    }

    /**
     * A CEF export is checked by each line's `externalId`: a changed id changes
     * the membership, a line without one is malformed, and any other change
     * changes the file's digest alone.
     *
     * @return void
     */
    public function testACefExportIsCheckedByExternalId(): void
    {
        $result = $this->export(ExportFormat::CEF);
        $lines  = $this->lines();
        $first  = $this->exportedId($lines[0]);

        $this->writeLines([str_replace('act=invoice.approved', 'act=invoice.voided', $lines[0]), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH], $this->verify()->findings);

        $this->writeLines([str_replace('externalId=' . $first, 'externalId=01932b4e-a000-7000-8000-000000000999', $lines[0]), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH], $this->verify()->findings);

        $this->writeLines([str_replace('externalId=' . $first, 'externalId=' . strtoupper($first), $lines[0]), $lines[1], $lines[2]]);

        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH, ExportFinding::LINE_MALFORMED], $this->verify()->findings);
        self::assertNotSame($first, $result->entryId);
    }

    /**
     * The file is read a line at a time: verifying a file of thousands of lines
     * grows the process's peak memory by far less than the file.
     *
     * @return void
     */
    public function testTheFileIsReadOneLineAtATime(): void
    {
        $this->export();

        $lines = $this->lines();
        $file  = fopen($this->target(), 'ab');

        self::assertIsResource($file);

        for ($copy = 0; $copy < 5000; $copy++) {
            fwrite($file, $lines[$copy % 3] . "\n");
        }

        fclose($file);

        $size = (int) filesize($this->target());

        $this->verify();

        memory_reset_peak_usage();

        $baseline     = memory_get_usage();
        $verification = $this->verify();
        $grown        = memory_get_peak_usage() - $baseline;

        self::assertSame(5003, $verification->lines);
        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH], $verification->findings);
        self::assertLessThan(intdiv($size, 4), $grown, sprintf('Verifying a %d-byte file grew peak memory by %d bytes.', $size, $grown));
    }

    /**
     * A policy that throws is recorded as a failure with `policy_failed`, and
     * what it threw propagates unchanged.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAThrowingPolicyIsRecordedAsAFailureAndRethrown(): void
    {
        $this->export();

        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): never => throw $thrown);

        try {
            $this->verify();

            self::fail('Expected the policy\'s exception.');
        } catch (\RuntimeException $caught) {
            self::assertSame($thrown, $caught);
        }

        $record = $this->readRecords(self::EXPORT_VERIFIED)[0];

        self::assertSame(['failure', 'policy_failed'], [$record['outcome'], $record['reason']]);
        self::assertNull(self::propertiesOf($record)['scope_fingerprint']);
    }

    /**
     * A statement that fails is recorded as a failure with `query_failed`, and
     * the verification is refused naming the class that failed and nothing it
     * held.
     *
     * @return void
     */
    public function testAQueryFailureIsRecordedAsAFailure(): void
    {
        $this->export();
        $this->failEntryReads();

        try {
            $this->verify();

            self::fail('Expected the verification to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(QueryException::class)->getMessage(), $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }

        $this->failEntryReads = false;

        $record = $this->readRecords(self::EXPORT_VERIFIED)[0];

        self::assertSame(['failure', 'query_failed'], [$record['outcome'], $record['reason']]);
        self::assertSame([], self::propertiesOf($record)['findings']);
    }

    /**
     * A verification whose record cannot be written returns nothing: it is
     * refused as unrecorded.
     *
     * @return void
     */
    public function testNoResultIsReturnedWhenItsRecordFails(): void
    {
        $this->export();
        $this->pointAtProbeTable();

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->verify();
    }

    /**
     * Export three seeded entries in the format, as the viewer, to the target.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportResult
     */
    private function export(ExportFormat $format = ExportFormat::NDJSON): ExportResult
    {
        $this->seedEntries(3);

        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->export($this->target(), $format);
    }

    /**
     * Every statement captured that read the entries or the artifacts table.
     *
     * @return list<string>
     */
    private function entryOrArtifactReads(): array
    {
        $tables  = '/[`"](' . preg_quote(EntrySettings::table(), '/') . '|' . preg_quote(EntrySettings::artifactsTable(), '/') . ')[`"]/';
        $queries = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());

        return array_values(array_filter($queries, static fn (string $sql): bool => str_starts_with($sql, 'select') && preg_match($tables, $sql) === 1));
    }

    /**
     * Verify the export at the target as the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportVerification
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function verify(): ExportVerification
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->verifyExport($this->target());
    }

    /**
     * The bundle of a second export, of the same entries in CEF, so its
     * manifest is another, to another target, made once.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}
     */
    private function otherExport(): array
    {
        $other = $this->directory . '/other.ndjson';

        if (!is_file($other)) {
            app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->export($other, ExportFormat::CEF);
        }

        return $this->bundleAt($other);
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
     * The id of the export entry the target's bundle names.
     *
     * @return string
     */
    private function entryId(): string
    {
        $id = $this->bundleAt($this->target())['entry']['id'] ?? null;

        self::assertIsString($id);

        return $id;
    }

    /**
     * The manifest the target's bundle carries.
     *
     * @return string
     */
    private function manifest(): string
    {
        return $this->bundleAt($this->target())['manifest'];
    }

    /**
     * The bundle beside the export at the path, decoded; it must be one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @return array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}
     */
    private function bundleAt(string $path): array
    {
        $bundle = ExportBundle::decode((string) file_get_contents($path . ExportFile::MANIFEST_SUFFIX));

        self::assertNotNull($bundle);

        return $bundle;
    }

    /**
     * Rewrite the target's bundle as the edit gives it, encoded as an export
     * writes one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(array<array-key, mixed>): array<array-key, mixed>  $edit
     * @return void
     */
    private function editBundle(\Closure $edit): void
    {
        $bundle = $edit($this->bundleAt($this->target()));

        self::assertIsArray($bundle['descriptor'] ?? null);
        self::assertIsArray($bundle['entry'] ?? null);
        self::assertIsString($bundle['manifest'] ?? null);

        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, ExportBundle::encode($bundle['descriptor'], $bundle['entry'], $bundle['manifest']));
    }

    /**
     * Change the columns of the export entry, in the entries table and in the
     * bundle alike, so the two still agree.
     *
     * @param  array<string, string>  $columns
     * @return void
     */
    private function editEntry(array $columns): void
    {
        $this->entriesTable()->where('id', $this->entryId())->update($columns);
        $this->editBundle(static fn (array $bundle): array => ['entry' => $columns + $bundle['entry']] + $bundle);
    }

    /**
     * The target's lines, without their line feeds.
     *
     * @return list<string>
     */
    private function lines(): array
    {
        $contents = (string) file_get_contents($this->target());

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
     * Rewrite one NDJSON line as the edit gives its envelope, in the canonical
     * encoding an export writes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $index
     * @param  \Closure(array<array-key, mixed>): array<array-key, mixed>  $edit
     * @return void
     */
    private function editLine(int $index, \Closure $edit): void
    {
        $lines = $this->lines();

        $decoded = json_decode($lines[$index], false, 513, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $decoded);

        $lines[$index] = CanonicalEncoder::encode($edit(get_object_vars($decoded)));

        $this->writeLines($lines);
    }

    /**
     * The JSON line as the edit gives it, with its maps as arrays.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $line
     * @param  \Closure(array<array-key, mixed>): array<array-key, mixed>  $edit
     * @return string
     */
    private static function withJson(string $line, \Closure $edit): string
    {
        $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        return json_encode($edit($decoded), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * The id a CEF line carries in its `externalId`.
     *
     * @param  string  $line
     * @return string
     */
    private function exportedId(string $line): string
    {
        self::assertSame(1, preg_match('/externalId=([0-9a-f-]{36})/', $line, $match));

        return $match[1];
    }

    /**
     * The statements run since capturing began that read the artifacts table,
     * as their SQL, in order.
     *
     * @return list<string>
     */
    private function artifactReads(): array
    {
        $reads = [];

        foreach ($this->capturedQueries() as $query) {
            if (!str_starts_with($query->sql, 'select') || !str_contains($query->sql, EntrySettings::artifactsTable())) {
                continue;
            }

            $reads[] = $query->sql;
        }

        return $reads;
    }

    /**
     * Make every read of the entries table on the storage connection fail with
     * the engine's exception, which holds the statement and its bindings, until
     * the flag is cleared.
     *
     * @return void
     */
    private function failEntryReads(): void
    {
        $this->failEntryReads = true;

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query, array $bindings, Connection $connection): void {
            if (!$this->failEntryReads || !str_starts_with($query, 'select') || !str_contains($query, EntrySettings::table())) {
                return;
            }

            throw new QueryException((string) $connection->getName(), $query, $bindings, new \PDOException('SQLSTATE[HY000]: General error: the read failed'));
        });
    }
}
