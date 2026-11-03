<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the check of the artifacts that verified entries' signed
 * manifests name, on whichever engine the suite runs against: bundles are
 * written as the store leaves them and changed through raw queries. They pin
 * the finding each change gives, that the members must decrypt to exactly the
 * canonical form the descriptor describes, that each finding names the earliest
 * entry, how a descriptor is read from a stored entry, and that the artifacts
 * are read in batches of entries and their members in sub-batches of bytes,
 * every statement on the writer and none for no manifest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ManifestVerifier::class)]
final class ManifestVerifierTest extends TestCase
{
    use SeedsArtifacts;

    /** @var string An artifact id no bundle has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var string An entry id no stored entry has. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-00000000f0f0';

    /** @var string A digest no bundle has. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string A key the test encrypter does not hold. */
    private const string OTHER_KEY = 'another audit-log test key!!!!!!';

    /**
     * Put the storage connection's reader back, in case a test replaced it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::connection(StorageConnection::name())->setReadPdo(null);

        parent::tearDown();
    }

    /**
     * A bundle whose artifact is as written has no finding.
     *
     * @return void
     */
    public function testAMatchingArtifactHasNoFinding(): void
    {
        $entryId = $this->seedBundle();

        self::assertSame([], $this->findingsOf([$entryId]));
    }

    /**
     * A bundle whose artifact is not stored is `manifest_missing`, at its
     * entry.
     *
     * @return void
     */
    public function testAMissingArtifactIsManifestMissing(): void
    {
        $entryId = $this->seedBundle();

        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        self::assertSame([[Finding::MANIFEST_MISSING, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * An artifact missing with its entry, both deleted by a prune that
     * committed after the segment read the entry, is no finding, and costs one
     * read of the entries; an artifact missing beside its entry is missing.
     *
     * @return void
     */
    public function testAnArtifactGoneWithItsEntryIsNoFinding(): void
    {
        [$pruned, $kept] = $this->seedBundles(2);
        $descriptors     = $this->descriptorsOf([$pruned, $kept]);

        $this->artifactsTable()->whereIn('entry_id', [$pruned, $kept])->delete();
        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $pruned)->delete();

        $statements = $this->recordStatements();

        self::assertSame([[Finding::MANIFEST_MISSING, $kept]], $this->verifier()->findings($descriptors));
        self::assertCount(2, $statements);
        self::assertStringContainsString(EntrySettings::table(), $statements[1]);
    }

    /**
     * An artifact deleted after its columns were read and before its members
     * are is missing, never unreadable; deleted with its entry, it is no
     * finding.
     *
     * @return void
     */
    public function testAnArtifactGoneBeforeItsMembersAreReadIsMissing(): void
    {
        [$alone, $withEntry] = $this->seedBundles(2);
        $descriptors         = $this->descriptorsOf([$alone, $withEntry]);
        $connection          = DB::connection(StorageConnection::name());
        $deleted             = false;

        $connection->beforeExecuting(function (string $query) use ($connection, &$deleted, $alone, $withEntry): void {
            if ($deleted || !str_contains($query, EntrySettings::artifactsTable()) || str_contains($query, 'length(')) {
                return;
            }

            $deleted = true;

            $this->artifactsTable()->whereIn('entry_id', [$alone, $withEntry])->delete();
            $connection->table(EntrySettings::table())->where('id', $withEntry)->delete();
        });

        self::assertSame([[Finding::MANIFEST_MISSING, $alone]], $this->verifier()->findings($descriptors));
        self::assertTrue($deleted);
    }

    /**
     * An artifact of the entry stored under another id than the one its
     * manifest signed is a mismatch.
     *
     * @return void
     */
    public function testAnotherArtifactIdIsManifestMismatch(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['id' => self::OTHER_ID]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * The artifact the manifest signed, moved to name another entry, is found
     * by its id and is a mismatch, never merely missing.
     *
     * @return void
     */
    public function testAnArtifactOfAnotherEntryIsManifestMismatch(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['entry_id' => self::OTHER_ID]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Two bundles of the same members whose artifacts are swapped between their
     * entries are each a mismatch, though each artifact's kind, count and
     * digest are the ones signed: only the artifact's id tells them apart.
     *
     * @return void
     */
    public function testArtifactsSwappedBetweenEntriesAreManifestMismatch(): void
    {
        [$first, $second] = $this->seedBundles(2);

        $this->tamperWithArtifact($first, ['entry_id' => self::OTHER_ID]);
        $this->tamperWithArtifact($second, ['entry_id' => $first]);
        $this->tamperWithArtifact(self::OTHER_ID, ['entry_id' => $second]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $first]], $this->findingsOf([$first]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, $second]], $this->findingsOf([$second]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, min($first, $second)]], $this->findingsOf([$first, $second]));
    }

    /**
     * An artifact of another kind than a bulk operation's is a mismatch.
     *
     * @return void
     */
    public function testAnotherKindIsManifestMismatch(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['kind' => 'export']);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * An artifact counting another number of members than its manifest signed
     * is a mismatch, whether the stored count or the signed one changed.
     *
     * @return void
     */
    public function testAChangedSignedCountIsManifestMismatch(): void
    {
        $entryId    = $this->seedBundle();
        $descriptor = $this->descriptorsOf([$entryId])[$entryId];

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->verifier()->findings([$entryId => ['count' => 4] + $descriptor]));

        $this->tamperWithArtifact($entryId, ['member_count' => 4]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * An artifact holding another digest than its manifest signed is a
     * mismatch, whether the stored digest or the signed one changed.
     *
     * @return void
     */
    public function testAChangedDigestIsManifestMismatch(): void
    {
        $entryId    = $this->seedBundle();
        $descriptor = $this->descriptorsOf([$entryId])[$entryId];

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->verifier()->findings([$entryId => ['digest' => self::OTHER_DIGEST] + $descriptor]));

        $this->tamperWithArtifact($entryId, ['digest' => self::OTHER_DIGEST]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * An artifact whose columns differ from its manifest's is a mismatch
     * without its members being read: protects against a check that opens every
     * artifact.
     *
     * @return void
     */
    public function testTheMembersOfAMismatchedArtifactAreNeverRead(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['kind' => 'export', 'members' => 'not a ciphertext']);

        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
        self::assertCount(1, $statements);
        self::assertStringContainsString('length(', $statements[0]);
    }

    /**
     * Members out of their canonical order are a mismatch, even holding every
     * member signed and giving the stored digest.
     *
     * @return void
     */
    public function testMembersOutOfOrderAreManifestMismatch(): void
    {
        $entryId  = $this->seedBundle();
        $reversed = self::plaintextOf(array_reverse(self::pairs(3)));

        $this->tamperWithArtifact($entryId, ['members' => self::sealed($reversed), 'digest' => hash('sha256', $reversed)]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Members holding one twice are a mismatch, though they are in order and as
     * many as signed.
     *
     * @return void
     */
    public function testADuplicateMemberIsManifestMismatch(): void
    {
        $entryId = $this->seedBundle();
        $pairs   = self::pairs(2);

        $this->tamperWithArtifact($entryId, ['members' => self::sealed(self::plaintextOf([$pairs[0], $pairs[0], $pairs[1]]))]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Members in canonical form but fewer than signed are a mismatch, and so
     * are more than signed.
     *
     * @return void
     */
    public function testFewerMembersThanSignedAreManifestMismatch(): void
    {
        $fewer = $this->seedBundle();
        $more  = $this->seedBundle();

        $this->tamperWithArtifact($fewer, ['members' => self::sealed(Manifest::encode(self::pairs(2)))]);
        $this->tamperWithArtifact($more, ['members' => self::sealed(Manifest::encode(self::pairs(4)))]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $fewer]], $this->findingsOf([$fewer]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, $more]], $this->findingsOf([$more]));
    }

    /**
     * Members in canonical form, as many as signed, but of other subjects do
     * not give the signed digest and are a mismatch.
     *
     * @return void
     */
    public function testOtherMembersOfTheSignedCountAreManifestMismatch(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['members' => self::sealed(Manifest::encode([['App\Models\Invoice', '7'], ['App\Models\Invoice', '8'], ['App\Models\Invoice', '9']]))]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Members that open but are not a manifest at all are a mismatch.
     *
     * @return void
     */
    public function testMembersThatAreNotAManifestAreManifestMismatch(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['members' => self::sealed('not json')]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Rows of `[stored members]`: members no application key opens, whether not
     * a ciphertext at all or sealed under a key the application does not hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUndecryptableMembers(): iterable
    {
        yield from [
            'not a ciphertext'         => ['not a ciphertext'],
            'sealed under another key' => [(new Encrypter(self::OTHER_KEY, 'aes-256-cbc'))->encryptString('[]')],
        ];
    }

    /**
     * Members the application's keys cannot decrypt cannot be checked, which is
     * `manifest_unreadable`, never a mismatch.
     *
     * @param  string  $members
     * @return void
     */
    #[DataProvider('provideUndecryptableMembers')]
    public function testUndecryptableMembersAreManifestUnreadable(string $members): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['members' => $members]);

        self::assertSame([[Finding::MANIFEST_UNREADABLE, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Members sealed under a key since rotated into `app.previous_keys` still
     * open and verify; once that key is dropped they are unreadable.
     *
     * @return void
     */
    public function testAPreviousApplicationKeyStillOpensTheMembers(): void
    {
        $entryId = $this->seedBundle();
        $config  = app(ConfigRepository::class);
        $old     = $config->get('app.key');

        self::assertIsString($old);

        $config->set('app.key', 'base64:' . base64_encode(self::OTHER_KEY));
        $config->set('app.previous_keys', [$old]);

        app()->forgetInstance('encrypter');

        self::assertSame([], $this->findingsOf([$entryId]));

        $config->set('app.previous_keys', []);

        app()->forgetInstance('encrypter');

        self::assertSame([[Finding::MANIFEST_UNREADABLE, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Each finding is given once, at the earliest of the entries it was found
     * at, bytewise, and the findings in the order of `Finding`, whatever order
     * the entries come in.
     *
     * @return void
     */
    public function testEachFindingNamesTheEarliestEntry(): void
    {
        $ids = $this->seedBundles(6);

        foreach ([0, 1] as $index) {
            $this->artifactsTable()->where('entry_id', $ids[$index])->delete();
        }

        foreach ([2, 3] as $index) {
            $this->tamperWithArtifact($ids[$index], ['members' => 'not a ciphertext']);
        }

        foreach ([4, 5] as $index) {
            $this->tamperWithArtifact($ids[$index], ['digest' => self::OTHER_DIGEST]);
        }

        $expected = [
            [Finding::MANIFEST_MISSING, min($ids[0], $ids[1])],
            [Finding::MANIFEST_MISMATCH, min($ids[4], $ids[5])],
            [Finding::MANIFEST_UNREADABLE, min($ids[2], $ids[3])],
        ];

        self::assertSame($expected, $this->findingsOf($ids));
        self::assertSame($expected, $this->findingsOf(array_reverse($ids)));
    }

    /**
     * A stored entry with no manifest has no descriptor and is never checked,
     * and no manifest at all costs no statement.
     *
     * @return void
     */
    public function testAnEntryWithoutADescriptorIsSkipped(): void
    {
        $entry = app(RowCodec::class)->encode(app(RecordSigner::class)->sign(RecordFactory::captured(), RecordFactory::RECORDED_AT));

        self::assertNull($this->verifier()->descriptorOf($entry));

        $statements = $this->recordArtifactStatements();

        self::assertSame([], $this->verifier()->findings([]));
        self::assertCount(0, $statements);
    }

    /**
     * Rows of `[stored properties, the descriptor read]`: an entry's raw
     * properties, and what is read of them, the stored value as it is, an empty
     * map for a value that is no map, and `null` where there is none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed, 1: ?array<array-key, mixed>}>
     */
    public static function provideStoredProperties(): iterable
    {
        yield from [
            'no properties'             => [null, null],
            'not a string'              => [['_audit' => ['manifest' => ['count' => 1]]], null],
            'not JSON'                  => ['{', null],
            'a JSON scalar'             => ['3', null],
            'no metadata'               => ['{"amount":"1"}', null],
            'metadata that is no map'   => ['{"_audit":"x"}', null],
            'metadata with no manifest' => ['{"_audit":{"identifier_hash":"x"}}', null],
            'a manifest of null'        => ['{"_audit":{"manifest":null}}', []],
            'a manifest of a string'    => ['{"_audit":{"manifest":"x"}}', []],
            'a manifest that is a list' => ['{"_audit":{"manifest":[1,2]}}', [1, 2]],
            'a manifest as stored'      => ['{"_audit":{"manifest":{"count":3,"extra":true}}}', ['count' => 3, 'extra' => true]],
        ];
    }

    /**
     * A descriptor is read from the entry's raw properties at
     * `_audit.manifest`, as stored, whatever its shape.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $properties
     * @param  ?array<array-key, mixed>  $descriptor
     * @return void
     */
    #[DataProvider('provideStoredProperties')]
    public function testADescriptorIsReadAsStored(mixed $properties, ?array $descriptor): void
    {
        self::assertSame($descriptor, $this->verifier()->descriptorOf(['properties' => $properties]));
    }

    /**
     * Rows of `[descriptor]`: values a signed manifest descriptor is not, since
     * it is exactly a lower-case UUID artifact id, a 64 lower-case hex digest
     * and a positive integer count.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideMalformedDescriptors(): iterable
    {
        $valid = ['artifact_id' => self::OTHER_ID, 'digest' => self::OTHER_DIGEST, 'count' => 3];

        yield from [
            'empty'                       => [[]],
            'a list'                      => [[self::OTHER_ID, self::OTHER_DIGEST, 3]],
            'no artifact id'              => [array_diff_key($valid, ['artifact_id' => true])],
            'no digest'                   => [array_diff_key($valid, ['digest' => true])],
            'no count'                    => [array_diff_key($valid, ['count' => true])],
            'an extra key'                => [$valid + ['extra' => 1]],
            'an upper-case artifact id'   => [['artifact_id' => strtoupper(self::OTHER_ID)] + $valid],
            'an artifact id not a UUID'   => [['artifact_id' => 'artifact'] + $valid],
            'an artifact id not a string' => [['artifact_id' => 7] + $valid],
            'an upper-case digest'        => [['digest' => strtoupper(self::OTHER_DIGEST)] + $valid],
            'a short digest'              => [['digest' => substr(self::OTHER_DIGEST, 1)] + $valid],
            'a digest not a string'       => [['digest' => 7] + $valid],
            'a zero count'                => [['count' => 0] + $valid],
            'a negative count'            => [['count' => -1] + $valid],
            'a count as a string'         => [['count' => '3'] + $valid],
            'a count as a float'          => [['count' => 3.0] + $valid],
        ];
    }

    /**
     * A malformed descriptor is a mismatch at its entry, found with no
     * statement, since a signed descriptor cannot be malformed without the key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return void
     */
    #[DataProvider('provideMalformedDescriptors')]
    public function testAMalformedDescriptorIsManifestMismatch(array $descriptor): void
    {
        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_MISMATCH, self::ENTRY_ID]], $this->verifier()->findings([self::ENTRY_ID => $descriptor]));
        self::assertCount(0, $statements);
    }

    /**
     * A stored entry signing a manifest that is no map, or a map that is no
     * descriptor, is checked and is a mismatch, never skipped.
     *
     * @return void
     */
    public function testAManifestThatIsNoMapIsManifestMismatch(): void
    {
        $scalar = $this->seedEntrySigning('not a descriptor');
        $extra  = $this->seedEntrySigning(['artifact_id' => self::OTHER_ID, 'digest' => self::OTHER_DIGEST, 'count' => 3, 'extra' => true]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $scalar]], $this->findingsOf([$scalar]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, $extra]], $this->findingsOf([$extra]));
    }

    /**
     * A manifest keyed by an entry id that is not a lower-case UUID is a
     * mismatch, and no statement binds it: protects every engine's UUID column
     * from a value it would refuse.
     *
     * @return void
     */
    public function testAnEntryIdThatIsNotAUuidIsManifestMismatch(): void
    {
        $descriptor = ['artifact_id' => self::OTHER_ID, 'digest' => self::OTHER_DIGEST, 'count' => 3];
        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_MISMATCH, 'not-a-uuid']], $this->verifier()->findings(['not-a-uuid' => $descriptor]));
        self::assertCount(0, $statements);
    }

    /**
     * The artifacts of 250 bundles are read in three statements of at most 100
     * entries each, and their members, which fit the byte bound, in one more
     * statement per batch, never one per entry.
     *
     * @return void
     */
    public function testManifestsAreReadInBatches(): void
    {
        $ids        = $this->seedBundles(250, 1);
        $statements = $this->recordArtifactStatements();

        self::assertSame([], $this->findingsOf($ids));

        $metadata = array_values(array_filter($statements->getArrayCopy(), static fn (string $sql): bool => str_contains($sql, 'length(')));

        self::assertCount(3, $metadata);
        self::assertCount(6, $statements);
    }

    /**
     * The members are read in sub-batches whose stored bytes sum to at most the
     * bound: five artifacts under a bound of two read their members in three
     * statements, each of at most two, and one larger than the bound is read
     * alone.
     *
     * @return void
     */
    public function testMembersAreFetchedWithinTheByteBatch(): void
    {
        $ids    = $this->seedBundles(5);
        $length = strlen((string) ($this->artifactOf($ids[0])['members'] ?? ''));

        $statements = $this->recordArtifactStatements();

        self::assertSame([], $this->findingsOf($ids, 2 * $length));
        self::assertSame([2, 2, 1], self::idsBound($statements));

        $statements->exchangeArray([]);

        self::assertSame([], $this->findingsOf($ids, $length - 1));
        self::assertSame([1, 1, 1, 1, 1], self::idsBound($statements));
    }

    /**
     * The default byte bound is 64 MiB and the entry batch 100.
     *
     * @return void
     */
    public function testTheBatchesArePinned(): void
    {
        self::assertSame(67108864, ManifestVerifier::MEMBERS_BATCH_BYTES);
        self::assertSame(100, ManifestVerifier::ENTRY_BATCH);
    }

    /**
     * Every statement reads the writer, so a replica's lag never reads as a
     * missing artifact: with a reader that refuses to be used, a check of a
     * bundle still passes.
     *
     * @return void
     */
    public function testEveryStatementReadsTheWriter(): void
    {
        $entryId     = $this->seedBundle();
        $descriptors = $this->descriptorsOf([$entryId]);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The manifest check read the replica.');
        });

        self::assertSame([], $this->verifier()->findings($descriptors));
    }

    /**
     * The findings of the stored entries' manifests, under a verifier from the
     * container's collaborators with the byte bound given or the default.
     *
     * @param  list<string>  $entryIds
     * @param  int  $membersBatchBytes
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    private function findingsOf(array $entryIds, int $membersBatchBytes = ManifestVerifier::MEMBERS_BATCH_BYTES): array
    {
        return $this->verifier($membersBatchBytes)->findings($this->descriptorsOf($entryIds));
    }

    /**
     * The descriptor each stored entry holds, by its id, read as the segment
     * verifier reads it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<string>  $entryIds
     * @return array<string, array<array-key, mixed>>
     */
    private function descriptorsOf(array $entryIds): array
    {
        $descriptors = [];

        foreach ($entryIds as $entryId) {
            $entry = DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $entryId)->first();

            self::assertNotNull($entry, 'No entry is stored with the id ' . $entryId . '.');

            $descriptor = $this->verifier()->descriptorOf((array) $entry);

            self::assertNotNull($descriptor, 'The entry ' . $entryId . ' holds no manifest.');

            $descriptors[$entryId] = $descriptor;
        }

        return $descriptors;
    }

    /**
     * A manifest verifier from the container's collaborators, with the byte
     * bound given or the default.
     *
     * @param  int  $membersBatchBytes
     * @return \SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier
     */
    private function verifier(int $membersBatchBytes = ManifestVerifier::MEMBERS_BATCH_BYTES): ManifestVerifier
    {
        return new ManifestVerifier(app(DatabaseManager::class), app(StringEncrypter::class), $membersBatchBytes);
    }

    /**
     * Record, from now on, every statement the storage connection runs on the
     * artifacts table, in lower case.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordArtifactStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;
        $table      = EntrySettings::artifactsTable();

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements, $table): void {
            if (!str_contains($query->sql, $table)) {
                return;
            }

            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }

    /**
     * Record, from now on, every statement the storage connection runs, in
     * lower case.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }

    /**
     * How many ids each recorded members statement binds, in order; the
     * statement reading the artifacts' columns is left out.
     *
     * @param  \ArrayObject<int, string>  $statements
     * @return list<int>
     */
    private static function idsBound(\ArrayObject $statements): array
    {
        $bound = [];

        foreach ($statements as $sql) {
            if (str_contains($sql, 'length(')) {
                continue;
            }

            $bound[] = substr_count($sql, '?');
        }

        return $bound;
    }

    /**
     * The type and id pairs of `App\Models\Invoice` 1 to the number given, as
     * strings, in the order the references come.
     *
     * @param  int  $count
     * @return list<array{0: string, 1: string}>
     */
    private static function pairs(int $count): array
    {
        return array_map(static fn (int $id): array => [RecordFactory::MEMBER_TYPE, (string) $id], range(1, $count));
    }

    /**
     * The members as JSON with the manifest's flags, in the order given.
     *
     * @param  list<array{0: string, 1: string}>  $members
     * @return string
     */
    private static function plaintextOf(array $members): string
    {
        return json_encode($members, Manifest::JSON_FLAGS);
    }

    /**
     * The plaintext sealed under the test encrypter, as an artifact's members
     * are.
     *
     * @param  string  $plaintext
     * @return string
     */
    private static function sealed(string $plaintext): string
    {
        return RecordFactory::encrypter()->encryptString($plaintext);
    }
}
