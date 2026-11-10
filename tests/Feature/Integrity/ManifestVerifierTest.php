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
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the check of the artifacts that verified entries' signed
 * manifests name, on whichever engine the suite runs against: bundles are
 * written as the store leaves them and changed through raw queries. They pin
 * the finding each change gives, for an artifact of every kind, that the
 * members must decrypt to exactly the canonical form of the kind the descriptor
 * names and describes, that each finding names the earliest entry, how a
 * descriptor is read from a stored entry, and that the artifacts are read in
 * batches of entries and their members in sub-batches of bytes, every statement
 * on the writer and none for no manifest.
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
        self::assertStringContainsString(EntrySettings::table(), $statements->getArrayCopy()[1]);
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
     * manifest signed is swapped.
     *
     * @return void
     */
    public function testAnotherArtifactIdIsManifestSwapped(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['id' => self::OTHER_ID]);

        self::assertSame([[Finding::MANIFEST_SWAPPED, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * The artifact the manifest signed, moved to name another entry, is found
     * by its id and is swapped, never merely missing.
     *
     * @return void
     */
    public function testAnArtifactOfAnotherEntryIsManifestSwapped(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['entry_id' => self::OTHER_ID]);

        self::assertSame([[Finding::MANIFEST_SWAPPED, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Two bundles of the same members whose artifacts are swapped between their
     * entries are each swapped, though each artifact's kind, count and digest
     * are the ones signed: only the artifact's id tells them apart. Their
     * members are never read.
     *
     * @return void
     */
    public function testASwappedArtifactIsSwapped(): void
    {
        [$first, $second] = $this->seedBundles(2);

        $this->swapArtifacts($first, $second);

        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_SWAPPED, $first]], $this->findingsOf([$first]));
        self::assertSame([[Finding::MANIFEST_SWAPPED, $second]], $this->findingsOf([$second]));
        self::assertSame([[Finding::MANIFEST_SWAPPED, min($first, $second)]], $this->findingsOf([$first, $second]));
        self::assertCount(3, $statements);
    }

    /**
     * A disclosure's and an export's artifacts swapped between their entries
     * are each swapped, before their kinds are compared: the stored kind of
     * each is the other's, but the artifact is the wrong one first.
     *
     * @return void
     */
    public function testArtifactsOfOtherKindsSwappedAreSwapped(): void
    {
        $disclosure = $this->seedBundle(2, ArtifactKind::DISCLOSURE);
        $export     = $this->seedBundle(2, ArtifactKind::EXPORT);

        $this->swapArtifacts($disclosure, $export);

        self::assertSame([[Finding::MANIFEST_SWAPPED, $disclosure]], $this->findingsOf([$disclosure]));
        self::assertSame([[Finding::MANIFEST_SWAPPED, $export]], $this->findingsOf([$export]));
    }

    /**
     * A bulk operation's artifact stored as another kind than its descriptor
     * names is the wrong kind.
     *
     * @return void
     */
    public function testAWrongKindIsWrongKind(): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['kind' => 'export']);

        self::assertSame([[Finding::MANIFEST_WRONG_KIND, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * A disclosure's artifact, its evidence read by the disclosure's own
     * reader, has no finding.
     *
     * @return void
     */
    public function testADisclosureArtifactVerifies(): void
    {
        $entryId = $this->seedBundle(3, ArtifactKind::DISCLOSURE);

        self::assertSame('disclosure', $this->artifactOf($entryId)['kind'] ?? null);
        self::assertSame([], $this->findingsOf([$entryId]));
    }

    /**
     * An export's artifact, its manifest read by the export's own reader, has
     * no finding.
     *
     * @return void
     */
    public function testAnExportArtifactVerifies(): void
    {
        $entryId = $this->seedBundle(2, ArtifactKind::EXPORT);

        self::assertSame('export', $this->artifactOf($entryId)['kind'] ?? null);
        self::assertSame([], $this->findingsOf([$entryId]));
    }

    /**
     * A disclosure of nothing and an export of no line, each counting no
     * member, have no finding.
     *
     * @return void
     */
    public function testAnEmptyDisclosureVerifies(): void
    {
        $disclosure = $this->seedBundle(0, ArtifactKind::DISCLOSURE);
        $export     = $this->seedBundle(0, ArtifactKind::EXPORT);

        self::assertSame(0, (int) ($this->artifactOf($disclosure)['member_count'] ?? -1));
        self::assertSame([], $this->findingsOf([$disclosure, $export]));
    }

    /**
     * An artifact stored as a kind its descriptor does not name is the wrong
     * kind, whether the stored kind or the signed one changed, and its members
     * are never read by another kind's reader.
     *
     * @return void
     */
    public function testAKindTheDescriptorDoesNotNameIsTheWrongKind(): void
    {
        $disclosure = $this->seedBundle(3, ArtifactKind::DISCLOSURE);
        $export     = $this->seedBundle(2, ArtifactKind::EXPORT);
        $descriptor = $this->descriptorsOf([$disclosure])[$disclosure];

        self::assertSame([[Finding::MANIFEST_WRONG_KIND, $disclosure]], $this->verifier()->findings([$disclosure => ['kind' => 'export'] + $descriptor]));
        self::assertSame([[Finding::MANIFEST_WRONG_KIND, $disclosure]], $this->verifier()->findings([$disclosure => ['kind' => 'bulk'] + $descriptor]));

        $this->tamperWithArtifact($export, ['kind' => 'disclosure']);

        self::assertSame([[Finding::MANIFEST_WRONG_KIND, $export]], $this->findingsOf([$export]));
    }

    /**
     * Rows of `[kind, another canonical form]`: each kind, and a canonical form
     * of it counting two members, as its fixture does, but of other members.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind, 1: string}>
     */
    public static function provideKinds(): iterable
    {
        yield from [
            'bulk'       => [ArtifactKind::BULK, Manifest::encode([[RecordFactory::MEMBER_TYPE, '7'], [RecordFactory::MEMBER_TYPE, '8']])],
            'disclosure' => [ArtifactKind::DISCLOSURE, str_replace('000000000002', '000000000009', RecordFactory::canonical(ArtifactKind::DISCLOSURE, 2))],
            'export'     => [ArtifactKind::EXPORT, str_replace('000000000002', '000000000009', RecordFactory::canonical(ArtifactKind::EXPORT, 2))],
        ];
    }

    /**
     * An artifact of every kind is checked: as written it has no finding,
     * members that open to no canonical form of the kind are malformed, and
     * another canonical form of the kind, of the signed count, is tampered.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $other
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testEachKindOfArtifactIsChecked(ArtifactKind $kind, string $other): void
    {
        $verifies  = $this->seedBundle(2, $kind);
        $malformed = $this->seedBundle(2, $kind);
        $tampered  = $this->seedBundle(2, $kind);

        self::assertNotSame(RecordFactory::canonical($kind, 2), $other);

        $this->tamperWithArtifact($malformed, ['members' => self::sealed('{}')]);
        $this->tamperWithArtifact($tampered, ['members' => self::sealed($other)]);

        self::assertSame([], $this->findingsOf([$verifies]));
        self::assertSame([[Finding::MANIFEST_MALFORMED, $malformed]], $this->findingsOf([$malformed]));
        self::assertSame([[Finding::MANIFEST_TAMPERED, $tampered]], $this->findingsOf([$tampered]));
    }

    /**
     * Rows of `[kind, canonical form, count]`: an artifact signed and stored as
     * one kind whose plaintext is another kind's canonical form, or no
     * canonical form of its version, its descriptor's count and digest those of
     * that plaintext.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind, 1: string, 2: int}>
     */
    public static function provideOtherPlaintexts(): iterable
    {
        yield from [
            'bulk members as a disclosure'       => [ArtifactKind::DISCLOSURE, RecordFactory::canonical(ArtifactKind::BULK, 1), 1],
            'bulk members as an export'          => [ArtifactKind::EXPORT, RecordFactory::canonical(ArtifactKind::BULK, 1), 1],
            'a disclosure as a bulk operation'   => [ArtifactKind::BULK, RecordFactory::canonical(ArtifactKind::DISCLOSURE, 1), 1],
            'a disclosure as an export'          => [ArtifactKind::EXPORT, RecordFactory::canonical(ArtifactKind::DISCLOSURE, 0), 0],
            'an export as a disclosure'          => [ArtifactKind::DISCLOSURE, RecordFactory::canonical(ArtifactKind::EXPORT, 0), 0],
            'an export as a bulk operation'      => [ArtifactKind::BULK, RecordFactory::canonical(ArtifactKind::EXPORT, 1), 1],
            'a disclosure of a version not read' => [ArtifactKind::DISCLOSURE, str_replace('_version":1', '_version":2', RecordFactory::canonical(ArtifactKind::DISCLOSURE, 0)), 0],
            'a disclosure that is spaced'        => [ArtifactKind::DISCLOSURE, str_replace(',"', ', "', RecordFactory::canonical(ArtifactKind::DISCLOSURE, 0)), 0],
            'an export of a version not read'    => [ArtifactKind::EXPORT, str_replace('_version":1', '_version":2', RecordFactory::canonical(ArtifactKind::EXPORT, 0)), 0],
        ];
    }

    /**
     * An artifact whose plaintext is not exactly a canonical form of the kind
     * its descriptor names is malformed, even when its count and digest are the
     * signed ones and another kind's reader would read it: each kind is read by
     * its own reader.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $canonical
     * @param  int  $count
     * @return void
     */
    #[DataProvider('provideOtherPlaintexts')]
    public function testAPlaintextOfAnotherKindIsMalformed(ArtifactKind $kind, string $canonical, int $count): void
    {
        $entryId = $this->seedArtifactOfKind($kind, $canonical, $count);

        self::assertSame([[Finding::MANIFEST_MALFORMED, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Rows of `[members' plaintext]`: plaintexts a bulk operation's members
     * open to that are no canonical form of it.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPlaintexts(): iterable
    {
        yield from [
            'not JSON'           => ['not json'],
            'empty'              => [''],
            'a JSON map'         => ['{"App\\\Models\\\Invoice":"1"}'],
            'an empty list'      => ['[]'],
            'a member twice'     => [self::plaintextOf([self::pairs(2)[0], self::pairs(2)[0], self::pairs(2)[1]])],
            'out of order'       => [self::plaintextOf(array_reverse(self::pairs(3)))],
            'spaced'             => [str_replace(',', ', ', Manifest::encode(self::pairs(3)))],
            'an id not a string' => ['[["App\\\Models\\\Invoice",1]]'],
        ];
    }

    /**
     * Members that open but are no canonical form of the signed kind are
     * malformed, whatever their count.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideMalformedPlaintexts')]
    public function testAMalformedPlaintextIsMalformed(string $plaintext): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['members' => self::sealed($plaintext)]);

        self::assertSame([[Finding::MANIFEST_MALFORMED, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * Members out of their canonical order are malformed, even holding every
     * member signed and with the stored and the signed digest both theirs.
     *
     * @return void
     */
    public function testMembersOutOfOrderAreMalformed(): void
    {
        $entryId    = $this->seedBundle();
        $reversed   = self::plaintextOf(array_reverse(self::pairs(3)));
        $descriptor = ['digest' => hash('sha256', $reversed)] + $this->descriptorsOf([$entryId])[$entryId];

        $this->tamperWithArtifact($entryId, ['members' => self::sealed($reversed), 'digest' => hash('sha256', $reversed)]);

        self::assertSame([[Finding::MANIFEST_MALFORMED, $entryId]], $this->verifier()->findings([$entryId => $descriptor]));
    }

    /**
     * Members in canonical form that are not the ones signed are tampered:
     * fewer or more than signed, or as many of other subjects, which do not
     * give the signed digest.
     *
     * @return void
     */
    public function testATamperedPlaintextIsTampered(): void
    {
        $fewer = $this->seedBundle();
        $more  = $this->seedBundle();
        $other = $this->seedBundle();

        $this->tamperWithArtifact($fewer, ['members' => self::sealed(Manifest::encode(self::pairs(2)))]);
        $this->tamperWithArtifact($more, ['members' => self::sealed(Manifest::encode(self::pairs(4)))]);
        $this->tamperWithArtifact($other, ['members' => self::sealed(Manifest::encode([['App\Models\Invoice', '7'], ['App\Models\Invoice', '8'], ['App\Models\Invoice', '9']]))]);

        self::assertSame([[Finding::MANIFEST_TAMPERED, $fewer]], $this->findingsOf([$fewer]));
        self::assertSame([[Finding::MANIFEST_TAMPERED, $more]], $this->findingsOf([$more]));
        self::assertSame([[Finding::MANIFEST_TAMPERED, $other]], $this->findingsOf([$other]));
    }

    /**
     * Another disclosure of the same count, canonical and of a supported
     * version, is tampered: its digest is not the one signed.
     *
     * @return void
     */
    public function testAnotherDisclosureOfTheSignedCountIsTampered(): void
    {
        $entryId = $this->seedBundle(0, ArtifactKind::DISCLOSURE);

        $this->tamperWithArtifact($entryId, ['members' => self::sealed(DisclosureManifest::of(['a' => 1], null, [])->canonical)]);

        self::assertSame([[Finding::MANIFEST_TAMPERED, $entryId]], $this->findingsOf([$entryId]));
    }

    /**
     * An artifact counting another number of members, or holding another
     * digest, than its manifest signed is a mismatch, whether the stored column
     * or the signed value changed.
     *
     * @return void
     */
    public function testAColumnMismatchIsAMismatch(): void
    {
        $count      = $this->seedBundle();
        $digest     = $this->seedBundle();
        $descriptor = $this->descriptorsOf([$count])[$count];

        self::assertSame([[Finding::MANIFEST_MISMATCH, $count]], $this->verifier()->findings([$count => ['count' => 4] + $descriptor]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, $count]], $this->verifier()->findings([$count => ['digest' => self::OTHER_DIGEST] + $descriptor]));

        $this->tamperWithArtifact($count, ['member_count' => 4]);
        $this->tamperWithArtifact($digest, ['digest' => self::OTHER_DIGEST]);

        self::assertSame([[Finding::MANIFEST_MISMATCH, $count]], $this->findingsOf([$count]));
        self::assertSame([[Finding::MANIFEST_MISMATCH, $digest]], $this->findingsOf([$digest]));
    }

    /**
     * Rows of `[changed columns, finding]`: a change to an artifact's columns
     * and the finding it gives without its members being read.
     *
     * @return iterable<string, array{0: array<string, int|string>, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideColumnChanges(): iterable
    {
        yield from [
            'another id'     => [['id' => self::OTHER_ID], Finding::MANIFEST_SWAPPED],
            'another kind'   => [['kind' => 'export'], Finding::MANIFEST_WRONG_KIND],
            'another count'  => [['member_count' => 4], Finding::MANIFEST_MISMATCH],
            'another digest' => [['digest' => self::OTHER_DIGEST], Finding::MANIFEST_MISMATCH],
        ];
    }

    /**
     * An artifact whose columns differ from its manifest's gives its finding
     * without its members being read: protects against a check that opens every
     * artifact.
     *
     * @param  array<string, int|string>  $columns
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    #[DataProvider('provideColumnChanges')]
    public function testTheMembersOfAMismatchedArtifactAreNeverRead(array $columns, Finding $finding): void
    {
        $entryId = $this->seedBundle();

        $this->tamperWithArtifact($entryId, ['members' => 'not a ciphertext'] + $columns);

        $statements = $this->recordArtifactStatements();

        self::assertSame([[$finding, $entryId]], $this->findingsOf([$entryId]));
        self::assertCount(1, $statements);
        self::assertStringContainsString('length(', $statements->getArrayCopy()[0]);
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
     * the entries come in: every artifact finding at once, each at two entries.
     *
     * @return void
     */
    public function testEachFindingNamesTheEarliestEntry(): void
    {
        $ids = $this->seedBundles(14);

        foreach ([0, 1] as $index) {
            $this->artifactsTable()->where('entry_id', $ids[$index])->delete();
        }

        foreach ([2, 3] as $index) {
            $this->tamperWithArtifact($ids[$index], ['members' => 'not a ciphertext']);
        }

        foreach ([4, 5] as $index) {
            $this->tamperWithArtifact($ids[$index], ['digest' => self::OTHER_DIGEST]);
        }

        foreach ([6, 7] as $index) {
            $this->tamperWithArtifact($ids[$index], ['id' => sprintf('01932b4e-9000-7000-8000-%012d', $index)]);
        }

        foreach ([8, 9] as $index) {
            $this->tamperWithArtifact($ids[$index], ['kind' => 'disclosure']);
        }

        foreach ([10, 11] as $index) {
            $this->tamperWithArtifact($ids[$index], ['members' => self::sealed('not json')]);
        }

        foreach ([12, 13] as $index) {
            $this->tamperWithArtifact($ids[$index], ['members' => self::sealed(Manifest::encode(self::pairs(2)))]);
        }

        $expected = [
            [Finding::MANIFEST_MISSING, min($ids[0], $ids[1])],
            [Finding::MANIFEST_MISMATCH, min($ids[4], $ids[5])],
            [Finding::MANIFEST_SWAPPED, min($ids[6], $ids[7])],
            [Finding::MANIFEST_WRONG_KIND, min($ids[8], $ids[9])],
            [Finding::MANIFEST_MALFORMED, min($ids[10], $ids[11])],
            [Finding::MANIFEST_TAMPERED, min($ids[12], $ids[13])],
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
     * it is exactly a lower-case UUID artifact id, a kind the package knows, a
     * 64 lower-case hex digest and an integer count, positive for a bulk
     * operation and never negative.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideMalformedDescriptors(): iterable
    {
        $valid = ['artifact_id' => self::OTHER_ID, 'kind' => 'bulk', 'digest' => self::OTHER_DIGEST, 'count' => 3];

        yield from [
            'empty'                       => [[]],
            'a list'                      => [[self::OTHER_ID, self::OTHER_DIGEST, 3]],
            'no artifact id'              => [array_diff_key($valid, ['artifact_id' => true])],
            'no digest'                   => [array_diff_key($valid, ['digest' => true])],
            'no count'                    => [array_diff_key($valid, ['count' => true])],
            'no kind'                     => [array_diff_key($valid, ['kind' => true])],
            'an unknown kind'             => [['kind' => 'audit'] + $valid],
            'an upper-case kind'          => [['kind' => 'BULK'] + $valid],
            'a kind not a string'         => [['kind' => 1] + $valid],
            'a negative disclosure'       => [['kind' => 'disclosure', 'count' => -1] + $valid],
            'a negative export'           => [['kind' => 'export', 'count' => -1] + $valid],
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
     * A malformed descriptor is malformed at its entry, found with no
     * statement, since a signed descriptor cannot be malformed without the key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return void
     */
    #[DataProvider('provideMalformedDescriptors')]
    public function testAMalformedDescriptorIsMalformed(array $descriptor): void
    {
        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_MALFORMED, self::ENTRY_ID]], $this->verifier()->findings([self::ENTRY_ID => $descriptor]));
        self::assertCount(0, $statements);
    }

    /**
     * A stored entry signing a manifest that is no map, or a map that is no
     * descriptor, a key added or its kind missing, is checked and is malformed,
     * never skipped.
     *
     * @return void
     */
    public function testAManifestThatIsNoMapIsMalformed(): void
    {
        $scalar = $this->seedEntrySigning('not a descriptor');
        $extra  = $this->seedEntrySigning(['artifact_id' => self::OTHER_ID, 'kind' => 'bulk', 'digest' => self::OTHER_DIGEST, 'count' => 3, 'extra' => true]);
        $three  = $this->seedEntrySigning(['artifact_id' => self::OTHER_ID, 'digest' => self::OTHER_DIGEST, 'count' => 3]);

        self::assertSame([[Finding::MANIFEST_MALFORMED, $scalar]], $this->findingsOf([$scalar]));
        self::assertSame([[Finding::MANIFEST_MALFORMED, $extra]], $this->findingsOf([$extra]));
        self::assertSame([[Finding::MANIFEST_MALFORMED, $three]], $this->findingsOf([$three]));
    }

    /**
     * A manifest keyed by an entry id that is not a lower-case UUID is
     * malformed, and no statement binds it: protects every engine's UUID column
     * from a value it would refuse.
     *
     * @return void
     */
    public function testAnEntryIdThatIsNotAUuidIsMalformed(): void
    {
        $descriptor = ['artifact_id' => self::OTHER_ID, 'kind' => 'bulk', 'digest' => self::OTHER_DIGEST, 'count' => 3];
        $statements = $this->recordArtifactStatements();

        self::assertSame([[Finding::MANIFEST_MALFORMED, 'not-a-uuid']], $this->verifier()->findings(['not-a-uuid' => $descriptor]));
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
