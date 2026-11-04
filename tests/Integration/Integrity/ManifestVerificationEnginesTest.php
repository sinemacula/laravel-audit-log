<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Encryption\Encrypter;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\SeedsArtifacts;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for the check of bundles' artifacts by `audit-log:verify`
 * on whichever engine the suite runs against, each artifact written and changed
 * through the engine's own columns: a sealed bundle verifies, as do a
 * disclosure's and an export's artifacts and an empty disclosure, a missing
 * artifact, artifacts swapped between entries, an artifact stored as another
 * kind, members that are no canonical form, a changed member list, a changed
 * count and an artifact moved to another entry are each tampered with a finding
 * of their own, an artifact the application's key cannot open is unverifiable,
 * a bundle not yet sealed is not checked until it is, and the greatest manifest
 * the settings allow, sealed in the longest artifact there can be, verifies on
 * every engine.
 *
 * The memory limit is raised for the test, because it is often less than the
 * greatest manifest needs, and the assertions should be what fails rather than
 * the engine's limit. It claims no coverage because that manifest is among the
 * slowest things in the suite: a mutant whose covering tests included it would
 * be skipped as taking too long rather than run. The checks are pinned by the
 * manifest verifier's and the segment verifier's own tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ManifestVerificationEnginesTest extends TestCase
{
    use SeedsArtifacts, TampersWithTheLog;

    /** @var string When the log is sealed: after every bundle is recorded. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every command runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string An entry id no stored entry has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var string The memory limit the tests run under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The greatest `audit-log.capture.bulk.max_bytes` takes: 8 MiB of canonical form. */
    private const int BULK_MAX_BYTES = 8388608;

    /** @var int The greatest `audit-log.capture.bulk.max_members` takes. */
    private const int BULK_MAX_MEMBERS = 1000000;

    /** @var string The type of every member of the greatest manifest. */
    private const string MEMBER_TYPE = 'invoice';

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /**
     * Register both commands, bind no anchor, nothing pruned and a clock
     * stopped when every command runs, seal at a fixed time, and raise the
     * memory limit.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->registerIntegrityCommands();

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $this->sealAt(self::SEALED_AT);

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Restore the memory limit, as far as what the process still holds allows.
     * An unlimited process stays so.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));
    }

    /**
     * A sealed bundle beside a plain entry verifies, and the run passes.
     *
     * @return void
     */
    public function testASealedBundleVerifies(): void
    {
        $this->storeEntries(1);
        $this->seedBundle();
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $this->sealIdAt(1)), $output);
    }

    /**
     * A sealed disclosure's artifact, written through the engine's columns,
     * verifies beside a plain entry.
     *
     * @return void
     */
    public function testADisclosureArtifactVerifies(): void
    {
        $this->storeEntries(1);
        $this->seedBundle(3, ArtifactKind::DISCLOSURE);
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $this->sealIdAt(1)), $output);
    }

    /**
     * A sealed export's artifact, written through the engine's columns,
     * verifies.
     *
     * @return void
     */
    public function testAnExportArtifactVerifies(): void
    {
        $this->seedBundle(2, ArtifactKind::EXPORT);
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString('integrity=valid anchoring=unanchored members=1', $output);
    }

    /**
     * A sealed disclosure of nothing and an export of no line, stored with a
     * count of 0 in the engine's unsigned column, verify.
     *
     * @return void
     */
    public function testAnEmptyDisclosureVerifies(): void
    {
        $disclosure = $this->seedBundle(0, ArtifactKind::DISCLOSURE);

        $this->seedBundle(0, ArtifactKind::EXPORT);
        $this->sealAll();

        self::assertSame(0, (int) ($this->artifactOf($disclosure)['member_count'] ?? -1));

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString('integrity=valid anchoring=unanchored members=2', $output);
    }

    /**
     * A sealed disclosure and a sealed export in one seal, written through the
     * engine's columns, verify together; the export's members replaced by a
     * plaintext that is no export manifest are then tampered as malformed, read
     * by the export's own reader.
     *
     * @return void
     */
    public function testADisclosureAndAnExportVerifyOnEveryEngine(): void
    {
        $this->seedBundle(3, ArtifactKind::DISCLOSURE);

        $export = $this->seedBundle(2, ArtifactKind::EXPORT);

        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $this->sealIdAt(1)), $output);

        $this->tamperWithArtifact($export, ['members' => app(StringEncrypter::class)->encryptString(RecordFactory::canonical(ArtifactKind::DISCLOSURE, 2))]);

        $this->assertTheSealIs('tampered', 'manifest_malformed', $export, 2);
    }

    /**
     * Two sealed bundles whose artifacts are swapped between their entries,
     * through the engine's unique entry index, are tampered as swapped, at the
     * earlier entry.
     *
     * @return void
     */
    public function testASwappedArtifactIsFoundOnEveryEngine(): void
    {
        $first  = $this->seedBundle();
        $second = $this->seedBundle();

        $this->sealAll();
        $this->swapArtifacts($first, $second);

        $this->assertTheSealIs('tampered', 'manifest_swapped', min($first, $second), 2);
    }

    /**
     * A sealed disclosure whose artifact is stored as another kind than its
     * descriptor names is tampered as the wrong kind.
     *
     * @return void
     */
    public function testAKindTheDescriptorDoesNotNameIsTheWrongKind(): void
    {
        $entryId = $this->seedBundle(3, ArtifactKind::DISCLOSURE);

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['kind' => 'export']);

        $this->assertTheSealIs('tampered', 'manifest_wrong_kind', $entryId);
    }

    /**
     * A sealed bundle whose artifact is deleted is tampered, at its entry.
     *
     * @return void
     */
    public function testAMissingArtifactIsTampered(): void
    {
        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        $this->assertTheSealIs('tampered', 'manifest_missing', $entryId);
    }

    /**
     * A sealed bundle whose members are replaced by another canonical list,
     * opened by the application's key, is tampered as `manifest_tampered`.
     *
     * @return void
     */
    public function testAChangedMemberListIsTampered(): void
    {
        $entryId = $this->seedBundle();
        $members = Manifest::encode([[RecordFactory::MEMBER_TYPE, '1'], [RecordFactory::MEMBER_TYPE, '2']]);

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['members' => app(StringEncrypter::class)->encryptString($members)]);

        $this->assertTheSealIs('tampered', 'manifest_tampered', $entryId);
    }

    /**
     * A sealed bundle whose artifact counts another number of members is
     * tampered as a mismatch.
     *
     * @return void
     */
    public function testAChangedCountIsTampered(): void
    {
        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['member_count' => 4]);

        $this->assertTheSealIs('tampered', 'manifest_mismatch', $entryId);
    }

    /**
     * A sealed bundle whose artifact is moved to name another entry is found by
     * its id and is tampered as swapped.
     *
     * @return void
     */
    public function testAnArtifactOfAnotherEntryIsTampered(): void
    {
        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['entry_id' => self::OTHER_ID]);

        $this->assertTheSealIs('tampered', 'manifest_swapped', $entryId);
    }

    /**
     * A sealed bundle whose members were sealed under a key the application
     * does not hold is unverifiable.
     *
     * @return void
     */
    public function testAnUndecryptableArtifactIsUnverifiable(): void
    {
        $entryId = $this->seedBundle();
        $members = (new Encrypter(str_repeat('k', 32), 'aes-256-cbc'))->encryptString(Manifest::encode([[RecordFactory::MEMBER_TYPE, '1']]));

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['members' => $members]);

        $this->assertTheSealIs('unverifiable', 'manifest_unreadable', $entryId);
    }

    /**
     * A bundle no seal holds yet is not checked: its missing artifact fails no
     * run while it is pending, and is tampered once its entry is sealed, as the
     * entry's own signature is.
     *
     * @return void
     */
    public function testAnUnsealedBundleIsNotYetChecked(): void
    {
        $entryId = $this->seedBundle();

        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString("Unsealed: 1 pending, 0 overdue.\n", $output);
        self::assertStringNotContainsString('manifest_', $output);

        $this->sealAll();

        $this->assertTheSealIs('tampered', 'manifest_missing', $entryId);
    }

    /**
     * The greatest manifest the settings allow, sealed in the longest artifact
     * there can be and written through the engine's columns, verifies.
     *
     * @return void
     */
    public function testTheMaximumManifestVerifies(): void
    {
        $manifest   = Manifest::of(self::membersOfBytes(self::BULK_MAX_BYTES), self::BULK_MAX_MEMBERS, self::BULK_MAX_BYTES);
        $attachment = Attachment::sealed($manifest, app(StringEncrypter::class));
        $properties = ['batch' => 'march', '_audit' => ['manifest' => $manifest->descriptor()]];
        $record     = RecordFactory::withFields(['properties' => $properties, 'attachment' => $attachment], RecordFactory::bundled());

        self::assertSame(self::BULK_MAX_BYTES, strlen($manifest->canonical));

        $entryId = $this->seedFinalisedBundle(app(RecordSigner::class)->sign($record, RecordFactory::RECORDED_AT));

        self::assertSame(strlen((string) $attachment->members), strlen((string) ($this->artifactOf($entryId)['members'] ?? '')));

        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit, 'The greatest manifest did not verify.');
        self::assertStringContainsString('integrity=valid anchoring=unanchored members=1', $output);
    }

    /**
     * The run fails, and the first seal, holding the number of members given,
     * is of the integrity given, with the finding given at the entry given.
     *
     * @param  string  $integrity
     * @param  string  $finding
     * @param  string  $entryId
     * @param  int  $members
     * @return void
     */
    private function assertTheSealIs(string $integrity, string $finding, string $entryId, int $members = 1): void
    {
        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        $line = sprintf("seal 1 %s integrity=%s anchoring=unanchored members=%d finding=%s first=%s\n", $this->sealIdAt(1), $integrity, $members, $finding, $entryId);

        self::assertStringContainsString($line, $output);
    }

    /**
     * References whose manifest's canonical form is exactly the bytes given: as
     * many of the longest id as fit, then two that make up the rest. Each pair
     * encodes to its id's length and 14 bytes more, and its comma to one; the
     * brackets add two, less the comma the last pair has not.
     *
     * @param  int  $bytes
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Records\Reference, void, void>
     */
    private static function membersOfBytes(int $bytes): \Generator
    {
        $longest = Reference::MAX_CHARACTERS;
        $full    = intdiv($bytes - 1, $longest + 15) - 1;
        $rest    = $bytes                            - 1 - ($full * ($longest + 15)) - 30;
        $first   = min($longest, $rest - 1);

        for ($index = 0; $index < $full; $index++) {
            yield Reference::of(self::MEMBER_TYPE, str_pad(sprintf('%07d', $index), $longest, 'x'));
        }

        yield Reference::of(self::MEMBER_TYPE, str_repeat('y', $first));
        yield Reference::of(self::MEMBER_TYPE, str_repeat('z', $rest - $first));
    }
}
