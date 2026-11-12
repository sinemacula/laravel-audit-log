<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationContext;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the verification of one segment, every tampering applied
 * through raw queries on whichever engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SegmentVerifier::class)]
final class SegmentVerifierTest extends TestCase
{
    use SealsEntries, SeedsArtifacts;

    /** @var string When every seal of a test is made. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string The same instant in the package's form. */
    private const string SEALED_INSTANT = '2026-11-01T13:00:00.000000Z';

    /** @var string A grace that starts long after every seal, so none awaits its first anchoring. */
    private const string NO_GRACE = '2026-11-02T00:00:00.000000Z';

    /** @var string The run's clock, at which every grace ends: after every seal and every grace's start. */
    private const string RUN_CLOCK = '2026-11-02T00:00:00.000000Z';

    /** @var string The disk a disk anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string A secret of the first key of an explicit ring. */
    private const string SECRET_2025 = 'audit-log verify test key 2025 0123456789';

    /** @var string A secret of the second key of an explicit ring. */
    private const string SECRET_2026 = 'audit-log verify test key 2026 0123456789';

    /** @var string A digest no seal has. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string An id no seal has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var string The key an envelope names. */
    private const string KEY_ID = '01932b4e-9000-7000-8000-00000000000a';

    /** @var string Another key an envelope names. */
    private const string OTHER_KEY_ID = '01932b4e-9000-7000-8000-00000000000b';

    /** @var string An envelope's ciphertext, as the reader requires it: non-empty clean text. */
    private const string CIPHERTEXT = 'c2VhbGVk';

    /** @var string The id of a prune operation. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When a prune ran. */
    private const string PRUNED_AT = '2027-11-01T00:00:00.000000Z';

    /**
     * Seal entries at a fixed time for every test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * A segment as sealed is valid: every member found, its digest the stored
     * one, and unanchored with no anchor configured.
     *
     * @return void
     */
    public function testAValidSegment(): void
    {
        $this->storeEntries(3);
        $this->sealAll();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertSame(1, $report->sequence);
        self::assertSame($this->seal(1)['id'], $report->sealId);
        self::assertSame(3, $report->members);
        self::assertNull($report->finding);
        self::assertNull($report->firstBadId);
        self::assertSame($this->seal(1)['seal_digest'], $report->digest);
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * Of a missing entry, an entry under an unknown key and an edited entry,
     * the edit wins, reported at the entry it was found at.
     *
     * @return void
     */
    public function testTheMostSevereFindingWins(): void
    {
        [$missing, $unknown, $edited] = $this->storeEntries(3);

        $this->sealAll();

        $this->entries()->where('id', $missing)->delete();
        $this->entries()->where('id', $unknown)->update(['key_id' => 'gone']);
        $this->entries()->where('id', $edited)->update(['event' => 'invoice.voided']);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertSame($edited, $report->firstBadId);

        $this->entries()->where('id', $edited)->delete();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::ENTRY_KEY, $report->finding);
        self::assertSame($unknown, $report->firstBadId);
    }

    /**
     * Of several entries failing the same check, the first in member order, the
     * entry ids sorted bytewise, is named.
     *
     * @return void
     */
    public function testTheFirstBadIdIsTheFirstInMemberOrder(): void
    {
        $ids = $this->storeEntries(4);

        $this->sealAll();

        $sorted = self::sorted($ids);

        $this->entries()->whereIn('id', [$sorted[1], $sorted[3]])->update(['event' => 'invoice.voided']);

        $report = $this->report(1);

        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertSame($sorted[1], $report->firstBadId);
    }

    /**
     * A seal at another sequence than the one expected is a gap, though it
     * links to a seal before it.
     *
     * @return void
     */
    public function testAnUnexpectedFirstSequenceIsAGap(): void
    {
        $this->storeTwoSeals();

        $report = $this->report(2, expected: 1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEQUENCE_GAP, $report->finding);
        self::assertSame($this->seal(2)['id'], $report->firstBadId);
        self::assertNull($this->report(2)->finding);
    }

    /**
     * A sequence gap is found on the raw column even when the seal cannot be
     * read, and the gap, as tampering, outranks the malformed seal.
     *
     * @return void
     */
    public function testAGapIsFoundOnAMalformedSeal(): void
    {
        $this->storeTwoSeals();

        $this->checkpoints()->where('sequence', 2)->update(['members_digest' => 'not a digest']);

        $report = $this->report(2, expected: 3);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEQUENCE_GAP, $report->finding);
        self::assertNull($report->digest);
        self::assertSame(2, $report->sequence);
    }

    /**
     * Rows of `[column, value]`: edits that leave the first seal unreadable, by
     * a malformed column or by an algorithm version this release does not read.
     *
     * @return iterable<string, array{0: string, 1: int|string}>
     */
    public static function provideUnreadableEdits(): iterable
    {
        yield from [
            'a malformed column' => ['members_digest', 'not a digest'],
            'a later version'    => ['algorithm_version', 2],
        ];
    }

    /**
     * A link to a seal that cannot be read is broken even when it names that
     * seal's id, since a readable seal never follows an unreadable one.
     *
     * @param  string  $column
     * @param  int|string  $value
     * @return void
     */
    #[DataProvider('provideUnreadableEdits')]
    public function testALinkToASealThatCannotBeReadIsBroken(string $column, int|string $value): void
    {
        $this->storeTwoSeals();

        $this->checkpoints()->where('sequence', 1)->update([$column => $value]);

        $unreadable = $this->report(1);
        $next       = $this->report(2, $unreadable);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $unreadable->integrity);
        self::assertNull($unreadable->digest);
        self::assertSame(Finding::CHAIN_BROKEN, $next->finding);
        self::assertSame(IntegrityStatus::TAMPERED, $next->integrity);

        $stranger = new SegmentReport(1, self::OTHER_ID, IntegrityStatus::UNVERIFIABLE, AnchorStatus::UNANCHORED, 0);

        self::assertSame(Finding::CHAIN_BROKEN, $this->report(2, $stranger)->finding);
    }

    /**
     * A seal dated after the run's clock never awaits its first anchoring,
     * since the grace ends when the run began; one at the clock still does.
     *
     * @return void
     */
    public function testASealDatedAfterTheRunIsNotAwaiting(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $verifier = $this->verifier(new RecordingAnchor);
        $before   = $this->report(1, verifier: $verifier, context: new VerificationContext(null, true, '2026-11-01T12:45:00.000000Z', '2026-11-01T12:59:59.999999Z'));
        $at       = $this->report(1, verifier: $verifier, context: new VerificationContext(null, true, '2026-11-01T12:45:00.000000Z', self::SEALED_INSTANT));

        self::assertSame(AnchorStatus::UNANCHORED, $before->anchoring);
        self::assertFalse($before->awaitingAnchor);
        self::assertTrue($at->awaitingAnchor);
    }

    /**
     * When the run's anchor head settles anchoring, seals up to it are anchored
     * and later ones not held, with no call to the anchor.
     *
     * @return void
     */
    public function testTheAnchorsHeadSettlesAnchoringWithNoCall(): void
    {
        $this->storeTwoSeals();

        $anchor   = new RecordingAnchor;
        $verifier = $this->verifier($anchor);
        $head     = new AnchoredHead(1, (string) $this->seal(1)['seal_digest']);
        $context  = new VerificationContext($head, true, self::NO_GRACE, self::RUN_CLOCK, true);
        $first    = $this->report(1, verifier: $verifier, context: $context);
        $second   = $this->report(2, $first, $verifier, $context);
        $empty    = $this->report(1, verifier: $verifier, context: new VerificationContext(null, true, self::NO_GRACE, self::RUN_CLOCK, true));

        self::assertSame(AnchorStatus::ANCHORED, $first->anchoring);
        self::assertSame(AnchorStatus::UNANCHORED, $second->anchoring);
        self::assertSame(AnchorStatus::UNANCHORED, $empty->anchoring);
        self::assertSame([], $anchor->calls());
    }

    /**
     * An anchor that failed earlier in the run is not asked again: the segment
     * is unavailable though its receipt would confirm.
     *
     * @return void
     */
    public function testAnAnchorThatFailedEarlierIsNotAsked(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $anchor = new RecordingAnchor;

        $this->anchorSeal($anchor, 1);

        $calls  = count($anchor->calls());
        $report = $this->report(1, verifier: $this->verifier($anchor), context: new VerificationContext(null, false, self::NO_GRACE, self::RUN_CLOCK));

        self::assertSame(AnchorStatus::UNAVAILABLE, $report->anchoring);
        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertCount($calls, $anchor->calls());
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * A configured anchor's unanchored seal sealed at or after the start of the
     * grace awaits its first anchoring: it is still unanchored.
     *
     * @return void
     */
    public function testASealWithinTheGraceIsAwaitingAnchor(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $verifier = $this->verifier(new RecordingAnchor);

        foreach (['2026-11-01T12:45:00.000000Z', self::SEALED_INSTANT] as $graceFrom) {
            $report = $this->report(1, verifier: $verifier, context: new VerificationContext(null, true, $graceFrom, self::RUN_CLOCK));

            self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring, $graceFrom);
            self::assertTrue($report->awaitingAnchor, $graceFrom);
        }
    }

    /**
     * A seal sealed before the grace starts, by as little as a microsecond,
     * does not await its anchoring.
     *
     * @return void
     */
    public function testASealPastTheGraceIsNot(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $report = $this->report(1, verifier: $this->verifier(new RecordingAnchor), context: new VerificationContext(null, true, '2026-11-01T13:00:00.000001Z', self::RUN_CLOCK));

        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * With no anchor configured, no seal awaits an anchoring that will never
     * come, however recently it was sealed.
     *
     * @return void
     */
    public function testWithoutAnAnchorNoSealAwaits(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $report = $this->report(1, context: new VerificationContext(null, true, '2026-11-01T12:45:00.000000Z', self::RUN_CLOCK));

        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * An awaiting seal that the anchor's head contradicts is not awaiting: a
     * contradiction is never excused.
     *
     * @return void
     */
    public function testAContradictedSealIsNeverAwaiting(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $context = new VerificationContext(new AnchoredHead(1, self::OTHER_DIGEST), true, '2026-11-01T12:45:00.000000Z', self::RUN_CLOCK);
        $report  = $this->report(1, verifier: $this->verifier(new RecordingAnchor), context: $context);

        self::assertSame(AnchorStatus::CONTRADICTED, $report->anchoring);
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * Rows of `[column, value]`: a version or a signer this release does not
     * read.
     *
     * @return iterable<string, array{0: string, 1: int|string}>
     */
    public static function provideUnsupportedVersions(): iterable
    {
        yield from [
            'a later algorithm version' => ['algorithm_version', 2],
            'another signer'            => ['signer', 'ed25519'],
            'an empty signer'           => ['signer', ''],
        ];
    }

    /**
     * A seal of a version or signer this release does not read is unverifiable,
     * with no member row read and no digest recomputed.
     *
     * @param  string  $column
     * @param  int|string  $value
     * @return void
     */
    #[DataProvider('provideUnsupportedVersions')]
    public function testAnUnsupportedVersionIsUnverifiable(string $column, int|string $value): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $this->checkpoints()->where('sequence', 1)->update([$column => $value]);

        $seal       = $this->seal(1);
        $verifier   = $this->verifier();
        $statements = $this->countStatements(static fn (): SegmentReport => $verifier->verify($seal, 1, null, self::context()));
        $report     = $verifier->verify($seal, 1, null, self::context());

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::SEAL_VERSION, $report->finding);
        self::assertSame($this->seal(1)['id'], $report->firstBadId);
        self::assertSame(0, $report->members);
        self::assertNull($report->digest);
        self::assertSame(0, $statements);
    }

    /**
     * A seal that cannot be read as a seal is unverifiable, named by its id,
     * and nothing more is checked.
     *
     * @return void
     */
    public function testAMalformedSealIsUnverifiable(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $this->checkpoints()->where('sequence', 1)->update(['members_digest' => 'not a digest']);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::SEAL_MALFORMED, $report->finding);
        self::assertSame($this->seal(1)['id'], $report->firstBadId);
        self::assertSame(0, $report->members);
        self::assertNull($report->digest);
    }

    /**
     * A seal whose id is not a string has no id to name: the report names an
     * empty seal id and no first bad id.
     *
     * @return void
     */
    public function testASealWithoutAnIdIsNamedByNone(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $seal = $this->seal(1);

        $seal['id'] = null;

        $report = $this->verifier()->verify($seal, 1, null, self::context());

        self::assertSame(Finding::SEAL_MALFORMED, $report->finding);
        self::assertSame('', $report->sealId);
        self::assertNull($report->firstBadId);
    }

    /**
     * A seal whose sequence is not an integer is at sequence 0, which is never
     * the one expected, so it is a gap, outranking the seal it cannot read.
     *
     * @return void
     */
    public function testASealWithoutASequenceIsAGap(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $seal = $this->seal(1);

        $seal['sequence'] = 'first';

        foreach ([1, -1] as $expected) {
            $report = $this->verifier()->verify($seal, $expected, null, self::context());

            self::assertSame(0, $report->sequence);
            self::assertSame(Finding::SEQUENCE_GAP, $report->finding);
        }
    }

    /**
     * A seal of another log than the one configured is unverifiable, while
     * every other check passes.
     *
     * @return void
     */
    public function testAnotherLogIsUnverifiable(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        app(ConfigRepository::class)->set('audit-log.integrity.log_id', 'another-log');

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::LOG_MISMATCH, $report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * An edited stored digest is tampering, and the report keeps the digest
     * recomputed from the fields, never the stored one.
     *
     * @return void
     */
    public function testAStoredDigestEditIsTampered(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $digest = $this->seal(1)['seal_digest'];

        $this->checkpoints()->where('sequence', 1)->update(['seal_digest' => self::OTHER_DIGEST]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEAL_DIGEST, $report->finding);
        self::assertSame($digest, $report->digest);
    }

    /**
     * An edited signature is tampering, and a signature that no key could have
     * made is malformed.
     *
     * @return void
     */
    public function testASignatureEditIsTampered(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $this->checkpoints()->where('sequence', 1)->update(['signature' => self::OTHER_DIGEST]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEAL_SIGNATURE, $report->finding);

        $this->checkpoints()->where('sequence', 1)->update(['signature' => 'not a signature']);

        self::assertSame(Finding::SEAL_MALFORMED, $this->report(1)->finding);
    }

    /**
     * An edited stored digest and an edited signature together report the
     * digest, which comes first, so neither check hides the other.
     *
     * @return void
     */
    public function testAStoredDigestOutranksASignatureEdit(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $this->checkpoints()->where('sequence', 1)->update(['seal_digest' => self::OTHER_DIGEST, 'signature' => self::OTHER_DIGEST]);

        self::assertSame(Finding::SEAL_DIGEST, $this->report(1)->finding);
    }

    /**
     * A seal signed under a key the ring no longer holds is unverifiable, and
     * its members, signed under a key it does, still verify.
     *
     * @return void
     */
    public function testAnUnknownSealKeyIsUnverifiable(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');
        $this->storeEntries(2);
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2025');
        $this->sealAll();
        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::SEAL_KEY, $report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * A first seal re-signed with a link to a seal before it breaks the genesis
     * rule, though its digest and signature hold.
     *
     * @return void
     */
    public function testGenesisWithAPreviousFieldIsTampered(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        foreach ([['previous_id' => self::OTHER_ID], ['previous_digest' => self::OTHER_DIGEST]] as $link) {
            $this->resign(1, ['previous_id' => null, 'previous_digest' => null, ...$link]);

            $report = $this->report(1);

            self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
            self::assertSame(Finding::GENESIS, $report->finding);
        }
    }

    /**
     * A later seal re-signed without either link field breaks the genesis rule,
     * which outranks the broken chain it also is.
     *
     * @return void
     */
    public function testALaterSealWithoutPreviousFieldsIsTampered(): void
    {
        $this->storeTwoSeals();

        $first = $this->report(1);
        $seal  = $this->seal(2);
        $link  = ['previous_id' => $seal['previous_id'], 'previous_digest' => $seal['previous_digest']];

        foreach (array_keys($link) as $field) {
            $this->resign(2, array_replace($link, [$field => null]));

            self::assertSame(Finding::GENESIS, $this->report(2)->finding, $field);
            self::assertSame(Finding::GENESIS, $this->report(2, $first)->finding, $field);
            self::assertSame(IntegrityStatus::TAMPERED, $this->report(2, $first)->integrity, $field);
        }
    }

    /**
     * A seal deleted between two is a gap at the seal after it, which outranks
     * the broken chain it also is.
     *
     * @return void
     */
    public function testASequenceGapIsTampered(): void
    {
        $this->storeTwoSeals();
        $this->storeEntries(1, '2026-11-01 12:45:00');
        $this->sealAll();

        $first = $this->report(1);

        $this->checkpoints()->where('sequence', 2)->delete();

        $report = $this->report(3, $first, expected: 2);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEQUENCE_GAP, $report->finding);
        self::assertSame($this->seal(3)['id'], $report->firstBadId);
    }

    /**
     * A seal re-signed to link to another seal before it, by id or by digest,
     * is a broken chain, though its digest and signature hold.
     *
     * @return void
     */
    public function testABrokenLinkIsTampered(): void
    {
        $this->storeTwoSeals();

        $first = $this->report(1);
        $seal  = $this->seal(2);
        $link  = ['previous_id' => $seal['previous_id'], 'previous_digest' => $seal['previous_digest']];

        self::assertNull($this->report(2, $first)->finding);

        foreach (['previous_id' => self::OTHER_ID, 'previous_digest' => self::OTHER_DIGEST] as $field => $value) {
            $this->resign(2, array_replace($link, [$field => $value]));

            $report = $this->report(2, $first);

            self::assertSame(IntegrityStatus::TAMPERED, $report->integrity, $field);
            self::assertSame(Finding::CHAIN_BROKEN, $report->finding, $field);
            self::assertSame($seal['id'], $report->firstBadId, $field);
        }
    }

    /**
     * The chain is checked over recomputed digests, never stored ones: an
     * edited digest is `seal_digest` and the next seal's `chain_broken`.
     *
     * @return void
     */
    public function testTheChainIsOverRecomputedDigests(): void
    {
        $this->storeTwoSeals();

        $this->checkpoints()->where('sequence', 1)->update(['seal_digest' => self::OTHER_DIGEST]);
        $this->resign(2, ['previous_digest' => self::OTHER_DIGEST]);

        $first = $this->report(1);

        self::assertSame(Finding::SEAL_DIGEST, $first->finding);
        self::assertSame(Finding::CHAIN_BROKEN, $this->report(2, $first)->finding);
    }

    /**
     * A member whose entry is missing, with no prune record, makes the segment
     * incomplete, naming the entry; its member row is still found.
     *
     * @return void
     */
    public function testAMissingEntryIsIncomplete(): void
    {
        $ids = $this->storeEntries(3);

        $this->sealAll();

        $this->entries()->where('id', $ids[1])->delete();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::INCOMPLETE, $report->integrity);
        self::assertSame(Finding::MISSING_ENTRY, $report->finding);
        self::assertSame($ids[1], $report->firstBadId);
        self::assertSame(3, $report->members);
    }

    /**
     * An entry whose stored HMAC is not the one its seal recorded is tampering,
     * named at the entry.
     *
     * @return void
     */
    public function testAMemberHmacEditIsTampered(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->where('id', $ids[0])->update(['hmac' => self::OTHER_DIGEST]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MEMBER_HMAC, $report->finding);
        self::assertSame($ids[0], $report->firstBadId);
    }

    /**
     * A member row whose recorded HMAC is edited no longer gives the members
     * digest the seal signed.
     *
     * @return void
     */
    public function testAMemberRowEditBreaksTheMembersDigest(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->members()->where('entry_id', $ids[0])->update(['hmac' => self::OTHER_DIGEST]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MEMBERS_DIGEST, $report->finding);
        self::assertSame($this->seal(1)['id'], $report->firstBadId);
    }

    /**
     * An entry edited after it was sealed no longer matches its own signature.
     *
     * @return void
     */
    public function testAnEntryEditIsTampered(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->where('id', $ids[1])->update(['outcome' => 'denied']);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertSame($ids[1], $report->firstBadId);
    }

    /**
     * An entry signed under a key the ring no longer holds is unverifiable,
     * while the seal, under a key it does, verifies.
     *
     * @return void
     */
    public function testAnEntryUnderARemovedKeyIsUnverifiable(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2025');

        $ids = $this->storeEntries(2);

        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');
        $this->sealAll();
        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::ENTRY_KEY, $report->finding);
        self::assertSame(self::sorted($ids)[0], $report->firstBadId);
    }

    /**
     * An entry that cannot be read for verification is unverifiable, named at
     * the entry.
     *
     * @return void
     */
    public function testAMalformedEntryIsUnverifiable(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->where('id', $ids[0])->update(['integrity_version' => 7]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::ENTRY_MALFORMED, $report->finding);
        self::assertSame($ids[0], $report->firstBadId);
    }

    /**
     * A member row added to a seal makes its rows more than it counts and
     * breaks its members digest; the count is reported, and the row is found.
     *
     * @return void
     */
    public function testAnExtraMemberIsTampered(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $extra = $this->storeEntries(1, '2026-11-01 12:30:00')[0];
        $hmac  = $this->entries()->where('id', $extra)->value('hmac');

        $this->members()->insert(['checkpoint_id' => $this->seal(1)['id'], 'entry_id' => $extra, 'hmac' => $hmac]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MEMBER_COUNT, $report->finding);
        self::assertSame(3, $report->members);
    }

    /**
     * An extra member sorting after every sealed one still breaks the members
     * digest, since only the pairs the seal counts are kept.
     *
     * @return void
     */
    public function testAnExtraMemberSortingLastStillBreaksTheMembersDigest(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $extra = $this->storeEntryAt('2026-11-01 12:30:00', 'ffffffff-ffff-7fff-bfff-ffffffffffff');
        $hmac  = $this->entries()->where('id', $extra)->value('hmac');

        $this->members()->insert(['checkpoint_id' => $this->seal(1)['id'], 'entry_id' => $extra, 'hmac' => $hmac]);
        $this->checkpoints()->where('sequence', 1)->update(['member_count' => 2]);

        $seal = $this->seal(1);

        $seal['member_count'] = 2;

        $report = $this->verifier()->verify($seal, 1, null, self::context());

        self::assertSame(Finding::MEMBER_COUNT, $report->finding);
        self::assertSame(3, $report->members);
    }

    /**
     * A member row removed from a seal makes its rows fewer than it counts.
     *
     * @return void
     */
    public function testARemovedMemberIsTampered(): void
    {
        $ids = $this->storeEntries(3);

        $this->sealAll();

        $this->members()->where('entry_id', $ids[2])->delete();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MEMBER_COUNT, $report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * Members swapped between two seals keep both counts and every entry, and
     * break both members digests.
     *
     * @return void
     */
    public function testMembersSwappedBetweenSealsAreTampered(): void
    {
        $first = $this->storeEntries(2);
        $this->sealAll();
        $second = $this->storeEntries(2, '2026-11-01 12:30:00');
        $this->sealAll();

        $this->members()->where('entry_id', $first[0])->update(['checkpoint_id' => $this->seal(2)['id']]);
        $this->members()->where('entry_id', $second[0])->update(['checkpoint_id' => $this->seal(1)['id']]);

        foreach ([1, 2] as $sequence) {
            $report = $this->report($sequence);

            self::assertSame(IntegrityStatus::TAMPERED, $report->integrity, (string) $sequence);
            self::assertSame(Finding::MEMBERS_DIGEST, $report->finding, (string) $sequence);
            self::assertSame(2, $report->members, (string) $sequence);
        }
    }

    /**
     * A seal whose every entry is missing, under a valid prune record of
     * exactly that seal, is pruned, with no finding.
     *
     * @return void
     */
    public function testAValidPruneRecordIsPruned(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->whereIn('id', $ids)->delete();

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1))));

        self::assertSame(IntegrityStatus::PRUNED, $report->integrity);
        self::assertNull($report->finding);
        self::assertNull($report->firstBadId);
        self::assertSame(2, $report->members);
    }

    /**
     * A prune record whose signature fails is forged, which is tampering; the
     * missing entries are not excused.
     *
     * @return void
     */
    public function testAForgedPruneRecordIsTampered(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->whereIn('id', $ids)->delete();

        $forged = self::changed($this->pruneOf(1), ['signature' => self::OTHER_DIGEST]);
        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($forged)));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::PRUNE_RECORD, $report->finding);
        self::assertSame($this->seal(1)['id'], $report->firstBadId);
    }

    /**
     * Rows of `[log id, seal id, seal digest, member count]`: a signed prune
     * record bound to another value, `null` taking the seal's own.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: ?string, 3: ?int}>
     */
    public static function provideMismatchedPruneFields(): iterable
    {
        yield from [
            'another digest'       => [null, null, self::OTHER_DIGEST, null],
            'another log'          => ['another-log', null, null, null],
            'another seal'         => [null, self::OTHER_ID, null, null],
            'another member count' => [null, null, null, 3],
        ];
    }

    /**
     * A validly signed prune record that binds anything but this seal's log,
     * id, recomputed digest and member count is tampering.
     *
     * @param  ?string  $logId
     * @param  ?string  $sealId
     * @param  ?string  $digest
     * @param  ?int  $count
     * @return void
     */
    #[DataProvider('provideMismatchedPruneFields')]
    public function testAPruneRecordForAnotherDigestIsTampered(?string $logId, ?string $sealId, ?string $digest, ?int $count): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $this->entries()->whereIn('id', $ids)->delete();

        $seal = $this->seal(1);
        $logId  ??= app(SealSettings::class)->logId();
        $sealId ??= (string) $seal['id'];
        $digest ??= (string) $seal['seal_digest'];
        $count  ??= 2;
        $record = app(SealSigner::class)->signPrune(
            $logId,
            $sealId,
            $digest,
            $count,
            PruneBitmap::encode(range(0, $count - 1), $count),
            $count,
            self::OPERATION_ID,
            self::PRUNED_AT,
        );
        $ledger = new class ($record, (string) $seal['id']) implements PruneLedger {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
             * @param  string  $sealId
             */
            public function __construct(

                /** The record given for the seal, whatever it names. */
                private readonly PruneRecord $record,

                /** The seal the record is given for. */
                private readonly string $sealId,
            ) {}

            /**
             * The record, for the seal it is given for.
             *
             * @param  string  $sealId
             * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
             */
            #[\Override]
            public function recordsFor(string $sealId): array
            {
                return $sealId === $this->sealId ? [$this->record] : [];
            }
        };

        $report = $this->report(1, verifier: $this->verifier(prunes: $ledger));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::PRUNE_RECORD, $report->finding);
    }

    /**
     * A prune record signed under a key the ring no longer holds cannot be
     * checked, so the segment is unverifiable.
     *
     * @return void
     */
    public function testAPruneRecordUnderAnUnknownKeyIsUnverifiable(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');

        $ids = $this->storeEntries(2);

        $this->sealAll();
        $this->entries()->whereIn('id', $ids)->delete();
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2025');

        $record = $this->pruneOf(1);

        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($record)));

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::PRUNE_KEY, $report->finding);
        self::assertSame($this->seal(1)['id'], $report->firstBadId);
    }

    /**
     * A prune record that binds another seal is tampering even under a key the
     * ring does not hold: what it binds is checked first.
     *
     * @return void
     */
    public function testAMismatchedPruneRecordUnderAnUnknownKeyIsTampered(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();
        $this->entries()->whereIn('id', $ids)->delete();

        $record = self::changed($this->pruneOf(1), ['seal_digest' => self::OTHER_DIGEST, 'key_id' => 'gone']);
        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($record)));

        self::assertSame(Finding::PRUNE_RECORD, $report->finding);
    }

    /**
     * A valid prune record never excuses a seal whose signature fails.
     *
     * @return void
     */
    public function testPruningNeverExcusesABadSignature(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $record = $this->pruneOf(1);

        $this->entries()->whereIn('id', $ids)->delete();
        $this->checkpoints()->where('sequence', 1)->update(['signature' => self::OTHER_DIGEST]);

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($record)));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::SEAL_SIGNATURE, $report->finding);
    }

    /**
     * A valid prune record never excuses a broken chain.
     *
     * @return void
     */
    public function testPruningNeverExcusesABrokenChain(): void
    {
        $this->storeTwoSeals();

        $this->entries()->whereIn('id', $this->membersOf((string) $this->seal(2)['id']))->delete();

        $stranger = new SegmentReport(1, self::OTHER_ID, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, 1, null, null, self::OTHER_DIGEST);
        $report   = $this->report(2, $stranger, $this->verifier(prunes: $this->ledgerOf($this->pruneOf(2))));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::CHAIN_BROKEN, $report->finding);
    }

    /**
     * A valid prune record never excuses an anchor's head that contradicts the
     * seal, and the anchoring is reported apart from the prune.
     *
     * @return void
     */
    public function testPruningNeverExcusesAnAnchorContradiction(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();
        $this->entries()->whereIn('id', $ids)->delete();

        $verifier = $this->verifier(new RecordingAnchor, $this->ledgerOf($this->pruneOf(1)));
        $report   = $this->report(1, verifier: $verifier, context: new VerificationContext(new AnchoredHead(1, self::OTHER_DIGEST), true, self::NO_GRACE, self::RUN_CLOCK));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::ANCHOR_CONTRADICTION, $report->finding);
        self::assertSame(AnchorStatus::CONTRADICTED, $report->anchoring);
    }

    /**
     * The entries of a pruned seal that are still present are verified: one
     * intact leaves the segment pruned, and one edited is tampering.
     *
     * @return void
     */
    public function testAPresentEntryOfAPrunedSegmentIsStillVerified(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();
        $this->entries()->where('id', $ids[0])->delete();

        $verifier = $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$ids[0]])));

        self::assertSame(IntegrityStatus::PRUNED, $this->report(1, verifier: $verifier)->integrity);

        $this->entries()->where('id', $ids[1])->update(['event' => 'invoice.voided']);

        $report = $this->report(1, verifier: $verifier);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertSame($ids[1], $report->firstBadId);
    }

    /**
     * Members are placed bytewise, never in the engine's order: rows returned
     * in reverse still give the pruned member the record's position.
     *
     * @return void
     */
    public function testMembersAreOrderedBytewiseNotByTheEngine(): void
    {
        $sorted = self::sorted($this->storeEntries(4));

        $this->sealAll();
        $this->entries()->where('id', $sorted[0])->delete();

        $bytewise = $this->pruneOf(1, [$sorted[0]]);
        $engine   = $this->pruneOf(1, [$sorted[3]]);

        $reversed = $this->useReversingConnection();
        $pruned   = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($bytewise)));

        self::assertSame(IntegrityStatus::PRUNED, $pruned->integrity);
        self::assertEqualsCanonicalizing($sorted, $reversed->getArrayCopy());
        self::assertNotSame($sorted, $reversed->getArrayCopy());

        $misplaced = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($engine)));

        self::assertSame(IntegrityStatus::INCOMPLETE, $misplaced->integrity);
        self::assertSame(Finding::MISSING_ENTRY, $misplaced->finding);
        self::assertSame($sorted[0], $misplaced->firstBadId);
    }

    /**
     * Every missing member is kept: a record covering two of three leaves the
     * third `missing_entry`, and one covering all three is pruned.
     *
     * @return void
     */
    public function testEveryMissingIdIsKept(): void
    {
        $sorted = self::sorted($this->storeEntries(5));

        $this->sealAll();
        $this->entries()->whereIn('id', [$sorted[0], $sorted[2], $sorted[4]])->delete();

        $partial = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$sorted[0], $sorted[2]]))));

        self::assertSame(IntegrityStatus::INCOMPLETE, $partial->integrity);
        self::assertSame(Finding::MISSING_ENTRY, $partial->finding);
        self::assertSame($sorted[4], $partial->firstBadId);

        $whole = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$sorted[0], $sorted[2], $sorted[4]]))));

        self::assertSame(IntegrityStatus::PRUNED, $whole->integrity);
        self::assertSame(5, $whole->members);
    }

    /**
     * A seal whose members two prunes removed has two disjoint records that
     * cover them together, so it is pruned.
     *
     * @return void
     */
    public function testTwoCategoriesPrunedInOneSealArePruned(): void
    {
        $sorted = self::sorted($this->storeEntries(4));

        $this->sealAll();
        $this->entries()->whereIn('id', [$sorted[0], $sorted[3], $sorted[1]])->delete();

        $first  = $this->pruneOf(1, [$sorted[0], $sorted[3]]);
        $second = $this->pruneOf(1, [$sorted[1]], '01932b4e-a000-7000-8000-000000000002');
        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($first, $second)));

        self::assertSame(IntegrityStatus::PRUNED, $report->integrity);
        self::assertNull($report->finding);
        self::assertSame(4, $report->members);
        self::assertSame(IntegrityStatus::INCOMPLETE, $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($first)))->integrity);
    }

    /**
     * A member a valid record covers that is still there when read again is
     * `resurrected`, which is incomplete and never valid.
     *
     * @return void
     */
    public function testAMemberCoveredButPresentIsResurrected(): void
    {
        $sorted = self::sorted($this->storeEntries(3));

        $this->sealAll();

        $row = (array) $this->entries()->where('id', $sorted[1])->first();

        $this->entries()->whereIn('id', [$sorted[0], $sorted[1]])->delete();
        $this->entries()->insert($row);

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$sorted[0], $sorted[1]]))));

        self::assertSame(IntegrityStatus::INCOMPLETE, $report->integrity);
        self::assertSame(Finding::RESURRECTED, $report->finding);
        self::assertSame($sorted[1], $report->firstBadId);
    }

    /**
     * A member gone between the two reads was pruned in between, so the record
     * the ledger then gives accounts for it.
     *
     * @return void
     */
    public function testAMemberGoneBetweenTheReadsIsPruned(): void
    {
        $sorted = self::sorted($this->storeEntries(3));

        $this->sealAll();

        $record = $this->pruneOf(1, [$sorted[2]]);
        $ledger = self::askedLedger(function () use ($sorted): void {
            $this->entries()->where('id', $sorted[2])->delete();
        }, [$record]);

        $report = $this->report(1, verifier: $this->verifier(prunes: $ledger));

        self::assertSame(IntegrityStatus::PRUNED, $report->integrity);
        self::assertNull($report->finding);
        self::assertSame(3, $report->members);
    }

    /**
     * The ledger is asked even with no member missing, so a seal whose pruned
     * members were all inserted again is `resurrected`.
     *
     * @return void
     */
    public function testAFullyResurrectedSealIsResurrected(): void
    {
        $sorted = self::sorted($this->storeEntries(2));

        $this->sealAll();

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1))));

        self::assertSame(IntegrityStatus::INCOMPLETE, $report->integrity);
        self::assertSame(Finding::RESURRECTED, $report->finding);
        self::assertSame($sorted[0], $report->firstBadId);
        self::assertSame(IntegrityStatus::VALID, $this->report(1)->integrity);
    }

    /**
     * A ledger that cannot read a stored record of the seal is a forged record
     * of it, tampering at the seal, whether or not a member is missing.
     *
     * @return void
     */
    public function testAnUnreadableLedgerRecordIsTampered(): void
    {
        $ids = $this->storeEntries(2);

        $this->sealAll();

        $ledger = self::askedLedger(static function (): void {}, null);
        $intact = $this->report(1, verifier: $this->verifier(prunes: $ledger));

        self::assertSame(IntegrityStatus::TAMPERED, $intact->integrity);
        self::assertSame(Finding::PRUNE_RECORD, $intact->finding);
        self::assertSame($this->seal(1)['id'], $intact->firstBadId);

        $this->entries()->where('id', $ids[0])->delete();

        self::assertSame(Finding::PRUNE_RECORD, $this->report(1, verifier: $this->verifier(prunes: $ledger))->finding);
    }

    /**
     * The ledger is asked after the members are read, and the covered members
     * still present are read again in one statement on the writer.
     *
     * @return void
     */
    public function testTheLedgerIsAskedAfterTheMembersAreRead(): void
    {
        $sorted = self::sorted($this->storeEntries(3));

        $this->sealAll();

        $seal = $this->seal(1);

        /** @var \ArrayObject<int, string> $order */
        $order  = new \ArrayObject;
        $ledger = self::askedLedger(static function () use ($order): void {
            $order->append('ledger');
        }, [$this->pruneOf(1, [$sorted[0], $sorted[2]])]);

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($order): void {
            $order->append(strtolower($query->sql));
        });

        $report = $this->verifier(prunes: $ledger)->verify($seal, 1, null, self::context());
        $steps  = $order->getArrayCopy();

        self::assertSame(Finding::RESURRECTED, $report->finding);
        self::assertCount(3, $steps);
        self::assertStringContainsString('left join', $steps[0]);
        self::assertSame('ledger', $steps[1]);
        self::assertMatchesRegularExpression('/^select \S*id\S* from \S*' . preg_quote(EntrySettings::table(), '/') . '\S* where \S*id\S* in \(\?, \?\)$/', $steps[2]);
    }

    /**
     * A worse finding still wins over pruning and resurrection, and two valid
     * records setting one member are tampering.
     *
     * @return void
     */
    public function testAWorseFindingStillWins(): void
    {
        $sorted = self::sorted($this->storeEntries(3));

        $this->sealAll();
        $this->entries()->where('id', $sorted[2])->update(['event' => 'invoice.voided']);

        $edited = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$sorted[0]]))));

        self::assertSame(IntegrityStatus::TAMPERED, $edited->integrity);
        self::assertSame(Finding::ENTRY_HMAC, $edited->finding);

        $this->entries()->where('id', $sorted[2])->delete();
        $this->entries()->where('id', $sorted[0])->delete();

        $overlap = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$sorted[0], $sorted[2]]), $this->pruneOf(1, [$sorted[2]]))));

        self::assertSame(IntegrityStatus::TAMPERED, $overlap->integrity);
        self::assertSame(Finding::PRUNE_RECORD, $overlap->finding);
        self::assertSame($this->seal(1)['id'], $overlap->firstBadId);
    }

    /**
     * A record never excuses a membership that is not the one sealed: with a
     * member row removed, the segment is tampering, never pruned.
     *
     * @return void
     */
    public function testARecordCoversNothingOfAnUnauthenticatedMembership(): void
    {
        $sorted = self::sorted($this->storeEntries(3));

        $this->sealAll();

        $record = $this->pruneOf(1, [$sorted[0]]);

        $this->entries()->where('id', $sorted[0])->delete();
        $this->members()->where('entry_id', $sorted[2])->delete();

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($record)));

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MEMBER_COUNT, $report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * Without an anchor configured, every segment is unanchored, even one whose
     * receipt columns are set, and no anchor is asked.
     *
     * @return void
     */
    public function testWithoutAnAnchorEverySegmentIsUnanchored(): void
    {
        $this->storeTwoSeals();

        $this->checkpoints()->update(['anchor' => 'null', 'anchor_receipt' => '{"sequence":1}']);

        foreach ([1, 2] as $sequence) {
            self::assertSame(AnchorStatus::UNANCHORED, $this->report($sequence)->anchoring);
            self::assertSame(AnchorStatus::UNANCHORED, $this->report($sequence, context: new VerificationContext(null, false, self::NO_GRACE, self::RUN_CLOCK))->anchoring);
        }
    }

    /**
     * A receipt the anchor confirms is anchored, whatever order the database
     * returns the receipt's keys in.
     *
     * @return void
     */
    public function testAConfirmedReceiptIsAnchored(): void
    {
        $this->storeTwoSeals();

        $anchor = $this->diskAnchor();

        $this->anchorSeal($anchor, 1);
        $this->anchorSeal($anchor, 2);

        foreach ([1, 2] as $sequence) {
            $report = $this->report($sequence, verifier: $this->verifier($anchor));

            self::assertSame(AnchorStatus::ANCHORED, $report->anchoring, (string) $sequence);
            self::assertSame(IntegrityStatus::VALID, $report->integrity, (string) $sequence);
            self::assertFalse($report->awaitingAnchor);
        }
    }

    /**
     * Another seal's receipt replayed onto a seal does not confirm it: the seal
     * is unanchored, never anchored and never contradicted.
     *
     * @return void
     */
    public function testAReplayedReceiptIsUnanchored(): void
    {
        $this->storeTwoSeals();

        $anchor = $this->diskAnchor();

        $this->anchorSeal($anchor, 1);
        $this->anchorSeal($anchor, 2);

        $first = $this->seal(1);

        $this->checkpoints()->where('sequence', 2)->update(['anchor' => $first['anchor'], 'anchor_receipt' => $first['anchor_receipt']]);

        $report = $this->report(2, verifier: $this->verifier($anchor));

        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertSame(IntegrityStatus::VALID, $report->integrity);
    }

    /**
     * A receipt kept under another anchor's name is unanchored, and the
     * configured anchor is not asked to confirm it.
     *
     * @return void
     */
    public function testAReceiptOfAnotherAnchorIsUnanchored(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $anchor = new RecordingAnchor;

        $this->anchorSeal($anchor, 1);
        $this->checkpoints()->where('sequence', 1)->update(['anchor' => 'disk:0123456789abcdef']);

        $calls  = count($anchor->calls());
        $report = $this->report(1, verifier: $this->verifier($anchor));

        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertCount($calls, $anchor->calls());
    }

    /**
     * An anchor that fails when asked to confirm a receipt leaves the seal
     * unavailable, and is asked once.
     *
     * @return void
     */
    public function testAnUnavailableAnchorIsUnavailable(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $anchor = new RecordingAnchor;

        $this->anchorSeal($anchor, 1);
        $anchor->failing();

        $calls  = count($anchor->calls());
        $report = $this->report(1, verifier: $this->verifier($anchor));

        self::assertSame(AnchorStatus::UNAVAILABLE, $report->anchoring);
        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertSame(['confirms'], array_slice($anchor->calls(), $calls));
        self::assertFalse($report->awaitingAnchor);
    }

    /**
     * An anchor that fails even to give its name leaves the seal unavailable.
     *
     * @return void
     */
    public function testAnAnchorThatCannotNameItselfIsUnavailable(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $this->checkpoints()->update(['anchor' => 'recording', 'anchor_receipt' => '{"sequence":1}']);

        $anchor = \Mockery::mock(CheckpointAnchor::class);

        $anchor->shouldReceive('name')->andThrow(new \RuntimeException('The anchor is unavailable.'));
        $anchor->shouldNotReceive('confirms');

        self::assertSame(AnchorStatus::UNAVAILABLE, $this->report(1, verifier: $this->verifier($anchor))->anchoring);
    }

    /**
     * Rows of `[receipt]`: valid JSON, so every engine's JSON column holds it,
     * that is no object of string keys to scalars or `null`.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideMalformedReceipts(): iterable
    {
        yield from [
            'no receipt'      => [null],
            'a JSON null'     => ['null'],
            'a JSON string'   => ['"a receipt"'],
            'a JSON list'     => ['[1, 2]'],
            'a nested object' => ['{"sequence": {"of": 1}}'],
            'a nested list'   => ['{"sequence": [1]}'],
            'a numeric key'   => ['{"0": 1}'],
            'an empty array'  => ['[]'],
        ];
    }

    /**
     * A receipt that is not a JSON object of string keys and scalars or `null`
     * is unanchored, and the anchor is not asked to confirm it.
     *
     * @param  ?string  $receipt
     * @return void
     */
    #[DataProvider('provideMalformedReceipts')]
    public function testAMalformedReceiptIsUnanchored(?string $receipt): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $anchor = new RecordingAnchor;

        $this->checkpoints()->update(['anchor' => RecordingAnchor::NAME, 'anchor_receipt' => $receipt]);

        $report = $this->report(1, verifier: $this->verifier($anchor));

        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertSame([], $anchor->calls());
    }

    /**
     * An empty JSON object is a receipt, of no field, which the anchor is asked
     * about and does not confirm.
     *
     * @return void
     */
    public function testAnEmptyReceiptIsAsked(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $anchor = new RecordingAnchor;

        $this->checkpoints()->update(['anchor' => RecordingAnchor::NAME, 'anchor_receipt' => '{}']);

        self::assertSame(AnchorStatus::UNANCHORED, $this->report(1, verifier: $this->verifier($anchor))->anchoring);
        self::assertSame(['confirms'], $anchor->calls());
    }

    /**
     * The anchor's head at the seal's sequence with another digest contradicts
     * it, which is tampering; the same digest or another sequence does not.
     *
     * @return void
     */
    public function testARemoteDigestThatDiffersIsContradicted(): void
    {
        $this->storeTwoSeals();

        $verifier = $this->verifier(new RecordingAnchor);
        $report   = $this->report(2, verifier: $verifier, context: new VerificationContext(new AnchoredHead(2, self::OTHER_DIGEST), true, self::NO_GRACE, self::RUN_CLOCK));

        self::assertSame(AnchorStatus::CONTRADICTED, $report->anchoring);
        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::ANCHOR_CONTRADICTION, $report->finding);
        self::assertSame($this->seal(2)['id'], $report->firstBadId);

        $head  = new AnchoredHead(2, (string) $this->seal(2)['seal_digest']);
        $same  = $this->report(2, verifier: $verifier, context: new VerificationContext($head, true, self::NO_GRACE, self::RUN_CLOCK));
        $other = $this->report(1, verifier: $verifier, context: new VerificationContext(new AnchoredHead(2, self::OTHER_DIGEST), true, self::NO_GRACE, self::RUN_CLOCK));

        self::assertSame(AnchorStatus::UNANCHORED, $same->anchoring);
        self::assertSame(IntegrityStatus::VALID, $same->integrity);
        self::assertSame(AnchorStatus::UNANCHORED, $other->anchoring);
        self::assertSame(IntegrityStatus::VALID, $other->integrity);
    }

    /**
     * The boundary checks only the seal's own fields, with no statement: an
     * edited digest is found, a missing entry or member is not.
     *
     * @return void
     */
    public function testTheBoundaryChecksOnlyTheSealsOwnFields(): void
    {
        $ids = $this->storeEntries(3);

        $this->sealAll();
        $this->entries()->where('id', $ids[0])->delete();
        $this->members()->where('entry_id', $ids[1])->delete();
        $this->checkpoints()->update(['anchor' => RecordingAnchor::NAME, 'anchor_receipt' => '{"sequence":1}']);

        $seal       = $this->seal(1);
        $verifier   = $this->verifier(new RecordingAnchor);
        $statements = $this->countStatements(static fn (): SegmentReport => $verifier->boundary($seal));
        $report     = $verifier->boundary($seal);

        self::assertSame(0, $statements);
        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertSame(AnchorStatus::UNANCHORED, $report->anchoring);
        self::assertSame(0, $report->members);
        self::assertSame($seal['seal_digest'], $report->digest);
        self::assertSame(1, $report->sequence);
        self::assertSame($seal['id'], $report->sealId);

        $seal['seal_digest'] = self::OTHER_DIGEST;

        self::assertSame(Finding::SEAL_DIGEST, $verifier->boundary($seal)->finding);
    }

    /**
     * A boundary that cannot be read is reported with no digest, under its
     * stored sequence and id.
     *
     * @return void
     */
    public function testAMalformedBoundaryHasNoDigest(): void
    {
        $this->storeEntries(1);
        $this->sealAll();

        $seal = $this->seal(1);

        $seal['members_digest'] = 'not a digest';

        $report = $this->verifier()->boundary($seal);

        self::assertSame(Finding::SEAL_MALFORMED, $report->finding);
        self::assertNull($report->digest);
        self::assertSame(1, $report->sequence);
        self::assertSame($seal['id'], $report->sealId);
    }

    /**
     * The members and their entries are read in one statement, a left join on
     * the writer, and nothing else is read with no prune or anchor to ask.
     *
     * @return void
     */
    public function testOneStatementReadsTheMembersAndTheirEntries(): void
    {
        $this->storeEntries(5);
        $this->sealAll();

        $seal = $this->seal(1);

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        $report = $this->verifier()->verify($seal, 1, null, self::context());

        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertCount(1, $statements);
        self::assertStringContainsString('left join', $statements->getArrayCopy()[0]);
        self::assertStringContainsString(IntegrityTables::membersTable(), $statements->getArrayCopy()[0]);
        self::assertStringContainsString(EntrySettings::table(), $statements->getArrayCopy()[0]);
    }

    /**
     * The members are sorted bytewise before their digest is taken, so rows
     * returned in reverse order still verify.
     *
     * @return void
     */
    public function testTheMemberOrderIsSortedNotTrusted(): void
    {
        $ids = $this->storeEntries(4);

        $this->sealAll();

        $reversed = $this->useReversingConnection();
        $report   = $this->report(1);

        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertSame(4, $report->members);
        self::assertSame(array_reverse(self::sorted($ids)), $reversed->getArrayCopy());
    }

    /**
     * A segment holding a bundle beside plain entries, its artifact as written,
     * is valid, with every member row found.
     *
     * @return void
     */
    public function testASegmentWithAValidBundleIsValid(): void
    {
        $this->storeEntries(2);
        $this->seedBundle();
        $this->sealAll();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertNull($report->finding);
        self::assertSame(3, $report->members);
    }

    /**
     * A segment whose bundle's artifact was changed after sealing is tampered,
     * named at the bundle's entry, whether the artifact was edited or deleted.
     *
     * @return void
     */
    public function testATamperedArtifactMakesTheSegmentTampered(): void
    {
        $this->storeEntries(1);

        $edited  = $this->seedBundle();
        $deleted = $this->seedBundle(2);

        $this->sealAll();
        $this->tamperWithArtifact($edited, ['member_count' => 2]);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MANIFEST_MISMATCH, $report->finding);
        self::assertSame($edited, $report->firstBadId);

        $this->tamperWithArtifact($edited, ['member_count' => 3]);
        $this->artifactsTable()->where('entry_id', $deleted)->delete();

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MANIFEST_MISSING, $report->finding);
        self::assertSame($deleted, $report->firstBadId);
    }

    /**
     * Rows of `[change, finding]`: a change to a sealed bundle's artifact, by
     * name, and the finding of its own that it gives.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideArtifactChanges(): iterable
    {
        yield from [
            'swapped between entries' => ['swapped', Finding::MANIFEST_SWAPPED],
            'stored as another kind'  => ['kind', Finding::MANIFEST_WRONG_KIND],
            'members no manifest'     => ['malformed', Finding::MANIFEST_MALFORMED],
            'other canonical members' => ['tampered', Finding::MANIFEST_TAMPERED],
        ];
    }

    /**
     * A bundle's artifact swapped, of another kind or with other members makes
     * the segment tampered, at the earliest entry that gives it.
     *
     * @param  string  $change
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    #[DataProvider('provideArtifactChanges')]
    public function testEachNewArtifactFindingMakesTheSegmentTampered(string $change, Finding $finding): void
    {
        $this->storeEntries(1);

        $first  = $this->seedBundle();
        $second = $this->seedBundle();

        $this->sealAll();

        if ($change === 'swapped') {
            $this->swapArtifacts($first, $second);
        } else {
            $this->tamperWithArtifact($first, match ($change) {
                'kind'      => ['kind' => 'disclosure'],
                'malformed' => ['members' => RecordFactory::encrypter()->encryptString('not json')],
                default     => ['members' => RecordFactory::encrypter()->encryptString(Manifest::encode([[RecordFactory::MEMBER_TYPE, '1']]))],
            });
        }

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame($finding, $report->finding);
        self::assertSame($change === 'swapped' ? min($first, $second) : $first, $report->firstBadId);
    }

    /**
     * A segment whose bundle's members the application's keys cannot decrypt is
     * unverifiable, named at the bundle's entry.
     *
     * @return void
     */
    public function testAnUnreadableArtifactMakesTheSegmentUnverifiable(): void
    {
        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['members' => 'not a ciphertext']);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::MANIFEST_UNREADABLE, $report->finding);
        self::assertSame($entryId, $report->firstBadId);
    }

    /**
     * An unreadable artifact never hides a tampered one: the segment is
     * tampered, at the tampered bundle.
     *
     * @return void
     */
    public function testATamperedArtifactOutranksAnUnreadableOne(): void
    {
        $unreadable = $this->seedBundle();
        $tampered   = $this->seedBundle();

        $this->sealAll();
        $this->tamperWithArtifact($unreadable, ['members' => 'not a ciphertext']);
        $this->tamperWithArtifact($tampered, ['kind' => 'export']);

        $report = $this->report(1);

        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::MANIFEST_WRONG_KIND, $report->finding);
        self::assertSame($tampered, $report->firstBadId);
    }

    /**
     * A member whose entry does not verify is not trusted for its descriptor:
     * its artifact is never asked for, and its own status stands.
     *
     * @return void
     */
    public function testAMemberThatFailsItsHmacIsNotTrustedForItsDescriptor(): void
    {
        $entryId = $this->seedBundle();

        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');
        $this->sealAll();
        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        $seal       = $this->seal(1);
        $statements = $this->countStatements(fn (): SegmentReport => $this->verifier()->verify($seal, 1, null, self::context()));
        $report     = $this->report(1);

        self::assertSame(IntegrityStatus::UNVERIFIABLE, $report->integrity);
        self::assertSame(Finding::ENTRY_KEY, $report->finding);
        self::assertSame($entryId, $report->firstBadId);
        self::assertSame(1, $statements);
    }

    /**
     * A bundle's entry edited after sealing is tampered at the entry, and its
     * artifact is never read.
     *
     * @return void
     */
    public function testAnEditedBundleEntryIsNeverCheckedForItsArtifact(): void
    {
        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->entries()->where('id', $entryId)->update(['outcome' => 'denied']);

        $seal       = $this->seal(1);
        $statements = $this->countStatements(fn (): SegmentReport => $this->verifier()->verify($seal, 1, null, self::context()));
        $report     = $this->report(1);

        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertSame(1, $statements);
    }

    /**
     * A bundle's entry and artifact deleted under a valid prune record of the
     * seal are pruned, with no manifest finding.
     *
     * @return void
     */
    public function testAPrunedBundleEntryNeedsNoArtifact(): void
    {
        $this->storeEntries(1);

        $entryId = $this->seedBundle();

        $this->sealAll();
        $this->entries()->where('id', $entryId)->delete();
        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        $report = $this->report(1, verifier: $this->verifier(prunes: $this->ledgerOf($this->pruneOf(1, [$entryId]))));

        self::assertSame(IntegrityStatus::PRUNED, $report->integrity);
        self::assertNull($report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * A segment of bundles reads its members and entries in one statement and
     * its manifests in one more for their artifacts and one for their members.
     *
     * @return void
     */
    public function testASegmentsBundlesAddTwoStatements(): void
    {
        $this->storeEntries(2);
        $this->seedBundles(3);
        $this->sealAll();

        $seal = $this->seal(1);

        self::assertSame(3, $this->countStatements(fn (): SegmentReport => $this->verifier()->verify($seal, 1, null, self::context())));
    }

    /**
     * An entry whose envelope names a key with no key use for it is
     * `key_use_missing`, tampered, and the segment's other entries are not.
     *
     * @return void
     */
    public function testAnEnvelopeWithoutItsKeyUseIsMissing(): void
    {
        $kept     = $this->storeEnvelopeEntry(self::KEY_ID, '2026-11-01T12:00:00.000000Z');
        $stripped = $this->storeEnvelopeEntry(self::OTHER_KEY_ID, '2026-11-01T12:00:01.000000Z');

        $this->storeEntries(1);
        $this->sealAll();

        $this->keyUses()->where('entry_id', $stripped)->delete();

        $report = $this->report(1);

        self::assertSame(1, $this->keyUses()->where('entry_id', $kept)->count());
        self::assertSame(IntegrityStatus::TAMPERED, $report->integrity);
        self::assertSame(Finding::KEY_USE_MISSING, $report->finding);
        self::assertSame($stripped, $report->firstBadId);
    }

    /**
     * Key uses are asked for only of verified entries: one failing its HMAC is
     * reported for that, and no key use is read.
     *
     * @return void
     */
    public function testAnEntryThatFailsItsHmacIsNotAskedForItsKeyUses(): void
    {
        $entryId = $this->storeEnvelopeEntry(self::KEY_ID, '2026-11-01T12:00:00.000000Z');

        $this->sealAll();
        $this->keyUses()->where('entry_id', $entryId)->delete();
        $this->entries()->where('id', $entryId)->update(['subject_id' => '43']);

        $seal       = $this->seal(1);
        $statements = $this->listen();
        $report     = $this->verifier()->verify($seal, 1, null, self::context());

        self::assertSame(Finding::ENTRY_HMAC, $report->finding);
        self::assertCount(1, $statements);
    }

    /**
     * An envelope whose key is not a canonical UUID, such as a custom
     * encrypter's, is given no key use and needs none: its segment is valid.
     *
     * @return void
     */
    public function testANonUuidKeyNeedsNoKeyUse(): void
    {
        $this->storeEnvelopeEntry('vault:key-7', '2026-11-01T12:00:00.000000Z');
        $this->sealAll();

        self::assertSame(0, $this->keyUses()->count());
        self::assertSame(IntegrityStatus::VALID, $this->report(1)->integrity);
    }

    /**
     * A seal with no envelope reads no key use, and one with envelopes reads
     * them all in one statement through the entry index.
     *
     * @return void
     */
    public function testASealWithoutEnvelopesReadsNoKeyUse(): void
    {
        $this->storeEntries(3);
        $this->sealAll();

        $plain = $this->seal(1);

        $this->storeEnvelopeEntry(self::KEY_ID, '2026-11-01T12:30:00.000000Z');
        $this->storeEnvelopeEntry(self::OTHER_KEY_ID, '2026-11-01T12:30:01.000000Z');
        $this->sealAll();

        $sealed     = $this->seal(2);
        $previous   = $this->report(1);
        $statements = $this->listen();

        self::assertSame(IntegrityStatus::VALID, $this->verifier()->verify($plain, 1, null, self::context())->integrity);
        self::assertCount(1, $statements);

        $statements->exchangeArray([]);

        self::assertSame(IntegrityStatus::VALID, $this->verifier()->verify($sealed, 2, $previous, self::context())->integrity);
        self::assertCount(2, $statements);
        self::assertStringContainsString(KeyTables::keyUsesTable(), $statements->getArrayCopy()[1]);
    }

    /**
     * Store entries and seal them twice, two seals of two entries each.
     *
     * @return void
     */
    private function storeTwoSeals(): void
    {
        $this->storeEntries(2);
        $this->sealAll();
        $this->storeEntries(2, '2026-11-01 12:30:00');
        $this->sealAll();
    }

    /**
     * The report of the seal at the sequence, by default expected there, under
     * a verifier and context with no anchor, prune, remote or grace.
     *
     * @param  int  $sequence
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $previous
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier  $verifier
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\VerificationContext  $context
     * @param  ?int  $expected
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     */
    private function report(
        int $sequence,
        ?SegmentReport $previous = null,
        ?SegmentVerifier $verifier = null,
        ?VerificationContext $context = null,
        ?int $expected = null,
    ): SegmentReport {
        return ($verifier ?? $this->verifier())->verify($this->seal($sequence), $expected ?? $sequence, $previous, $context ?? self::context());
    }

    /**
     * Store an entry at the instant whose properties hold an envelope naming
     * the key, with its key uses, and return its id.
     *
     * @param  string  $keyId
     * @param  string  $at
     * @return string
     */
    private function storeEnvelopeEntry(string $keyId, string $at): string
    {
        $finaliser = new RecordFinaliser(FrozenClock::at($at), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured(['card' => ['v' => 1, 'k' => $keyId, 'c' => self::CIPHERTEXT]], occurredAt: $at));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }

    /**
     * Record every statement the storage connection runs from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function listen(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }

    /**
     * A query of the key uses table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function keyUses(): Builder
    {
        return DB::connection(StorageConnection::name())->table(KeyTables::keyUsesTable());
    }

    /**
     * A segment verifier from the container's collaborators, with the anchor
     * and prune ledger given, or none.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\PruneLedger  $prunes
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier
     */
    private function verifier(?CheckpointAnchor $anchor = null, ?PruneLedger $prunes = null): SegmentVerifier
    {
        return new SegmentVerifier(
            app(SealSigner::class),
            app(RecordSigner::class),
            app(RowCodec::class),
            app(SealSettings::class),
            $prunes ?? new NullPruneLedger,
            $anchor ?? new NullAnchor,
            app(DatabaseManager::class),
            app(ManifestVerifier::class),
        );
    }

    /**
     * The stored seal at the sequence, as its raw row.
     *
     * @param  int  $sequence
     * @return array<string, scalar|null>
     */
    private function seal(int $sequence): array
    {
        $seal = $this->checkpoints()->where('sequence', $sequence)->first();

        self::assertNotNull($seal, 'No seal is stored at sequence ' . $sequence . '.');

        /** @var array<string, scalar|null> */
        return (array) $seal;
    }

    /**
     * Rewrite the stored seal at the sequence with the changes, and store the
     * digest and signature of the result, as someone holding the key would.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $changes
     * @return void
     */
    private function resign(int $sequence, array $changes): void
    {
        $this->checkpoints()->where('sequence', $sequence)->update($changes);

        $envelope = SealEnvelope::fromRow($this->seal($sequence));

        $this->checkpoints()->where('sequence', $sequence)->update(['seal_digest' => $envelope->digest(), 'signature' => app(SealSigner::class)->sign($envelope)]);
    }

    /**
     * Anchor the stored seal at the sequence and keep the receipt beside it, as
     * anchoring does.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  int  $sequence
     * @return void
     */
    private function anchorSeal(CheckpointAnchor $anchor, int $sequence): void
    {
        $seal    = $this->seal($sequence);
        $receipt = $anchor->anchor(SealSummary::of(SealEnvelope::fromRow($seal), (string) $seal['seal_digest']));

        $this->checkpoints()->where('sequence', $sequence)->update([
            'anchor'         => $anchor->name(),
            'anchor_receipt' => json_encode($receipt, JSON_THROW_ON_ERROR),
            'anchored_at'    => '2026-11-01 13:05:00.000000',
        ]);
    }

    /**
     * A disk anchor of the configured log on a fake disk.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    private function diskAnchor(): DiskAnchor
    {
        return new DiskAnchor(Storage::fake(self::DISK), self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId());
    }

    /**
     * The valid prune record of the given members of the seal at the sequence,
     * every member by default, signed under the ring's key.
     *
     * @param  int  $sequence
     * @param  ?list<string>  $pruned
     * @param  string  $operationId
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    private function pruneOf(int $sequence, ?array $pruned = null, string $operationId = self::OPERATION_ID): PruneRecord
    {
        $seal      = $this->seal($sequence);
        $members   = self::sorted($this->membersOf((string) $seal['id']));
        $positions = array_keys(array_intersect($members, $pruned ?? $members));
        $bitmap    = PruneBitmap::encode($positions, (int) $seal['member_count']);

        return app(SealSigner::class)->signPrune(
            (string) $seal['log_id'],
            (string) $seal['id'],
            (string) $seal['seal_digest'],
            (int) $seal['member_count'],
            $bitmap,
            count($positions),
            $operationId,
            self::PRUNED_AT,
        );
    }

    /**
     * A prune ledger holding the records given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  ...$records
     * @return \Tests\Fixtures\Integrity\InMemoryPruneLedger
     */
    private function ledgerOf(PruneRecord ...$records): InMemoryPruneLedger
    {
        $ledger = new InMemoryPruneLedger;

        foreach ($records as $record) {
            $ledger->add($record);
        }

        return $ledger;
    }

    /**
     * A prune ledger that runs the work each time it is asked, then answers the
     * records, or refuses a stored record when given none.
     *
     * @param  \Closure(): void  $work
     * @param  ?list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>  $records
     * @return \SineMacula\Laravel\AuditLog\Contracts\PruneLedger
     */
    private static function askedLedger(\Closure $work, ?array $records): PruneLedger
    {
        return new class ($work, $records) implements PruneLedger {
            /**
             * Constructor.
             *
             * @param  \Closure(): void  $work
             * @param  ?list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>  $records
             */
            public function __construct(

                /** What runs each time the ledger is asked. */
                private readonly \Closure $work,

                /** The records of every seal, or `null` for a stored record that cannot be read. */
                private readonly ?array $records,
            ) {}

            /**
             * Run the work, then answer with the records, or refuse.
             *
             * @param  string  $sealId
             * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
             *
             * @throws \UnexpectedValueException
             */
            #[\Override]
            public function recordsFor(string $sealId): array
            {
                ($this->work)();

                return $this->records ?? throw new \UnexpectedValueException('A stored prune record\'s `pruned` must be text.');
            }
        };
    }

    /**
     * The record given with the fields given changed, its signature kept unless
     * one is given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @param  array<string, string>  $changes
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    private static function changed(PruneRecord $record, array $changes): PruneRecord
    {
        return PruneRecord::fromArray([...$record->toArray(), 'signature' => $record->signature, ...$changes]);
    }

    /**
     * How many statements the storage connection runs while the work runs.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $work
     * @return int
     */
    private function countStatements(\Closure $work): int
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        try {
            $work();

            return count($connection->getQueryLog());
        } finally {
            $connection->disableQueryLog();
        }
    }

    /**
     * Make the storage connection stream rows in reverse order, and return the
     * member entry ids it streamed, in that order.
     *
     * @return \ArrayObject<int, string>
     */
    private function useReversingConnection(): \ArrayObject
    {
        $config   = app(ConfigRepository::class);
        $testing  = DB::connection(StorageConnection::name());
        $streamed = new \ArrayObject;

        $config->set('database.connections.reversing', $config->get('database.connections.' . $testing->getName()));

        app(DatabaseManager::class)->extend('reversing', static fn (): Connection => self::reversing($testing, $streamed));

        $config->set('audit-log.storage.connection', 'reversing');

        return $streamed;
    }

    /**
     * A connection on the same database that streams rows in reverse order,
     * recording the member entry ids it streams.
     *
     * @param  \Illuminate\Database\Connection  $testing
     * @param  \ArrayObject<int, string>  $streamed
     * @return \Illuminate\Database\Connection
     */
    private static function reversing(Connection $testing, \ArrayObject $streamed): Connection
    {
        $config    = ['driver' => $testing->getDriverName(), 'name' => 'reversing'];
        $reversing = new class ($testing->getPdo(), $testing->getDatabaseName(), $testing->getTablePrefix(), $config) extends Connection {
            /** @var ?\ArrayObject<int, string> The member entry ids streamed, in the order returned. */
            public ?\ArrayObject $streamed = null;

            /**
             * Every row of the statement, in the reverse of the order the
             * database returned them.
             *
             * @param  string  $query
             * @param  array<array-key, mixed>  $bindings
             * @param  bool  $useReadPdo
             * @param  array<array-key, mixed>  $fetchUsing
             * @return \Generator<int, \stdClass>
             */
            #[\Override]
            public function cursor($query, $bindings = [], $useReadPdo = true, array $fetchUsing = []): \Generator // phpcs:ignore Squiz.Commenting.FunctionComment
            {
                $rows = array_reverse(iterator_to_array(parent::cursor($query, $bindings, $useReadPdo, $fetchUsing), false));

                array_map(fn (\stdClass $row) => $this->streamed?->append(is_string($row->member_entry_id ?? null) ? $row->member_entry_id : ''), $rows);

                yield from $rows;
            }
        };

        $reversing->streamed = $streamed;
        $reversing->setQueryGrammar($testing->getQueryGrammar());
        $reversing->setPostProcessor($testing->getPostProcessor());

        return $reversing;
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * A query of the seals table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }

    /**
     * A query of the members table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function members(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable());
    }

    /**
     * A context with no anchor's head, the anchor still asked, and a grace that
     * starts after every seal.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationContext
     */
    private static function context(): VerificationContext
    {
        return new VerificationContext(null, true, self::NO_GRACE, self::RUN_CLOCK);
    }

    /**
     * The ids sorted bytewise, as the members are.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        usort($ids, strcmp(...));

        return $ids;
    }
}
