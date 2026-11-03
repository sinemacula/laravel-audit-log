<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity\Anchors;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Filesystem\Filesystem as Files;
use Illuminate\Support\Facades\Storage;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use Tests\TestCase;

/**
 * Feature tests for the disk anchor, on a faked disk and on a local disk in a
 * temporary directory: the golden object at the golden path and its receipt;
 * that anchoring is idempotent and write-once, the marker written before the
 * object; that another digest for a sequence conflicts, even after a crash
 * between the marker and the object; which receipts confirm; how the head is
 * discovered and cross-checked against its marker; and that every path stays
 * inside the log's namespace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiskAnchor::class)]
final class DiskAnchorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The golden seal vectors. */
    private const string GOLDEN = __DIR__ . '/../../../Fixtures/Integrity/seal-v1.json';

    /** @var string The namespace the anchors write under. */
    private const string PATH = 'audit-log-anchors';

    /** @var string The log the anchors hold. */
    private const string LOG_ID = 'app-eu-1';

    /** @var string The faked disk's name. */
    private const string DISK = 'anchors';

    /** @var string The golden first seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The golden first seal's digest. */
    private const string DIGEST = '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6';

    /** @var string The marker of the golden first seal. */
    private const string MARKER = 'audit-log-anchors/app-eu-1/by-sequence/00000000000000000001';

    /** @var string The refusal of a path that could leave its namespace. */
    private const string UNCONTAINED = 'A disk anchor\'s path must be 1 to 191 characters of path segments of letters, digits, dots, underscores'
        . ' and hyphens, separated by single slashes, with no `.` or `..` segment.';

    /** @var ?string The temporary directory of the local disk, once one is made. */
    private ?string $root = null;

    /**
     * Delete the faked disk's files and the local disk's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $files = new Files;

        $files->deleteDirectory(storage_path('framework/testing/disks/' . self::DISK));

        if ($this->root !== null) {
            $files->deleteDirectory($this->root);
        }

        $this->root = null;

        parent::tearDown();
    }

    /**
     * Rows of `[disk]`: the faked disk and a local disk in a temporary
     * directory.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDisks(): iterable
    {
        yield from [
            'a faked disk' => ['fake'],
            'a local disk' => ['local'],
        ];
    }

    /**
     * The golden first seal is written in its golden bytes at the golden path,
     * after a marker holding its digest.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDisks')]
    public function testWritesTheGoldenObjectAtTheGoldenPath(string $kind): void
    {
        $disk = $this->disk($kind);

        self::anchorOn($disk)->anchor(self::goldenSummary());

        self::assertSame(self::golden('anchor_bytes'), $disk->get(self::golden('anchor_path')));
        self::assertSame(self::DIGEST, $disk->get(self::MARKER));
        self::assertSame(self::golden('anchor_path'), self::anchorOn($disk)->pathOf(self::goldenSummary()));
        self::assertSame([self::golden('anchor_path'), self::MARKER], self::filesOn($disk));
    }

    /**
     * The receipt is exactly the object's path and the SHA-256 of its bytes.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDisks')]
    public function testTheReceiptIsThePathAndTheHash(string $kind): void
    {
        $receipt = self::anchorOn($this->disk($kind))->anchor(self::goldenSummary());

        self::assertSame(['path' => self::golden('anchor_path'), 'sha256' => self::golden('anchor_sha256')], $receipt);
    }

    /**
     * Anchoring the same summary again returns the identical receipt and writes
     * nothing.
     *
     * @return void
     */
    public function testAnchoringTheSameSummaryAgainReturnsTheSameReceiptAndWritesNothing(): void
    {
        $writes = self::writes();
        $anchor = self::anchorOn(self::spyOn(Storage::fake(self::DISK), $writes));

        $first = $anchor->anchor(self::goldenSummary());

        self::assertCount(2, $writes);

        $second = $anchor->anchor(self::goldenSummary());

        self::assertSame($first, $second);
        self::assertCount(2, $writes);
    }

    /**
     * Another digest for an anchored sequence is a conflict naming the
     * sequence, and nothing of it is written.
     *
     * @return void
     */
    public function testADifferentDigestForAnAnchoredSequenceConflicts(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        $anchor->anchor(self::summary(4));

        try {
            $anchor->anchor(self::summary(4, str_repeat('e', 64)));
            self::fail('Expected another digest for the sequence to conflict.');
        } catch (AnchorConflictException $exception) {
            self::assertSame(4, $exception->sequence);
        }

        self::assertSame([$anchor->pathOf(self::summary(4)), 'audit-log-anchors/app-eu-1/by-sequence/00000000000000000004'], self::filesOn($disk));
        self::assertSame(self::summary(4)->sealDigest, $disk->get('audit-log-anchors/app-eu-1/by-sequence/00000000000000000004'));
    }

    /**
     * An object at the summary's path that holds the whole canonical summary of
     * another seal conflicts, with its marker or without it, and is never
     * replaced.
     *
     * @return void
     */
    public function testAnObjectWithOtherBytesConflicts(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);
        $object = $anchor->pathOf(self::goldenSummary());
        $other  = CanonicalEncoder::encode((new SealSummary(self::LOG_ID, 1, '01932b4e-9000-7000-8000-0000000000ff', self::DIGEST))->toArray());

        $disk->put($object, $other);

        foreach ([false, true] as $marked) {
            if ($marked) {
                $disk->put(self::MARKER, self::DIGEST);
            }

            try {
                $anchor->anchor(self::goldenSummary());
                self::fail('Expected an object with other bytes to conflict.');
            } catch (AnchorConflictException $exception) {
                self::assertSame(1, $exception->sequence);
            }

            self::assertSame($other, $disk->get($object));
        }
    }

    /**
     * Rows of `[path, bytes]`: a marker or an object that holds part of a
     * write, as another anchorer still making it leaves it to a reader.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function providePartialWrites(): iterable
    {
        yield from [
            'an empty marker' => [self::MARKER, ''],
            'half a marker'   => [self::MARKER, substr(self::DIGEST, 0, 32)],
            'an empty object' => ['audit-log-anchors/app-eu-1/00000000000000000001-' . self::DIGEST . '.json', ''],
            'half an object'  => ['audit-log-anchors/app-eu-1/00000000000000000001-' . self::DIGEST . '.json', '{"log_id":"app-eu-1","seal_dig'],
        ];
    }

    /**
     * A path that holds part of a write is the anchor unavailable for now,
     * never a conflict, so a concurrent anchorer's write in progress never
     * raises a tamper alarm; nothing there is replaced, and once the write is
     * whole the same summary anchors with no conflict.
     *
     * @param  string  $path
     * @param  string  $bytes
     * @return void
     */
    #[DataProvider('providePartialWrites')]
    public function testAPartialWriteIsUnavailableNotAConflict(string $path, string $bytes): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        if ($path !== self::MARKER) {
            $disk->put(self::MARKER, self::DIGEST);
        }

        $disk->put($path, $bytes);

        try {
            $anchor->anchor(self::goldenSummary());
            self::fail('Expected a partial write to make the anchor unavailable.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The anchor holds a partial write; it is read again on the next run.', $exception->getMessage());
        }

        self::assertSame($bytes, $disk->get($path));

        $disk->put($path, $path === self::MARKER ? self::DIGEST : self::golden('anchor_bytes'));

        self::assertSame($anchor->pathOf(self::goldenSummary()), $anchor->anchor(self::goldenSummary())['path']);
    }

    /**
     * Whatever is anchored, again or conflicting, each path is written once,
     * never over what was there, and the disk is asked for nothing but reads
     * and writes, so nothing is deleted, moved, copied or appended to: the
     * double fails any other call.
     *
     * @return void
     */
    public function testNeverOverwritesOrDeletes(): void
    {
        $writes = self::writes();
        $anchor = self::anchorOn(self::spyOn(Storage::fake(self::DISK), $writes));

        $anchor->anchor(self::summary(1));
        $anchor->anchor(self::summary(2));
        $anchor->anchor(self::summary(1));

        try {
            $anchor->anchor(self::summary(2, str_repeat('e', 64)));
            self::fail('Expected another digest for the sequence to conflict.');
        } catch (AnchorConflictException) {
            // The conflict is expected; what matters is what was written
        }

        $expected = [
            'put audit-log-anchors/app-eu-1/by-sequence/00000000000000000001',
            'put ' . $anchor->pathOf(self::summary(1)),
            'put audit-log-anchors/app-eu-1/by-sequence/00000000000000000002',
            'put ' . $anchor->pathOf(self::summary(2)),
        ];

        self::assertSame($expected, $writes->getArrayCopy());
    }

    /**
     * The marker is written before the object.
     *
     * @return void
     */
    public function testTheMarkerIsWrittenBeforeTheObject(): void
    {
        $writes = self::writes();

        self::anchorOn(self::spyOn(Storage::fake(self::DISK), $writes))->anchor(self::goldenSummary());

        self::assertSame(['put ' . self::MARKER, 'put ' . self::golden('anchor_path')], $writes->getArrayCopy());
    }

    /**
     * A marker left without its object, as a crash between the two writes
     * leaves it, is completed by the next anchoring of the same summary, which
     * writes the object alone and returns the usual receipt.
     *
     * @return void
     */
    public function testAMissingObjectIsCompletedByTheNextAnchoring(): void
    {
        $disk   = Storage::fake(self::DISK);
        $writes = self::writes();

        $disk->put(self::MARKER, self::DIGEST);

        $receipt = self::anchorOn(self::spyOn($disk, $writes))->anchor(self::goldenSummary());

        self::assertSame(['put ' . self::golden('anchor_path')], $writes->getArrayCopy());
        self::assertSame(self::golden('anchor_bytes'), $disk->get(self::golden('anchor_path')));
        self::assertSame(['path' => self::golden('anchor_path'), 'sha256' => self::golden('anchor_sha256')], $receipt);
    }

    /**
     * A marker left without its object still refuses another digest for its
     * sequence, so no second object is ever written for it.
     *
     * @return void
     */
    public function testAMarkerWrittenBeforeACrashStillRefusesAnotherDigest(): void
    {
        $disk = Storage::fake(self::DISK);

        $disk->put(self::MARKER, self::DIGEST);

        try {
            self::anchorOn($disk)->anchor(self::summary(1, str_repeat('e', 64)));
            self::fail('Expected the marker to refuse another digest.');
        } catch (AnchorConflictException $exception) {
            self::assertSame(1, $exception->sequence);
        }

        self::assertSame([self::MARKER], self::filesOn($disk));
    }

    /**
     * A write the disk refuses, of the marker or of the object, makes the
     * anchor unavailable, never a conflict.
     *
     * @return void
     */
    public function testAFailedWriteIsUnavailable(): void
    {
        foreach ([0, 1] as $succeeding) {
            $disk = self::spyOn(Storage::fake(self::DISK), self::writes(), $succeeding);

            try {
                self::anchorOn($disk)->anchor(self::goldenSummary());
                self::fail('Expected a refused write to make the anchor unavailable.');
            } catch (AnchorConflictException) {
                self::fail('A refused write is not a conflict.');
            } catch (\RuntimeException $exception) {
                self::assertSame('The anchor could not write to its disk.', $exception->getMessage(), "After {$succeeding} writes.");
            }
        }
    }

    /**
     * A path that is there and cannot be read is a failure, never read as
     * nothing being there, whether anchoring, confirming or discovering.
     *
     * @return void
     */
    public function testAnUnreadablePathIsAFailureNotAnAbsence(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn(self::spyOn($disk, self::writes(), unreadable: true));

        $receipt = self::anchorOn($disk)->anchor(self::goldenSummary());

        $calls = [
            'anchor'   => static fn () => $anchor->anchor(self::goldenSummary()),
            'confirms' => static fn () => $anchor->confirms(self::goldenSummary(), $receipt),
            'latest'   => static fn () => $anchor->latest(),
        ];

        foreach ($calls as $name => $call) {
            try {
                $call();
                self::fail("Expected {$name}() to fail on an unreadable path.");
            } catch (\RuntimeException $exception) {
                self::assertSame('The anchor could not read its disk.', $exception->getMessage(), $name);
            }
        }
    }

    /**
     * The anchor confirms the receipt it gave, whatever the order of its keys.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDisks')]
    public function testConfirmsItsOwnReceipt(string $kind): void
    {
        $anchor  = self::anchorOn($this->disk($kind));
        $receipt = $anchor->anchor(self::goldenSummary());

        self::assertTrue($anchor->confirms(self::goldenSummary(), $receipt));
        self::assertTrue($anchor->confirms(self::goldenSummary(), array_reverse($receipt, true)));
    }

    /**
     * The first seal's receipt never confirms the second seal's summary, even
     * with both anchored.
     *
     * @return void
     */
    public function testAReplayedReceiptDoesNotConfirm(): void
    {
        $anchor = self::anchorOn(Storage::fake(self::DISK));

        $first = $anchor->anchor(self::summary(1));

        $anchor->anchor(self::summary(2));

        self::assertFalse($anchor->confirms(self::summary(2), $first));
        self::assertFalse($anchor->confirms(self::summary(1, str_repeat('e', 64)), $first));
    }

    /**
     * Rows of `[receipt]`: receipts that are not exactly the one the golden
     * summary was given.
     *
     * @return iterable<string, array{0: array<string, scalar|null>}>
     */
    public static function provideOtherReceipts(): iterable
    {
        $path = 'audit-log-anchors/app-eu-1/00000000000000000001-329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6.json';
        $hash = '43a5f8ceb107717979f5c5179fe22278e529585c1d95e7d7f2e403f051e69a65';

        yield from [
            'another hash'         => [['path' => $path, 'sha256' => str_repeat('0', 64)]],
            'an upper-case hash'   => [['path' => $path, 'sha256' => strtoupper($hash)]],
            'another path'         => [['path' => 'audit-log-anchors/app-eu-1/other.json', 'sha256' => $hash]],
            'no hash'              => [['path' => $path]],
            'no path'              => [['sha256' => $hash]],
            'an extra key'         => [['path' => $path, 'sha256' => $hash, 'extra' => null]],
            'the hash as the path' => [['path' => $hash, 'sha256' => $path]],
            'nothing'              => [[]],
        ];
    }

    /**
     * A receipt that is not exactly the path and hash of the summary never
     * confirms it, though the object is there.
     *
     * @param  array<string, scalar|null>  $receipt
     * @return void
     */
    #[DataProvider('provideOtherReceipts')]
    public function testAReceiptWithAnotherHashDoesNotConfirm(array $receipt): void
    {
        $anchor = self::anchorOn(Storage::fake(self::DISK));

        $anchor->anchor(self::goldenSummary());

        self::assertFalse($anchor->confirms(self::goldenSummary(), $receipt));
    }

    /**
     * A receipt whose object is gone, or holds other bytes, does not confirm.
     *
     * @return void
     */
    public function testAMissingObjectDoesNotConfirm(): void
    {
        $disk    = Storage::fake(self::DISK);
        $anchor  = self::anchorOn($disk);
        $receipt = $anchor->anchor(self::goldenSummary());

        $disk->put(self::golden('anchor_path'), self::golden('anchor_bytes') . ' ');

        self::assertFalse($anchor->confirms(self::goldenSummary(), $receipt));

        $disk->delete(self::golden('anchor_path'));

        self::assertFalse($anchor->confirms(self::goldenSummary(), $receipt));
    }

    /**
     * Rows of `[seals anchored]`: logs of sizes either side of each doubling
     * the discovery probes, so the halving that follows is exercised at every
     * offset.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideLogSizes(): iterable
    {
        foreach ([1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 33, 100] as $size) {
            yield $size . ' seals' => [$size];
        }
    }

    /**
     * The head is the highest sequence anchored, with its digest, whatever the
     * size of the log.
     *
     * @param  int  $size
     * @return void
     */
    #[DataProvider('provideLogSizes')]
    public function testTheLatestIsTheHighestSequence(int $size): void
    {
        $anchor = self::anchorOn(Storage::fake(self::DISK));

        for ($sequence = 1; $sequence <= $size; $sequence++) {
            $anchor->anchor(self::summary($sequence));
        }

        $head = $anchor->latest();

        self::assertNotNull($head);
        self::assertSame($size, $head->sequence);
        self::assertSame(self::summary($size)->sealDigest, $head->digest);
        self::assertTrue($anchor->supportsDiscovery());
    }

    /**
     * Discovery works on a local disk as on a faked one.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDisks')]
    public function testDiscoveryWorksOnEveryDisk(string $kind): void
    {
        $anchor = self::anchorOn($this->disk($kind));

        foreach ([1, 2, 3] as $sequence) {
            $anchor->anchor(self::summary($sequence));
        }

        self::assertSame(3, $anchor->latest()?->sequence);
    }

    /**
     * Discovery never lists the anchor: it asks whether markers exist, about
     * twice per doubling of the log, and reads only the head's marker and
     * object, so its cost grows with the logarithm of the log, not the log.
     *
     * @return void
     */
    public function testDiscoveryProbesMarkersAndNeverLists(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        for ($sequence = 1; $sequence <= 1000; $sequence++) {
            $disk->put(sprintf('audit-log-anchors/app-eu-1/by-sequence/%020d', $sequence), self::summary($sequence)->sealDigest);
        }

        $anchor->anchor(self::summary(1000));

        $probes = 0;
        $spy    = \Mockery::mock(Filesystem::class);

        $spy->shouldReceive('exists')->andReturnUsing(static function (string $path) use ($disk, &$probes): bool {
            $probes++;

            return $disk->exists($path);
        });
        $spy->shouldReceive('get')->twice()->andReturnUsing(static fn (string $path): ?string => $disk->get($path));
        $spy->shouldNotReceive('files', 'allFiles', 'directories');

        self::assertSame(1000, self::anchorOn($spy)->latest()?->sequence);
        self::assertLessThanOrEqual(2 * 11 + 2, $probes);
    }

    /**
     * Rows of `[seals anchored, markers asked about in order]`: an empty log, a
     * log of one seal, and a log whose head falls between two doublings; the
     * last a log with a head asks about is its head's, as the marker is read.
     *
     * @return iterable<string, array{0: int, 1: list<int>}>
     */
    public static function provideProbes(): iterable
    {
        yield 'an empty log' => [0, [1]];
        yield 'one seal' => [1, [1, 2, 1]];
        yield 'five seals' => [5, [1, 2, 4, 8, 6, 5, 5]];
    }

    /**
     * Discovery probes the marker at 1 and then at each doubling until one is
     * missing, then halves the gap until it closes, and reads only the head's
     * marker and object: an empty log is asked about sequence 1 alone and
     * nothing is read.
     *
     * @param  int  $size
     * @param  list<int>  $expected
     * @return void
     */
    #[DataProvider('provideProbes')]
    public function testDiscoveryProbesAtEachDoublingThenHalves(int $size, array $expected): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        for ($sequence = 1; $sequence <= $size; $sequence++) {
            $anchor->anchor(self::summary($sequence));
        }

        $probed = [];
        $spy    = \Mockery::mock(Filesystem::class);

        $spy->shouldReceive('exists')->andReturnUsing(static function (string $path) use ($disk, &$probed): bool {
            if (str_contains($path, '/by-sequence/')) {
                $probed[] = (int) basename($path);
            }

            return $disk->exists($path);
        });
        $spy->shouldReceive('get')->times($size === 0 ? 0 : 2)->andReturnUsing(static fn (string $path): ?string => $disk->get($path));

        self::assertSame($size === 0 ? null : $size, self::anchorOn($spy)->latest()?->sequence);
        self::assertSame($expected, $probed);
    }

    /**
     * The head is ordered by its sequence alone, never by its digest, even a
     * digest that sorts below every padded sequence (protects against a
     * mutation that compares a digest with a sequence).
     *
     * @return void
     */
    public function testTheHeadIsOrderedBySequenceWhateverItsDigest(): void
    {
        $anchor = self::anchorOn(Storage::fake(self::DISK));

        $anchor->anchor(self::summary(1, str_repeat('f', 64)));
        $anchor->anchor(self::summary(2, str_repeat('0', 64)));

        $head = $anchor->latest();

        self::assertSame(2, $head?->sequence);
        self::assertSame(str_repeat('0', 64), $head->digest);
    }

    /**
     * A namespace with no marker, or only a first marker with no object yet,
     * has no head.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDisks')]
    public function testAnEmptyNamespaceHasNoHead(string $kind): void
    {
        $disk = $this->disk($kind);

        self::assertNull(self::anchorOn($disk)->latest());

        $disk->put(self::MARKER, self::DIGEST);

        self::assertNull(self::anchorOn($disk)->latest());
    }

    /**
     * The markers are authoritative: an object at the head's sequence that its
     * marker does not name, as only a writer bypassing the anchor could add, is
     * never the head's digest.
     *
     * @return void
     */
    public function testAnObjectTheMarkerDoesNotNameIsNotTheHead(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);
        $forged = self::summary(2, str_repeat('e', 64));

        $anchor->anchor(self::summary(1));
        $anchor->anchor(self::summary(2));

        $disk->put($anchor->pathOf($forged), CanonicalEncoder::encode($forged->toArray()));

        $head = $anchor->latest();

        self::assertSame(2, $head?->sequence);
        self::assertSame(self::summary(2)->sealDigest, $head->digest);
    }

    /**
     * A head whose marker names a digest with no object is the seal before it,
     * and the sequence still refuses any other digest, so a marker that was
     * rewritten never lets another seal be anchored there.
     *
     * @return void
     */
    public function testAMarkerNamingAnotherDigestHoldsTheSequence(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        foreach ([1, 2, 3] as $sequence) {
            $anchor->anchor(self::summary($sequence));
        }

        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000003', str_repeat('e', 64));

        self::assertSame(2, $anchor->latest()?->sequence);

        try {
            $anchor->anchor(self::summary(3));
            self::fail('Expected the marker to refuse the sequence\'s digest.');
        } catch (AnchorConflictException $exception) {
            self::assertSame(3, $exception->sequence);
        }
    }

    /**
     * An object with no marker beside it is not held by the anchor's markers,
     * and so is never the head.
     *
     * @return void
     */
    public function testAnObjectWithoutItsMarkerIsNotTheHead(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        $anchor->anchor(self::summary(1));
        $anchor->anchor(self::summary(2));

        $disk->delete('audit-log-anchors/app-eu-1/by-sequence/00000000000000000002');

        self::assertSame(1, $anchor->latest()?->sequence);
    }

    /**
     * A marker without its object, as a crash between the two writes leaves it,
     * is never the head.
     *
     * @return void
     */
    public function testAMarkerWithoutItsObjectIsNotTheHead(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        $anchor->anchor(self::summary(1));

        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000002', self::summary(2)->sealDigest);

        $head = $anchor->latest();

        self::assertSame(1, $head?->sequence);
        self::assertSame(self::summary(1)->sealDigest, $head->digest);
    }

    /**
     * Two markers at the top with neither object, which no run of the anchorer
     * leaves, is malformed, never a head further back.
     *
     * @return void
     */
    public function testTwoMarkersWithoutObjectsAreUnexpected(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        $anchor->anchor(self::summary(1));

        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000002', self::summary(2)->sealDigest);
        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000003', self::summary(3)->sealDigest);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The anchor\'s newest object is malformed.');

        $anchor->latest();
    }

    /**
     * Rows of `[bytes]`: newest objects that are not exactly the canonical
     * summary of their sequence and digest in the anchor's log.
     *
     * @return iterable<string, array{0: string}>
     *
     * @throws \UnexpectedValueException
     */
    public static function provideMalformedObjects(): iterable
    {
        $summary = self::summary(5)->toArray();

        yield from [
            'not JSON'             => ['not json'],
            'a JSON string'        => ['"seal"'],
            'no seal id'           => [CanonicalEncoder::encode(array_diff_key($summary, ['seal_id' => true]))],
            'a seal id not a UUID' => [CanonicalEncoder::encode(['seal_id' => 'not-a-uuid'] + $summary)],
            'an upper-case id'     => [CanonicalEncoder::encode(['seal_id' => strtoupper($summary['seal_id'])] + $summary)],
            'a numeric seal id'    => [CanonicalEncoder::encode(['seal_id' => 7] + $summary)],
            'another log'          => [CanonicalEncoder::encode(['log_id' => 'app-eu-2'] + $summary)],
            'another sequence'     => [CanonicalEncoder::encode(['sequence' => 4] + $summary)],
            'another digest'       => [CanonicalEncoder::encode(['seal_digest' => str_repeat('e', 64)] + $summary)],
            'another version'      => [CanonicalEncoder::encode(['v' => 2] + $summary)],
            'an extra key'         => [CanonicalEncoder::encode(['extra' => null] + $summary)],
            'not canonical'        => [json_encode($summary, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)],
            'a trailing newline'   => [CanonicalEncoder::encode($summary) . "\n"],
            'empty'                => [''],
        ];
    }

    /**
     * A newest object whose bytes are not exactly its canonical summary is
     * malformed, never a head.
     *
     * @param  string  $bytes
     * @return void
     */
    #[DataProvider('provideMalformedObjects')]
    public function testAMalformedNewestObjectIsUnexpected(string $bytes): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        foreach ([1, 2, 3, 4] as $sequence) {
            $anchor->anchor(self::summary($sequence));
        }

        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000005', self::summary(5)->sealDigest);
        $disk->put($anchor->pathOf(self::summary(5)), $bytes);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The anchor\'s newest object is malformed.');

        $anchor->latest();
    }

    /**
     * Rows of `[marker]`: newest markers that are not a whole digest, as a
     * write in progress leaves one to a reader.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePartialMarkers(): iterable
    {
        yield from [
            'empty'         => [''],
            'half a digest' => [substr(self::DIGEST, 0, 32)],
            'upper-case'    => [strtoupper(self::DIGEST)],
        ];
    }

    /**
     * A newest marker that is not a whole digest is a partial write, which
     * makes discovery fail for now, never a head and never an absence.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('providePartialMarkers')]
    public function testAPartialNewestMarkerFails(string $marker): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        $anchor->anchor(self::summary(1));

        $disk->put('audit-log-anchors/app-eu-1/by-sequence/00000000000000000002', $marker);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The anchor holds a partial write; it is read again on the next run.');

        $anchor->latest();
    }

    /**
     * The largest sequence a seal can have is found, the probe stopping there
     * rather than doubling past it.
     *
     * @return void
     */
    public function testTheLargestSequenceIsTheHead(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);

        for ($sequence = 1; $sequence < PHP_INT_MAX; $sequence = $sequence > intdiv(PHP_INT_MAX, 2) ? PHP_INT_MAX : $sequence << 1) {
            $disk->put(sprintf('audit-log-anchors/app-eu-1/by-sequence/%020d', $sequence), self::summary($sequence)->sealDigest);
        }

        $anchor->anchor(self::summary(PHP_INT_MAX));

        self::assertSame(PHP_INT_MAX, $anchor->latest()?->sequence);
    }

    /**
     * A file whose name is not a marker, or that sits below the log's
     * namespace, is not a seal and never the head.
     *
     * @return void
     */
    public function testIgnoresFilesThatAreNotSeals(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = self::anchorOn($disk);
        $digest = self::summary(2)->sealDigest;

        $anchor->anchor(self::summary(1));

        $files = [
            'README',
            '00000000000000000002-' . $digest . '.json',
            'by-sequence/2',
            'by-sequence/00000000000000000002.tmp',
            'nested/by-sequence/00000000000000000002',
        ];

        foreach ($files as $file) {
            $disk->put('audit-log-anchors/app-eu-1/' . $file, $digest);
        }

        self::assertSame(1, $anchor->latest()?->sequence);
    }

    /**
     * The anchor discovers only its own log, never another under the same path,
     * even one whose id starts with its own.
     *
     * @return void
     */
    public function testDiscoversOnlyItsOwnLog(): void
    {
        $disk  = Storage::fake(self::DISK);
        $other = new DiskAnchor($disk, self::DISK, self::PATH, 'app-eu-1x');

        self::anchorOn($disk)->anchor(self::summary(1));

        foreach ([1, 2] as $sequence) {
            $other->anchor(new SealSummary('app-eu-1x', $sequence, self::SEAL_ID, self::DIGEST));
        }

        self::assertSame(1, self::anchorOn($disk)->latest()?->sequence);
        self::assertSame(2, $other->latest()?->sequence);
        self::assertNull((new DiskAnchor($disk, self::DISK, self::PATH, 'app'))->latest());
    }

    /**
     * A summary of another log is refused by every method that takes one.
     *
     * @return void
     */
    public function testRefusesASummaryOfAnotherLog(): void
    {
        $disk    = Storage::fake(self::DISK);
        $anchor  = self::anchorOn($disk);
        $summary = new SealSummary('app-eu-2', 1, self::SEAL_ID, self::DIGEST);

        $calls = [
            'anchor'   => static fn () => $anchor->anchor($summary),
            'confirms' => static fn () => $anchor->confirms($summary, ['path' => 'x', 'sha256' => 'y']),
            'pathOf'   => static fn () => $anchor->pathOf($summary),
        ];

        foreach ($calls as $name => $call) {
            try {
                $call();
                self::fail("Expected {$name}() to refuse a summary of another log.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A disk anchor holds one log; the seal names another.', $exception->getMessage(), $name);
            }
        }

        self::assertSame([], $disk->allFiles());
    }

    /**
     * The name is `disk:` and the first 16 hex of the SHA-256 of the disk's
     * name and the path: one location gives one name, another disk or another
     * path another name.
     *
     * @return void
     */
    public function testItsNameIsItsLocation(): void
    {
        $disk = Storage::fake(self::DISK);
        $name = self::anchorOn($disk)->name();

        self::assertSame('disk:' . substr(hash('sha256', "anchors\0audit-log-anchors"), 0, 16), $name);
        self::assertSame($name, (new DiskAnchor($disk, self::DISK, self::PATH, 'app-eu-2'))->name());
        self::assertNotSame($name, (new DiskAnchor($disk, self::DISK, 'audit-log-anchors/moved', self::LOG_ID))->name());
        self::assertNotSame($name, (new DiskAnchor($disk, 's3', self::PATH, self::LOG_ID))->name());
        self::assertNotSame((new DiskAnchor($disk, 'a', 'b/c', self::LOG_ID))->name(), (new DiskAnchor($disk, 'a/b', 'c', self::LOG_ID))->name());
        self::assertSame(21, strlen($name));
    }

    /**
     * Everything the anchor writes, and every path it gives, is inside the
     * log's namespace under its path.
     *
     * @return void
     */
    public function testEveryPathStaysInsideTheNamespace(): void
    {
        $disk   = Storage::fake(self::DISK);
        $anchor = new DiskAnchor($disk, self::DISK, 'tenants/eu/anchors', self::LOG_ID);

        foreach ([1, 2, PHP_INT_MAX] as $sequence) {
            $anchor->anchor(self::summary($sequence));

            self::assertStringStartsWith('tenants/eu/anchors/app-eu-1/', $anchor->pathOf(self::summary($sequence)));
        }

        self::assertCount(6, $disk->allFiles());

        foreach ($disk->allFiles() as $file) {
            self::assertStringStartsWith('tenants/eu/anchors/app-eu-1/', $file);
        }
    }

    /**
     * Rows of `[path]`: paths that could leave their namespace or that no
     * setting accepts.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncontainedPaths(): iterable
    {
        yield from [
            'empty'            => [''],
            'the parent'       => ['../x'],
            'a parent inside'  => ['a/../b'],
            'the current'      => ['.'],
            'a current inside' => ['a/./b'],
            'absolute'         => ['/a'],
            'a trailing slash' => ['a/'],
            'a doubled slash'  => ['a//b'],
            'a space'          => ['a b'],
            'a backslash'      => ['a\b'],
            '192 characters'   => [str_repeat('a', 192)],
        ];
    }

    /**
     * A disk anchor made directly is held to the path the settings accept, so
     * no path can leave its namespace.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideUncontainedPaths')]
    public function testRefusesAPathThatCouldLeaveItsNamespace(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::UNCONTAINED);

        new DiskAnchor(Storage::fake(self::DISK), self::DISK, $path, self::LOG_ID);
    }

    /**
     * The longest path accepted is 191 characters.
     *
     * @return void
     */
    public function testAcceptsAPathOfTheLongestLength(): void
    {
        $anchor = new DiskAnchor(Storage::fake(self::DISK), self::DISK, str_repeat('a', 191), self::LOG_ID);

        self::assertStringStartsWith(str_repeat('a', 191) . '/app-eu-1/', $anchor->pathOf(self::goldenSummary()));
    }

    /**
     * Rows of `[log id]`: log ids that are not a single path segment of the log
     * id grammar.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedLogIds(): iterable
    {
        yield from [
            'empty'            => [''],
            'the parent'       => ['..'],
            'a slash'          => ['a/b'],
            'a leading hyphen' => ['-a'],
            '65 characters'    => [str_repeat('a', 65)],
        ];
    }

    /**
     * A disk anchor made directly is held to the log id grammar, so the log it
     * lists is one segment under its path.
     *
     * @param  string  $logId
     * @return void
     */
    #[DataProvider('provideMalformedLogIds')]
    public function testRefusesALogIdThatIsNoPathSegment(string $logId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A disk anchor\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');

        new DiskAnchor(Storage::fake(self::DISK), self::DISK, self::PATH, $logId);
    }

    /**
     * The disk of the kind: the faked disk, or a local disk in a temporary
     * directory this test deletes.
     *
     * @param  string  $kind
     * @return \Illuminate\Contracts\Filesystem\Filesystem
     *
     * @throws \Random\RandomException
     */
    private function disk(string $kind): Filesystem
    {
        if ($kind === 'fake') {
            return Storage::fake(self::DISK);
        }

        $this->root = sys_get_temp_dir() . '/audit-log-anchors-' . bin2hex(random_bytes(8));

        return Storage::build(['driver' => 'local', 'root' => $this->root]);
    }

    /**
     * A disk anchor on the disk, under the default path, for the golden log.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    private static function anchorOn(Filesystem $disk): DiskAnchor
    {
        return new DiskAnchor($disk, self::DISK, self::PATH, self::LOG_ID);
    }

    /**
     * The disk behind a double that answers only what a disk anchor may ask of
     * it, whether a path exists, its bytes and a write, each from the disk, so
     * any other call, a listing, a deletion or a move say, fails the test. It
     * records every write as `put <path>`, marking one to a path that was
     * already there, refuses every write after the given number, and when
     * unreadable, answers every read as a failed one.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @param  \ArrayObject<int, string>  $writes
     * @param  int  $succeeding
     * @param  bool  $unreadable
     * @return \Illuminate\Contracts\Filesystem\Filesystem
     */
    private static function spyOn(Filesystem $disk, \ArrayObject $writes, int $succeeding = PHP_INT_MAX, bool $unreadable = false): Filesystem
    {
        $spy = \Mockery::mock(Filesystem::class);

        $spy->shouldReceive('exists')->andReturnUsing(static fn (string $path): bool => $disk->exists($path));
        $spy->shouldReceive('get')->andReturnUsing(static fn (string $path): ?string => $unreadable ? null : $disk->get($path));

        $spy->shouldReceive('put')->andReturnUsing(static function (string $path, string $contents) use ($disk, $writes, &$succeeding): bool {
            $writes->append('put ' . $path . ($disk->exists($path) ? ' over what was there' : ''));

            return $succeeding-- > 0 && $disk->put($path, $contents);
        });

        return $spy;
    }

    /**
     * An empty record of writes.
     *
     * @return \ArrayObject<int, string>
     */
    private static function writes(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> */
        return new \ArrayObject;
    }

    /**
     * Every file on the disk, sorted.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @return list<string>
     */
    private static function filesOn(Filesystem $disk): array
    {
        $files = $disk->allFiles();

        sort($files);

        return $files;
    }

    /**
     * The summary of the golden first seal.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSummary
     */
    private static function goldenSummary(): SealSummary
    {
        return new SealSummary(self::LOG_ID, 1, self::SEAL_ID, self::DIGEST);
    }

    /**
     * A summary in the golden log at the sequence, under the digest given or a
     * digest of the sequence.
     *
     * @param  int  $sequence
     * @param  ?string  $digest
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSummary
     */
    private static function summary(int $sequence, ?string $digest = null): SealSummary
    {
        $sealId = sprintf('01932b4e-9000-7000-8000-%012x', $sequence % 0xFFFFFFFFFFFF);

        return new SealSummary(self::LOG_ID, $sequence, $sealId, $digest ?? hash('sha256', 'seal ' . $sequence));
    }

    /**
     * A golden value.
     *
     * @param  string  $key
     * @return string
     *
     * @throws \JsonException
     */
    private static function golden(string $key): string
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
        $value  = is_array($golden) ? ($golden[$key] ?? null) : null;

        self::assertIsString($value, "The golden `{$key}` is not a string.");

        return $value;
    }
}
