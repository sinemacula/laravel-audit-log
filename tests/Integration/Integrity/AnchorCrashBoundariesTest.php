<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Filesystem\Filesystem as Disk;
use Illuminate\Database\Query\Builder;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\KillingAnchor;
use Tests\Fixtures\Integrity\KillingDisk;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Integration tests for an anchorer killed by `SIGKILL` at every boundary of an
 * anchoring, on a disk anchor every process shares and on whichever engine the
 * suite runs against: before the anchor is written to, between the disk
 * anchor's marker and its object, after the anchor has kept a summary and
 * before its receipt is returned, and after the receipt is recorded. Anchoring
 * is idempotent, so the next run of `audit-log:seal` anchors every seal left
 * unanchored, completes an object a marker waits for, records for a kept
 * summary the receipt it would have had, and never meets a conflict of its own
 * making; a strict verification then finds every seal anchored and the anchor's
 * head the last seal. A marker left without its object still refuses another
 * digest for its sequence, so a seal rewritten meanwhile by someone holding the
 * key is caught at its next anchoring.
 *
 * Every test starts from three seals, the first anchored and the others not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Anchorer::class)]
#[CoversClass(DiskAnchor::class)]
#[CoversClass(SealCommand::class)]
final class AnchorCrashBoundariesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every seal of a test is made and anchored. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every verification runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var string The disk the anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string The namespace on the disk the anchor writes under. */
    private const string PATH = 'audit-log-anchors';

    /** @var string The time the rewritten second seal claims it was made at. */
    private const string REWRITTEN_AT = '2026-11-01 13:00:01.000000';

    /** @var ?string The directory the anchor's disk is rooted at. */
    private ?string $anchorRoot = null;

    /** @var ?\Illuminate\Contracts\Filesystem\Filesystem The disk every process shares, under the anchor. */
    private ?Disk $disk = null;

    /**
     * Register the command, stop the clock, bind a disk anchor every process
     * shares and no prune ledger, and make three seals, anchoring the first.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new SealCommand);

        CarbonImmutable::setTestNow(self::SEALED_AT);

        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->anchorRoot = rtrim($this->childFile(''), '/') . '-anchors';
        $this->disk       = Storage::build(['driver' => 'local', 'root' => $this->anchorRoot]);

        app()->instance(CheckpointAnchor::class, $this->diskAnchor());

        $this->storeEntries(3);

        self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());

        $this->storeEntries(2, '2026-11-01 12:10:00.000000');
        $this->sealer()->seal();
        $this->storeEntries(2, '2026-11-01 12:20:00.000000');
        $this->sealer()->seal();

        self::assertSame([true, false, false], $this->anchored());
    }

    /**
     * Put the clock back, remove the anchor's disk, and remove what the
     * children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if ($this->anchorRoot !== null) {
            (new Filesystem)->deleteDirectory($this->anchorRoot);
        }

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * An anchorer killed before the second seal reaches the anchor leaves it
     * and the third unanchored, with nothing written for either and no failure
     * recorded, and the next run anchors both.
     *
     * @return void
     */
    public function testACrashBeforeTheRemoteWriteLeavesTheSealUnanchoredAndTheNextRunAnchorsIt(): void
    {
        $this->crashAnchoring(fn (): CheckpointAnchor => new KillingAnchor($this->diskAnchor(), killBefore: true));

        self::assertSame([true, false, false], $this->anchored());
        self::assertSame(self::sorted($this->filesOf(1)), $this->files());
        self::assertSame([null, null, null], $this->errorClasses());

        $this->assertRecovers();
    }

    /**
     * An anchorer killed once the anchor has kept the second seal's summary,
     * before its receipt is returned, leaves the seal unanchored locally with
     * its marker and object on the disk; the next run anchors it again, writing
     * nothing, and records exactly the receipt that object proves.
     *
     * @return void
     */
    public function testACrashAfterTheRemoteWriteBeforeTheReceiptRecoversWithTheSameReceipt(): void
    {
        $this->crashAnchoring(fn (): CheckpointAnchor => new KillingAnchor($this->diskAnchor(), killAfter: true));

        $object = $this->diskAnchor()->pathOf($this->summaryOf(2));
        $bytes  = $this->disk()->get($object);

        self::assertSame([true, false, false], $this->anchored());
        self::assertSame(self::sorted([...$this->filesOf(1), ...$this->filesOf(2)]), $this->files());
        self::assertIsString($bytes);

        $this->assertRecovers();

        self::assertSame(['path' => $object, 'sha256' => hash('sha256', $bytes)], $this->receiptOf(2));
        self::assertSame($bytes, $this->disk()->get($object));
    }

    /**
     * An anchorer killed between the second seal's marker and its object leaves
     * the marker alone; the next run finds it holding the seal's own digest,
     * writes the object, and anchors the seal and the third.
     *
     * @return void
     */
    public function testACrashBetweenTheMarkerAndItsObjectIsCompleted(): void
    {
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(new KillingDisk($this->disk(), 1)));

        $marker = $this->markerOf(2);

        self::assertSame([true, false, false], $this->anchored());
        self::assertSame(self::sorted([...$this->filesOf(1), $marker]), $this->files());
        self::assertSame($this->summaryOf(2)->sealDigest, $this->disk()->get($marker));

        $this->assertRecovers();

        self::assertSame($this->summaryOf(2)->sealDigest, $this->disk()->get($marker));
    }

    /**
     * A marker left without its object by a killed anchorer still refuses
     * another digest for its sequence. The second seal rewritten meanwhile by
     * someone holding the key, and the third chained onto it again, verify
     * locally, and the marker is invisible to discovery, so a verification that
     * is not strict passes; the next anchoring conflicts at the second seal,
     * records the conflict on it, writes nothing, anchors nothing after it, and
     * alarms, and a strict verification fails.
     *
     * @return void
     */
    public function testACrashBetweenTheMarkerAndItsObjectStillRefusesAnotherDigest(): void
    {
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(new KillingDisk($this->disk(), 1)));

        $original = $this->summaryOf(2)->sealDigest;

        $this->resign(2, ['sealed_at' => self::REWRITTEN_AT]);
        $this->resign(3, ['previous_digest' => $this->summaryOf(2)->sealDigest]);

        $forged = $this->verify();

        self::assertNotSame($original, $this->summaryOf(2)->sealDigest);
        self::assertSame([['valid', 'anchored'], ['valid', 'unanchored'], ['valid', 'unanchored']], $forged[1]);
        self::assertFalse($forged[0]->fails(false));

        /** @var \ArrayObject<int, ?string> $alarms */
        $alarms = new \ArrayObject;

        Event::listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event->finding);
        });

        self::assertSame(1, Artisan::call('audit-log:seal'));
        self::assertStringContainsString('The anchor holds another digest for seal 2', Artisan::output());
        self::assertSame(['anchor_conflict'], $alarms->getArrayCopy());
        self::assertSame([true, false, false], $this->anchored());
        self::assertSame([null, AnchorConflictException::class, null], $this->errorClasses());
        self::assertSame(self::sorted([...$this->filesOf(1), $this->markerOf(2)]), $this->files());
        self::assertSame($original, $this->disk()->get($this->markerOf(2)));
        self::assertTrue($this->verify()[0]->fails(true));
    }

    /**
     * An anchorer killed once it has recorded the second seal's receipt keeps
     * that seal anchored, its progress still naming the first; the next run
     * leaves the receipt as it was, anchors the third, and moves its progress
     * to it.
     *
     * @return void
     */
    public function testACrashAfterTheReceiptKeepsItAnchored(): void
    {
        $id = $this->summaryOf(2)->sealId;

        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(), '/^update \S*audit_log_checkpoints\S* set .*anchored_at.* where \S*id\S* = \'' . $id . '\'$/');

        $anchoring = $this->anchoringOf(2);

        self::assertSame([true, true, false], $this->anchored());
        self::assertSame(1, $this->progressOf(IntegrityProgress::ANCHOR_LAST));

        $this->assertRecovers();

        self::assertSame($anchoring, $this->anchoringOf(2));
        self::assertSame(3, $this->progressOf(IntegrityProgress::ANCHOR_LAST));
    }

    /**
     * Anchorers killed one after another at every boundary, with no run between
     * them to recover, leave nothing the next run takes for a conflict: before
     * the anchor is written to, between the second seal's marker and its
     * object, once its object is written and before its receipt is returned,
     * once its receipt is recorded, and once the third seal's object is
     * written. The next run anchors every seal, no failure is recorded on any,
     * and each sequence has one marker and one object.
     *
     * @return void
     */
    public function testNoCrashLeavesAConflict(): void
    {
        $second = $this->summaryOf(2)->sealId;

        $this->crashAnchoring(fn (): CheckpointAnchor => new KillingAnchor($this->diskAnchor(), killBefore: true));
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(new KillingDisk($this->disk(), 1)));
        $this->crashAnchoring(fn (): CheckpointAnchor => new KillingAnchor($this->diskAnchor(), killAfter: true));
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(), '/^update \S*audit_log_checkpoints\S* set .* where \S*id\S* = \'' . $second . '\'$/');
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(new KillingDisk($this->disk(), 2)));

        self::assertSame([true, true, false], $this->anchored());
        self::assertSame(self::sorted([...$this->filesOf(1), ...$this->filesOf(2), ...$this->filesOf(3)]), $this->files());

        $this->assertRecovers();

        self::assertSame([null, null, null], $this->errorClasses());
        self::assertSame(self::sorted([...$this->filesOf(1), ...$this->filesOf(2), ...$this->filesOf(3)]), $this->files());
    }

    /**
     * A marker a killed anchorer left without its object is never the anchor's
     * head: a verification before the next run reports the first seal as the
     * head, matching the local seal there, and every segment `valid`; it
     * passes, and a strict one fails on the seals left unanchored past their
     * grace.
     *
     * @return void
     */
    public function testAVerificationBetweenTheMarkerAndItsObjectSeesTheObjectBefore(): void
    {
        $this->crashAnchoring(fn (): CheckpointAnchor => $this->diskAnchor(new KillingDisk($this->disk(), 1)));

        [$summary, $segments] = $this->verify();

        self::assertSame([AnchorStatus::ANCHORED, 1], [$summary->remote, $summary->remoteHead]);
        self::assertSame([['valid', 'anchored'], ['valid', 'unanchored'], ['valid', 'unanchored']], $segments);
        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));

        $this->assertRecovers();
    }

    /**
     * Put the database on a file SQLite can share across a fork.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }

    /**
     * Anchor the pending seals in a child, on the anchor it makes, and assert
     * the child was killed, by the anchor or at the statement the pattern
     * matches once it has run.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  ?string  $killAfter
     * @return void
     */
    private function crashAnchoring(\Closure $anchor, ?string $killAfter = null): void
    {
        $this->assertKilled($this->runChild(static function () use ($anchor): void {
            app()->instance(CheckpointAnchor::class, $anchor());
            app(Anchorer::class)->anchorPending();
        }, killAfter: $killAfter));
    }

    /**
     * Run `audit-log:seal` and assert it succeeds and leaves every seal
     * anchored: the sequences contiguous from 1, and on verification, strict,
     * every segment `valid` and anchored, the anchor's head the last seal, and
     * nothing recorded as a failure.
     *
     * @return void
     */
    private function assertRecovers(): void
    {
        self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());

        $count = count($this->seals());

        self::assertSame(range(1, $count), array_map(static fn (array $seal): int => (int) $seal['sequence'], $this->seals()));
        self::assertSame(array_fill(0, $count, true), $this->anchored());

        [$summary, $segments] = $this->verify();

        self::assertSame(array_fill(0, $count, ['valid', 'anchored']), $segments);
        self::assertSame([AnchorStatus::ANCHORED, $count], [$summary->remote, $summary->remoteHead]);
        self::assertFalse($summary->fails(true));
    }

    /**
     * Verify the whole log at the time verifications run, and return the
     * summary and the integrity and anchoring of each segment, in order.
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary, 1: list<array{0: string, 1: string}>}
     */
    private function verify(): array
    {
        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        $segments = new \ArrayObject;

        try {
            $summary = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($segments): void {
                $segments->append([$report->integrity->value, $report->anchoring->value]);
            });
        } finally {
            CarbonImmutable::setTestNow(self::SEALED_AT);
        }

        /** @var list<array{0: string, 1: string}> $reports */
        $reports = $segments->getArrayCopy();

        return [$summary, $reports];
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

        $envelope = SealEnvelope::fromRow((array) $this->checkpoints()->where('sequence', $sequence)->first());

        $this->checkpoints()->where('sequence', $sequence)->update(['seal_digest' => $envelope->digest(), 'signature' => app(SealSigner::class)->sign($envelope)]);
    }

    /**
     * A disk anchor on the disk given, or on the disk every process shares, at
     * the one location every test anchors to.
     *
     * @param  ?\Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    private function diskAnchor(?Disk $disk = null): DiskAnchor
    {
        return new DiskAnchor($disk ?? $this->disk(), self::DISK, self::PATH, app(SealSettings::class)->logId());
    }

    /**
     * The disk every process shares.
     *
     * @return \Illuminate\Contracts\Filesystem\Filesystem
     */
    private function disk(): Disk
    {
        assert($this->disk instanceof Disk);

        return $this->disk;
    }

    /**
     * The summary of the stored seal at the sequence, under its stored digest.
     *
     * @param  int  $sequence
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSummary
     */
    private function summaryOf(int $sequence): SealSummary
    {
        $seal = (array) $this->checkpoints()->where('sequence', $sequence)->first();

        return SealSummary::of(SealEnvelope::fromRow($seal), (string) $seal['seal_digest']);
    }

    /**
     * The object and the marker the anchor writes for the stored seal at the
     * sequence.
     *
     * @param  int  $sequence
     * @return list<string>
     */
    private function filesOf(int $sequence): array
    {
        return [$this->diskAnchor()->pathOf($this->summaryOf($sequence)), $this->markerOf($sequence)];
    }

    /**
     * The path of the marker of the sequence.
     *
     * @param  int  $sequence
     * @return string
     */
    private function markerOf(int $sequence): string
    {
        return sprintf('%s/%s/by-sequence/%020d', self::PATH, app(SealSettings::class)->logId(), $sequence);
    }

    /**
     * Every file on the anchor's disk, in byte order.
     *
     * @return list<string>
     */
    private function files(): array
    {
        return self::sorted($this->disk()->allFiles());
    }

    /**
     * Whether each stored seal is anchored, by sequence.
     *
     * @return list<bool>
     */
    private function anchored(): array
    {
        return array_map(static fn (array $seal): bool => $seal['anchored_at'] !== null && $seal['anchor_receipt'] !== null, $this->seals());
    }

    /**
     * The class of the failure recorded on each stored seal, by sequence.
     *
     * @return list<?string>
     */
    private function errorClasses(): array
    {
        return array_map(static fn (array $seal): ?string => $seal['anchor_error_class'] === null ? null : (string) $seal['anchor_error_class'], $this->seals());
    }

    /**
     * The four anchor columns of the stored seal at the sequence, as the engine
     * returns them.
     *
     * @param  int  $sequence
     * @return array<string, scalar|null>
     */
    private function anchoringOf(int $sequence): array
    {
        $seal = $this->seals()[$sequence - 1];

        return array_intersect_key($seal, array_flip(['anchor', 'anchor_receipt', 'anchored_at', 'anchor_error_class']));
    }

    /**
     * The receipt recorded on the stored seal at the sequence, its keys in
     * order, since an engine may keep them in another.
     *
     * @param  int  $sequence
     * @return array<string, scalar|null>
     */
    private function receiptOf(int $sequence): array
    {
        /** @var array<string, scalar|null> $receipt */
        $receipt = json_decode((string) $this->seals()[$sequence - 1]['anchor_receipt'], true, flags: JSON_THROW_ON_ERROR);

        ksort($receipt);

        return $receipt;
    }

    /**
     * The sequence the progress under the name records, or `null` when there is
     * none.
     *
     * @param  string  $name
     * @return ?int
     */
    private function progressOf(string $name): ?int
    {
        $sequence = app(IntegrityProgress::class)->get($name)['sequence'] ?? null;

        return $sequence === null ? null : (int) $sequence;
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
     * The paths in byte order.
     *
     * @param  array<array-key, string>  $paths
     * @return list<string>
     */
    private static function sorted(array $paths): array
    {
        $sorted = array_values($paths);

        sort($sorted, SORT_STRING);

        return $sorted;
    }
}
