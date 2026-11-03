<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\TableBackedPruneLedger;
use Tests\TestCase;

/**
 * Integration tests for a prune killed by `SIGKILL` at every boundary, on
 * whichever engine the suite runs against. The prune is this test's own, as a
 * lifecycle prune would be: it deletes a whole segment's entries and writes the
 * segment's signed record to a table-backed ledger in one transaction on the
 * maintenance connection, keeping the checkpoint and its members. A kill before
 * that transaction commits leaves the segment `valid`, and a kill after it
 * leaves the segment `pruned`, so it is never half pruned. A prune that is not
 * atomic is caught either way: entries deleted without their record are
 * `incomplete`, and a record written without its deletion excuses nothing, so
 * every entry is still verified. After every kill a run of `audit-log:seal` and
 * a verification find every seal anchored, whatever its integrity.
 *
 * Every test starts from three anchored seals of two entries each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class PruneBoundariesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every seal of a test is made and anchored. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every verification runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var string The id of the prune operation every prune record names. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When every prune runs. */
    private const string PRUNED_AT = '2026-11-01T13:30:00.000000Z';

    /** @var string The disk the anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string The delete of the segment's entries. */
    private const string DELETE = '/^delete from \S*audit_log_entries/';

    /** @var string The insert of the segment's prune record. */
    private const string RECORD = '/^insert into \S*audit_test_prune_records/';

    /** @var string The commit of the prune's transaction, the first of the prune. */
    private const string COMMIT = '/^commit$/';

    /** @var ?string The directory the anchor's disk is rooted at. */
    private ?string $anchorRoot = null;

    /**
     * Register the command, stop the clock, bind a disk anchor every process
     * shares and the table-backed prune ledger, and make three seals of two
     * entries each, anchoring every one.
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

        $this->anchorRoot = rtrim($this->childFile(''), '/') . '-anchors';

        $disk   = Storage::build(['driver' => 'local', 'root' => $this->anchorRoot]);
        $ledger = app(TableBackedPruneLedger::class);

        $ledger->createTable();

        app()->instance(PruneLedger::class, $ledger);
        app()->instance(CheckpointAnchor::class, new DiskAnchor($disk, self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId()));

        foreach (['12:00', '12:01', '12:02'] as $minute) {
            $this->storeEntries(2, '2026-11-01 ' . $minute . ':00.000000');

            self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());
        }

        self::assertCount(3, $this->seals());
    }

    /**
     * Put the clock back, drop the prune ledger's table, remove the anchor's
     * disk, and remove what the children shared once the migrations have rolled
     * back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        app(TableBackedPruneLedger::class)->dropTable();

        if ($this->anchorRoot !== null) {
            (new Filesystem)->deleteDirectory($this->anchorRoot);
        }

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Rows of `[the statement the prune is killed after, or none for a kill as
     * it commits]`: every boundary before its transaction commits.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideUncommittedBoundaries(): iterable
    {
        yield from [
            'after its entries are deleted' => [self::DELETE],
            'after its record is written'   => [self::RECORD],
            'as it commits'                 => [null],
        ];
    }

    /**
     * A prune killed before its transaction commits leaves the segment's
     * entries and no record, so every segment is `valid` and anchored; the
     * prune made again then commits, and the segment is `pruned`.
     *
     * @param  ?string  $after
     * @return void
     */
    #[DataProvider('provideUncommittedBoundaries')]
    public function testACrashBeforeThePruneCommitsLeavesTheSegmentValid(?string $after): void
    {
        $this->assertKilled($this->runChild(function () use ($after): void {
            if ($after === null) {
                Event::listen(TransactionCommitting::class, static function (): void {
                    self::killThisProcess();
                });
            }

            $this->prune(2);
        }, killAfter: $after));

        self::assertSame([2, false], [$this->entriesLeftOf(2), $this->hasRecord(2)]);

        $this->assertSegments(['valid', 'valid', 'valid']);

        $this->prune(2);

        $this->assertSegments(['valid', 'pruned', 'valid']);
    }

    /**
     * A prune killed once its transaction has committed leaves the segment's
     * entries deleted, its record written, and its checkpoint and members kept,
     * so the segment is `pruned`, still anchored, and the run passes, strict.
     *
     * @return void
     */
    public function testACommittedPruneIsPruned(): void
    {
        $members = $this->membersOf($this->sealIdOf(2));

        $this->assertKilled($this->runChild(fn () => $this->prune(2), killAfter: self::COMMIT));

        self::assertSame([0, true], [$this->entriesLeftOf(2), $this->hasRecord(2)]);
        self::assertSame($members, $this->membersOf($this->sealIdOf(2)));

        $this->assertSegments(['valid', 'pruned', 'valid']);
    }

    /**
     * A prune that deletes the segment's entries before it writes their record,
     * in two transactions, killed between them, leaves the entries missing with
     * nothing to account for them: the segment is `incomplete`, found missing
     * at its first member, and still anchored, since integrity and anchoring
     * are separate, and the run fails.
     *
     * @return void
     */
    public function testADeletionWithoutItsRecordIsIncomplete(): void
    {
        $first = $this->membersOf($this->sealIdOf(2))[0];

        $this->assertKilled($this->runChild(function (): void {
            [$members, $record] = $this->pruneOf(2);

            $this->maintenance()->table(EntrySettings::table())->whereIn('id', $members)->delete();
            $this->maintenance()->transaction(static fn () => app(TableBackedPruneLedger::class)->record($record));
        }, killBefore: self::RECORD));

        self::assertSame([0, false], [$this->entriesLeftOf(2), $this->hasRecord(2)]);

        $summary = $this->assertSegments(['valid', 'incomplete', 'valid'], false);

        self::assertSame(['missing_entry', $first], [$summary->firstFinding?->value, $summary->firstBadId]);
    }

    /**
     * A prune that writes the segment's record before it deletes the entries,
     * killed between them, leaves the record and every entry: the record
     * accounts only for an entry that is missing, so the segment is `valid`,
     * and an entry of it changed after is still `tampered`, found at that
     * entry.
     *
     * @return void
     */
    public function testARecordWithoutItsDeletionStillVerifiesEveryEntry(): void
    {
        $this->assertKilled($this->runChild(function (): void {
            [$members, $record] = $this->pruneOf(2);

            app(TableBackedPruneLedger::class)->record($record);

            $this->maintenance()->table(EntrySettings::table())->whereIn('id', $members)->delete();
        }, killBefore: self::DELETE));

        self::assertSame([2, true], [$this->entriesLeftOf(2), $this->hasRecord(2)]);

        $this->assertSegments(['valid', 'valid', 'valid']);

        $changed = $this->membersOf($this->sealIdOf(2))[1];

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $changed)->update(['event' => 'invoice.forged']);

        $summary = $this->assertSegments(['valid', 'tampered', 'valid'], false);

        self::assertSame(['entry_hmac', $changed], [$summary->firstFinding?->value, $summary->firstBadId]);
    }

    /**
     * A prune of the last seal that commits before its process is killed keeps
     * the checkpoint, so the next seal still chains onto it and is anchored:
     * the pruned segment is `pruned` and every other `valid`.
     *
     * @return void
     */
    public function testAPrunedHeadIsStillExtendedAndAnchored(): void
    {
        $this->assertKilled($this->runChild(fn () => $this->prune(3), killAfter: self::COMMIT));

        $this->storeEntries(2, '2026-11-01 12:03:00.000000');

        $this->assertSegments(['valid', 'valid', 'pruned', 'valid']);

        $seals = $this->seals();

        self::assertSame($seals[2]['seal_digest'], $seals[3]['previous_digest']);
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
     * Run `audit-log:seal`, which succeeds, then verify the whole log, and
     * assert each segment has the integrity given, in order, and is anchored,
     * the anchor's head the last seal, and the run fails exactly when it is not
     * meant to pass, strict.
     *
     * @param  list<string>  $integrity
     * @param  bool  $passes
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function assertSegments(array $integrity, bool $passes = true): VerificationSummary
    {
        self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());

        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        $segments = new \ArrayObject;

        try {
            $summary = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($segments): void {
                $segments->append([$report->integrity->value, $report->anchoring->value]);
            });
        } finally {
            CarbonImmutable::setTestNow(self::SEALED_AT);
        }

        $count = count($integrity);

        self::assertSame(array_map(static fn (string $status): array => [$status, 'anchored'], $integrity), $segments->getArrayCopy());
        self::assertSame($count, $summary->remoteHead);
        self::assertSame(range(1, $count), array_map(static fn (array $seal): int => (int) $seal['sequence'], $this->seals()));
        self::assertSame(!$passes, $summary->fails(true));

        return $summary;
    }

    /**
     * Prune the seal at the sequence as one transaction on the maintenance
     * connection: delete its entries and write its signed record.
     *
     * @param  int  $sequence
     * @return void
     */
    private function prune(int $sequence): void
    {
        [$members, $record] = $this->pruneOf($sequence);

        $this->maintenance()->transaction(static function (Connection $connection) use ($members, $record): void {
            $connection->table(EntrySettings::table())->whereIn('id', $members)->delete();

            app(TableBackedPruneLedger::class)->record($record);
        });
    }

    /**
     * The entry ids the seal at the sequence holds and its prune record, signed
     * under the ring's signing key.
     *
     * @param  int  $sequence
     * @return array{0: list<string>, 1: \SineMacula\Laravel\AuditLog\Integrity\PruneRecord}
     */
    private function pruneOf(int $sequence): array
    {
        $seal   = $this->seals()[$sequence - 1];
        $id     = (string) $seal['id'];
        $record = app(SealSigner::class)->signPrune((string) $seal['log_id'], $id, (string) $seal['seal_digest'], (int) $seal['member_count'], self::OPERATION_ID, self::PRUNED_AT);

        return [$this->membersOf($id), $record];
    }

    /**
     * How many of the entries the seal at the sequence holds are still stored.
     *
     * @param  int  $sequence
     * @return int
     */
    private function entriesLeftOf(int $sequence): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->whereIn('id', $this->membersOf($this->sealIdOf($sequence)))->count();
    }

    /**
     * Whether the ledger holds a prune record for the seal at the sequence.
     *
     * @param  int  $sequence
     * @return bool
     */
    private function hasRecord(int $sequence): bool
    {
        return app(TableBackedPruneLedger::class)->recordFor($this->sealIdOf($sequence)) instanceof PruneRecord;
    }

    /**
     * The id of the stored seal at the sequence.
     *
     * @param  int  $sequence
     * @return string
     */
    private function sealIdOf(int $sequence): string
    {
        return (string) $this->seals()[$sequence - 1]['id'];
    }

    /**
     * The maintenance connection, which a prune runs on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
