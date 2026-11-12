<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;

/**
 * Write and memory budget for a thousand-subject bulk operation. No wall-clock
 * bound is set: time ratios between small runs are noise on a shared runner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(DatabaseAuditStore::class)]
final class BulkWriteBudgetTest extends PerformanceContractTestCase
{
    /** @var string The code every bulk operation records. */
    private const string CODE = 'invoice.voided';

    /** @var int How many subjects the large operation names. */
    private const int SUBJECTS = 1000;

    /** @var int Bytes of memory a bulk write may grow by per byte its manifest's canonical form grows by. */
    private const int BYTES_PER_CANONICAL_BYTE = 24;

    /** @var int Growth allowed beyond that for the allocator's rounding, in bytes. */
    private const int ALLOWANCE = 65536;

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::connection()->transactionLevel() > 0) {
            DB::connection()->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A thousand-subject bulk write is two inserts, the artifact's then the
     * entry's, in one transaction of its own.
     *
     * @return void
     */
    public function testAThousandSubjectBulkWriteIsTwoInsertsInOneTransaction(): void
    {
        $subjects = self::subjects(self::SUBJECTS);
        $record   = static fn (): AuditRecord => AuditLog::event(self::CODE)->covering($subjects)->record();

        $this->assertTransactionBudget(1, 1, fn (): AuditRecord => $this->assertStatementBudget(0, 2, 0, 0, $record));

        $this->assertTheArtifactPrecedesTheEntry();
    }

    /**
     * Inside a host's transaction it is the same two inserts in one savepoint.
     *
     * @return void
     */
    public function testInsideAHostTransactionItIsTwoInsertsInOneSavepoint(): void
    {
        $subjects = self::subjects(self::SUBJECTS);
        $record   = static fn (): AuditRecord => AuditLog::event(self::CODE)->covering($subjects)->immediately()->record();

        DB::connection()->beginTransaction();

        $this->assertTransactionBudget(0, 0, fn (): AuditRecord => $this->assertStatementBudget(0, 2, 1, 0, $record));

        $this->assertTheArtifactPrecedesTheEntry();

        DB::connection()->commit();

        self::assertSame(1, DB::connection()->table(EntrySettings::artifactsTable())->count());
    }

    /**
     * Peak memory grows with the manifest, not per member: from 1,000 to 4,000
     * subjects, by at most 24 bytes per canonical byte plus 64 KiB.
     *
     * @return void
     */
    public function testItsMemoryGrowsWithTheManifestNotPerMember(): void
    {
        $thousand = self::subjects(self::SUBJECTS);
        $fourfold = self::subjects(self::SUBJECTS * 4);

        self::peakOf($fourfold);

        $small  = self::peakOf($thousand);
        $large  = self::peakOf($fourfold);
        $growth = self::canonicalBytesOf($fourfold) - self::canonicalBytesOf($thousand);
        $bound  = (self::BYTES_PER_CANONICAL_BYTE * $growth) + self::ALLOWANCE;

        $message = sprintf('Four times the subjects took %d bytes more, over the bound of %d for %d more canonical bytes.', $large - $small, $bound, $growth);

        self::assertLessThanOrEqual($bound, $large - $small, $message);
    }

    /**
     * Assert the last captured writes were the artifact's insert and then the
     * entry's.
     *
     * @return void
     */
    private function assertTheArtifactPrecedesTheEntry(): void
    {
        $writes = $this->capturedWrites();

        self::assertStringContainsString(EntrySettings::artifactsTable(), $writes[0]);
        self::assertStringContainsString(EntrySettings::table(), $writes[1]);
        self::assertStringNotContainsString(EntrySettings::artifactsTable(), $writes[1]);
    }

    /**
     * The growth of peak memory a bulk write of the subjects takes.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @return int
     */
    private static function peakOf(array $subjects): int
    {
        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        AuditLog::event(self::CODE)->covering($subjects)->record();

        return memory_get_peak_usage() - $before;
    }

    /**
     * The length of the canonical form of the subjects' manifest, in bytes.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function canonicalBytesOf(array $subjects): int
    {
        return strlen(Manifest::of($subjects, count($subjects), PHP_INT_MAX)->canonical);
    }

    /**
     * References to the number of invoices.
     *
     * @param  int  $count
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    private static function subjects(int $count): array
    {
        return array_map(static fn (int $id): Reference => Reference::of('invoice', (string) $id), range(1, $count));
    }
}
