<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Exporter;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Budget contract for exporting the trail, measured against a baseline taken in
 * the same process, never against the clock: the memory an export of four
 * thousand entries holds at its peak is at most twice what an export of two
 * hundred holds, and an export of eight thousand holds at most 16 bytes more
 * for each entry beyond four thousand, far less than keeping even one short
 * string per entry costs, so it does not grow with the export; and the
 * statements of the larger export exceed those of the smaller by the chunks
 * between them alone, on every connection, the export's own session included.
 *
 * Entries are read in chunks of a hundred, the least the setting takes, so the
 * larger export reads thirty-eight chunks more than the smaller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Exporter::class)]
final class ExportMemoryBudgetTest extends PerformanceContractTestCase
{
    use ReadsTheTrail;

    /** @var int The rows of a chunk. */
    private const int CHUNK = 100;

    /** @var int The entries of the smaller export, the baseline. */
    private const int SMALL = 200;

    /** @var int The entries of the larger export. */
    private const int LARGE = 4000;

    /** @var int The entries of the largest export, twice the larger. */
    private const int LARGEST = 8000;

    /** @var int The most bytes the peak may rise by for each entry the largest export holds beyond the larger: far less than any string kept per entry costs. */
    private const int BYTES_PER_ENTRY = 16;

    /** @var int The rows inserted by one statement while seeding. */
    private const int SEED_BATCH = 100;

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /** @var int The entries seeded so far, so each next one is recorded a microsecond after the last. */
    private int $seeded = 0;

    /**
     * Bind the read path, let every viewer see every entry, read in chunks of a
     * hundred and make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();

        app(ConfigRepository::class)->set('audit-log.export.chunk', self::CHUNK);

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-export-budget-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory and everything in it.
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

        parent::tearDown();
    }

    /**
     * The peak memory of an export of four thousand entries, over the memory in
     * use when it began, is at most twice that of an export of two hundred, and
     * that of eight thousand exceeds that of four thousand by at most
     * `BYTES_PER_ENTRY` for each entry between them, each measured with the
     * peak reset first, once a first export has loaded everything an export
     * needs. The ratio alone would let a fixed overhead hide what grows: an
     * export that kept one id of each entry it wrote, as one that sorted or
     * hashed its membership at the end would, holds tens of bytes an entry
     * more, and fails the slope.
     *
     * @return void
     */
    public function testMemoryDoesNotGrowWithTheExport(): void
    {
        $this->seedRows(self::SMALL);
        $this->export('warm-up');

        [$small, $smallGrowth] = $this->measured('small');

        $this->seedRows(self::LARGE - self::SMALL);

        [$large, $largeGrowth] = $this->measured('large');

        $this->seedRows(self::LARGEST - self::LARGE);

        [$largest, $largestGrowth] = $this->measured('largest');

        self::assertSame([self::SMALL, self::LARGE, self::LARGEST], [$small->lines, $large->lines, $largest->lines]);
        self::assertGreaterThan(0, $smallGrowth);

        $sizes   = [self::SMALL, self::LARGE, self::LARGEST];
        $message = sprintf('Exports of %d, %d and %d entries grew memory by %d, %d and %d bytes.', ...[...$sizes, $smallGrowth, $largeGrowth, $largestGrowth]);

        self::assertLessThanOrEqual(2 * $smallGrowth, $largeGrowth, $message);
        self::assertLessThanOrEqual(self::BYTES_PER_ENTRY * (self::LARGEST - self::LARGE), $largestGrowth - $largeGrowth, $message);
    }

    /**
     * The statements an export of four thousand entries runs, on every
     * connection, exceed those of an export of two hundred by the chunks
     * between them alone, each a read of the entries table: the begin, the
     * bound, the commit and the journal cost the same.
     *
     * @return void
     */
    public function testStatementsGrowOnlyByChunk(): void
    {
        $this->seedRows(self::SMALL);

        $small = $this->statementsOf('small');

        $this->seedRows(self::LARGE - self::SMALL);

        $large = $this->statementsOf('large');
        $more  = intdiv(self::LARGE - self::SMALL, self::CHUNK);

        self::assertCount(count($small['all']) + $more, $large['all']);
        self::assertCount(count($small['reads']) + $more, $large['reads']);
        self::assertSame($small['writes'], $large['writes']);
    }

    /**
     * Seed the number of captured entries of the `finance` category, each
     * recorded a microsecond after the one before, signed as the package signs
     * them and inserted a batch at a time, as the store would insert each.
     *
     * @param  int  $count
     * @return void
     */
    private function seedRows(int $count): void
    {
        $first = new CarbonImmutable(self::FIRST_SEEDED_AT, 'UTC');
        $codec = new RowCodec;
        $rows  = [];

        for ($index = 0; $index < $count; $index++) {
            $at        = StoredTime::format($first->addMicroseconds($this->seeded++));
            $finaliser = new RecordFinaliser(FrozenClock::at($at), app(RecordSigner::class));
            $rows[]    = $codec->encode($finaliser->finalise(RecordFactory::captured(occurredAt: $at)));

            if (count($rows) !== self::SEED_BATCH) {
                continue;
            }

            $this->insert($rows);

            $rows = [];
        }

        $this->insert($rows);
    }

    /**
     * Insert the rows into the entries table on the storage connection in one
     * statement, unless there are none.
     *
     * @param  list<array<string, int|string|null>>  $rows
     * @return void
     */
    private function insert(array $rows): void
    {
        if ($rows === []) {
            return;
        }

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->insert($rows);
    }

    /**
     * Export the `finance` entries to a file of the name, and return the result
     * with how far the peak memory rose above the memory in use when the export
     * began, the peak reset first.
     *
     * @param  string  $name
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\ExportResult, 1: int}
     */
    private function measured(string $name): array
    {
        gc_collect_cycles();
        memory_reset_peak_usage();

        $baseline = memory_get_usage();
        $result   = $this->export($name);

        return [$result, memory_get_peak_usage() - $baseline];
    }

    /**
     * The statements an export of the `finance` entries to a file of the name
     * runs on every connection: all of them, the reads of the entries table,
     * and the writes, in order.
     *
     * @param  string  $name
     * @return array{all: list<string>, reads: list<string>, writes: list<string>}
     */
    private function statementsOf(string $name): array
    {
        $this->captureQueries();
        $this->export($name);

        $all = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());

        return [
            'all'    => $all,
            'reads'  => $this->entryReads(),
            'writes' => array_values(array_filter($all, static fn (string $sql): bool => preg_match('/^\s*(insert|update|delete|replace)\b/i', $sql) === 1)),
        ];
    }

    /**
     * Export the `finance` entries, for the viewer, to a file of the name in
     * the directory.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportResult
     */
    private function export(string $name): ExportResult
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->export($this->directory . '/' . $name . '.ndjson');
    }
}
