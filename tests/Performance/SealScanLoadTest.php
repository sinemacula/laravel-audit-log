<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealBatch;
use SineMacula\Laravel\AuditLog\Integrity\SealCursor;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Load contract for scanning the entries table when sealing: a sweep's work
 * grows in line with the table, whether its rows are unsealed or already
 * sealed, because a window costs the same wherever its cursor is; a recent pass
 * costs the same whatever sealed history lies beyond its lookback; and the
 * batches of a backlog follow each other, each reading on from where the one
 * before stopped, never from the beginning.
 *
 * Nothing here is held to an absolute limit: each measurement over the larger
 * table is compared with one over the smaller, taken in this process, so a slow
 * machine slows both. Each is the least CPU time of three runs, user and system
 * together, since a run can only be slowed by what else is happening.
 * `getrusage()` sees only this process, so the CPU time of a database server is
 * never counted: the measurements run on SQLite alone, whose engine works
 * inside the process, and are skipped on any other driver. They are not taken
 * while Xdebug collects coverage either, which slows every line by an order of
 * magnitude, so they would be measuring Xdebug. Whether a backlog restarts is a
 * matter of the statements alone, so it is checked on every engine.
 *
 * The sealer reads only an entry's id, HMAC and time, so the tables are filled
 * with copies of one finalised entry under fresh ids and times, which is far
 * quicker than finalising each.
 *
 * It claims no coverage because its tables are among the slowest things in the
 * suite to fill: a mutant whose covering tests included them would be skipped
 * as taking too long rather than run. The sealer's behaviour is pinned by its
 * own tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SealScanLoadTest extends PerformanceContractTestCase
{
    use SealsEntries;

    /** @var int How many rows the smaller table holds; the larger holds four times as many. */
    private const int ROWS = 2000;

    /** @var int How much more work four times the rows may cost: linear growth is four times, and quadratic sixteen. */
    private const int MAX_WORK_RATIO = 6;

    /** @var int How much more a recent pass may cost over four times the sealed history: one that does not grow with it costs the same. */
    private const int MAX_RECENT_RATIO = 2;

    /** @var int How much more a window from near the beginning of a table may cost than one from near its end: one that reads only its batch costs the same. */
    private const int MAX_WINDOW_RATIO = 2;

    /** @var int The batch a sweep seals and reads its windows in. */
    private const int BATCH = 500;

    /** @var int The rows a measured window reads: the least batch the settings accept. */
    private const int WINDOW = 100;

    /** @var int How many runs each CPU measurement takes the least of. */
    private const int ROUNDS = 3;

    /** @var int How many recent passes or windows one measurement makes, so it is long enough to measure. */
    private const int PASSES = 20;

    /** @var int How many recent rows each recent pass finds sealed in its lookback. */
    private const int RECENT_ROWS = 100;

    /** @var int Entries inserted by one statement, well under every engine's placeholder limit. */
    private const int INSERT_CHUNK = 20;

    /** @var string When the history of every table begins: a month before the frozen clock. */
    private const string HISTORY_FROM = '2026-10-01 00:00:00';

    /** @var ?array<string, int|string|null> The finalised entry every row inserted is a copy of. */
    private ?array $template = null;

    /**
     * A sweep of four times the unsealed rows costs no more than six times the
     * CPU time of a sweep of the smaller table: linear growth gives four, and
     * quadratic sixteen.
     *
     * @return void
     */
    public function testASweepIsLinearInTheTable(): void
    {
        $this->requireInProcessCpu();
        $this->useBatch(self::BATCH);

        $this->insertRows(self::ROWS, self::HISTORY_FROM);

        $small = self::leastCpu(fn (): SealResult => $this->sealer()->sweep(), $this->forgetSeals(...));

        self::assertSame(self::ROWS, $this->countMembers());

        $this->insertRows(3 * self::ROWS, self::HISTORY_FROM, self::ROWS);

        $large = self::leastCpu(fn (): SealResult => $this->sealer()->sweep(), $this->forgetSeals(...));

        self::assertSame(4 * self::ROWS, $this->countMembers());
        self::assertLessThanOrEqual(self::MAX_WORK_RATIO * $small, $large, sprintf('Sweeping four times the rows took %d ns, and the smaller table %d ns.', $large, $small));
    }

    /**
     * A recent pass over a table whose sealed history is four times as large,
     * all of it recorded more than the lookback before the newest sealed row,
     * costs no more than twice one over the smaller history: it starts at the
     * lookback, so the history beyond it is never read.
     *
     * @return void
     */
    public function testTheRecentPassDoesNotGrowWithSealedHistory(): void
    {
        $this->requireInProcessCpu();

        $this->insertRows(self::ROWS, self::HISTORY_FROM);
        $this->sealAll();
        $this->insertRows(self::RECENT_ROWS, '2026-11-01 10:00:00');
        $this->sealer()->seal();

        $small = self::leastCpu($this->recentPasses(...));

        $this->insertRows(3 * self::ROWS, self::HISTORY_FROM, self::ROWS);
        $this->sealAll();
        $this->insertRows(self::RECENT_ROWS, '2026-11-01 11:30:00');
        $this->sealer()->seal();

        $large = self::leastCpu($this->recentPasses(...));

        self::assertSame(4 * self::ROWS + 2 * self::RECENT_ROWS, $this->countMembers());
        $message = sprintf('A recent pass over four times the history took %d ns, and over the smaller %d ns.', $large, $small);

        self::assertLessThanOrEqual(self::MAX_RECENT_RATIO * $small, $large, $message);
    }

    /**
     * Rows of `[run]`: the recent pass and the sweep, which page the table in
     * the same order.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Integrity\Sealer): \SineMacula\Laravel\AuditLog\Integrity\SealResult}>
     */
    public static function provideRuns(): iterable
    {
        yield from [
            'the recent pass' => [static fn (Sealer $sealer): SealResult => $sealer->seal()],
            'the sweep'       => [static fn (Sealer $sealer): SealResult => $sealer->sweep()],
        ];
    }

    /**
     * Across a run of ten batches over a backlog, only the first candidate
     * query starts at the beginning of the table, and each one after it reads
     * on strictly after the position the one before reached.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Integrity\Sealer): \SineMacula\Laravel\AuditLog\Integrity\SealResult  $run
     * @return void
     */
    #[DataProvider('provideRuns')]
    public function testABacklogNeverRestartsAtTheBeginning(\Closure $run): void
    {
        $this->useBatch(100);

        app(ConfigRepository::class)->set('audit-log.integrity.seal.max_batches', 10);

        $this->insertRows(1050, self::HISTORY_FROM);

        $positions = $this->recordCandidatePositions();
        $result    = $run($this->sealer());

        self::assertSame(10, $result->seals());
        self::assertCount(10, $positions);
        self::assertNull($positions[0]);

        for ($batch = 1; $batch < 10; $batch++) {
            $before  = $positions[$batch - 1] ?? ['', ''];
            $current = $positions[$batch];

            self::assertNotNull($current, sprintf('Batch %d started at the beginning of the table.', $batch + 1));
            self::assertGreaterThan(0, $current <=> $before, sprintf('Batch %d did not read on after batch %d.', $batch + 1, $batch));
        }
    }

    /**
     * A sweep over four times the rows, every one sealed already, costs no more
     * than six times the CPU time of one over the smaller table: its windows
     * read on to the end and seal nothing.
     *
     * @return void
     */
    public function testASweepOverASealedTableIsLinear(): void
    {
        $this->requireInProcessCpu();
        $this->useBatch(self::BATCH);

        $this->insertRows(self::ROWS, self::HISTORY_FROM);
        $this->sealAll();

        $small = self::leastCpu(fn (): SealResult => $this->sweepSealingNothing());

        $this->insertRows(3 * self::ROWS, self::HISTORY_FROM, self::ROWS);
        $this->sealAll();

        $large = self::leastCpu(fn (): SealResult => $this->sweepSealingNothing());

        self::assertLessThanOrEqual(self::MAX_WORK_RATIO * $small, $large, sprintf('Sweeping four times the sealed rows took %d ns, and the smaller table %d ns.', $large, $small));
    }

    /**
     * A sweep window reads at most its batch of rows wherever its cursor is, so
     * a window from near the beginning of a sealed table costs no more than
     * twice the CPU time of one from near its end: one that sorted every row
     * after its cursor before taking its batch would cost in line with the rows
     * left, and make a whole sweep quadratic in the table.
     *
     * @return void
     */
    public function testAWindowCostsTheSameWhereverItStarts(): void
    {
        $this->requireInProcessCpu();

        $this->insertRows(4 * self::ROWS, self::HISTORY_FROM);
        $this->sealAll();

        $writer = new CheckpointWriter(app(DatabaseManager::class), app(SealSigner::class), app(SealSettings::class), app(Clock::class));
        $until  = StoredTime::format(CarbonImmutable::now());
        $early  = $this->cursorAt(0);
        $late   = $this->cursorAt(4 * self::ROWS - 2 * self::WINDOW);

        $windows = static function (SealCursor $after) use ($writer, $until): SealBatch {
            $batch = $writer->writeWindow($after, $until, self::WINDOW);

            for ($window = 1; $window < self::PASSES; $window++) {
                $batch = $writer->writeWindow($after, $until, self::WINDOW);
            }

            return $batch;
        };

        self::assertSame(self::WINDOW, $windows($early)->read);
        self::assertSame(self::WINDOW, $windows($late)->read);

        $fromTheBeginning = self::leastCpu(static fn (): SealBatch => $windows($early));
        $fromTheEnd       = self::leastCpu(static fn (): SealBatch => $windows($late));

        $message = sprintf('A window near the beginning took %d ns, and one near the end %d ns.', $fromTheBeginning, $fromTheEnd);

        self::assertLessThanOrEqual(self::MAX_WINDOW_RATIO * $fromTheEnd, $fromTheBeginning, $message);
    }

    /**
     * Skip a CPU measurement wherever this process cannot see all of the work
     * or would be measuring something else.
     *
     * @return void
     */
    private function requireInProcessCpu(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            self::markTestSkipped('getrusage() sees only this process, so only SQLite, whose engine works inside it, can be measured.');
        }

        if (!function_exists('xdebug_info') || !in_array('coverage', xdebug_info('mode'), true)) {
            return;
        }

        self::markTestSkipped('Xdebug slows every line by an order of magnitude, so this would be measuring Xdebug.');
    }

    /**
     * Seal in batches of the size given.
     *
     * @param  int  $batch
     * @return void
     */
    private function useBatch(int $batch): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', $batch);
    }

    /**
     * Insert the number of rows, copies of one finalised entry, a chunk at a
     * time, the first recorded at the offset given in microseconds after the
     * time given, and each next one a microsecond later.
     *
     * @param  int  $count
     * @param  string  $from
     * @param  int  $offset
     * @return void
     */
    private function insertRows(int $count, string $from, int $offset = 0): void
    {
        $first = new CarbonImmutable($from, 'UTC');

        for ($start = 0; $start < $count; $start += self::INSERT_CHUNK) {
            $rows = [];

            for ($index = $start; $index < min($count, $start + self::INSERT_CHUNK); $index++) {
                $time   = StoredTime::toStorage(StoredTime::format($first->addMicroseconds($offset + $index)));
                $rows[] = ['id' => Str::uuid7()->toString(), 'occurred_at' => $time, 'recorded_at' => $time] + $this->template();
            }

            DB::connection()->table(EntrySettings::table())->insert($rows);
        }
    }

    /**
     * The row of a finalised entry, as the store writes it, made once.
     *
     * @return array<string, int|string|null>
     */
    private function template(): array
    {
        if ($this->template !== null) {
            return $this->template;
        }

        $instant   = StoredTime::format(new CarbonImmutable(self::HISTORY_FROM, 'UTC'));
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));

        return $this->template = app(RowCodec::class)->encode($finaliser->finalise(RecordFactory::captured(occurredAt: $instant)));
    }

    /**
     * Remove every seal, member and progress row, so the next sweep seals the
     * whole table afresh.
     *
     * @return void
     */
    private function forgetSeals(): void
    {
        foreach ([IntegrityTables::membersTable(), IntegrityTables::checkpointsTable(), IntegrityTables::stateTable()] as $table) {
            DB::connection()->table($table)->delete();
        }
    }

    /**
     * Make a number of recent passes, each of which finds every row in its
     * lookback sealed, and return the last one's result.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     */
    private function recentPasses(): SealResult
    {
        $sealer = $this->sealer();
        $result = $sealer->seal();

        for ($pass = 1; $pass < self::PASSES; $pass++) {
            $result = $sealer->seal();
        }

        self::assertSame(0, $result->seals());

        return $result;
    }

    /**
     * Sweep a table every row of which is sealed, and check that it sealed
     * nothing and reached the end.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     */
    private function sweepSealingNothing(): SealResult
    {
        $result = $this->sealer()->sweep();

        self::assertSame(0, $result->seals());
        self::assertTrue($result->isSweepComplete());

        return $result;
    }

    /**
     * Record the position every candidate query from now on reads after, in
     * order: `null` for one that starts at the beginning of the table, and
     * otherwise its time, in the package's form, and its id, which is empty for
     * one that starts at its time.
     *
     * @return \ArrayObject<int, ?array{0: string, 1: string}>
     */
    private function recordCandidatePositions(): \ArrayObject
    {
        /** @var \ArrayObject<int, ?array{0: string, 1: string}> $positions */
        $positions = new \ArrayObject;
        $table     = preg_quote(EntrySettings::table(), '/');
        $pattern   = '/^select .* from (?:\S*' . $table . '\S* as e\b|\(select .* from \S*' . $table . '\b)/';

        DB::connection()->beforeExecuting(static function (string $query, array $bindings) use ($positions, $pattern): void {
            if (preg_match($pattern, str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $values = array_values(array_map(static fn (mixed $value): string => is_scalar($value) ? (string) $value : '', $bindings));

            $positions->append(match (count($values)) {
                1       => null,
                2       => [StoredTime::fromStorage($values[1]), ''],
                default => [StoredTime::fromStorage($values[1]), $values[4] ?? ''],
            });
        });

        return $positions;
    }

    /**
     * The position after the row at the offset given, in sealing order, as the
     * database returns its time and id.
     *
     * @param  int  $offset
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealCursor
     */
    private function cursorAt(int $offset): SealCursor
    {
        $row = DB::connection()->table(EntrySettings::table())->orderBy('recorded_at')->orderBy('id')->offset($offset)->first(['recorded_at', 'id']);

        return SealCursor::after((string) $row?->recorded_at, (string) $row?->id);
    }

    /**
     * How many member rows there are.
     *
     * @return int
     */
    private function countMembers(): int
    {
        return DB::connection()->table(IntegrityTables::membersTable())->count();
    }

    /**
     * The least CPU time the work takes over a few runs, in nanoseconds, each
     * run after the reset given, if any, which is not measured.
     *
     * @param  \Closure(): object  $work
     * @param  ?\Closure(): void  $reset
     * @return int
     */
    private static function leastCpu(\Closure $work, ?\Closure $reset = null): int
    {
        $least = PHP_INT_MAX;

        for ($round = 0; $round < self::ROUNDS; $round++) {
            if ($reset !== null) {
                $reset();
            }

            $started = self::cpuNanoseconds();

            $work();

            $least = min($least, self::cpuNanoseconds() - $started);
        }

        return $least;
    }

    /**
     * The CPU time this process has used, user and system together: waiting for
     * a core on a busy machine or runner uses none of it.
     *
     * @return int
     */
    private static function cpuNanoseconds(): int
    {
        $usage = getrusage();

        assert(is_array($usage));

        return ($usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec'])  * 1000000000
            + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) * 1000;
    }
}
