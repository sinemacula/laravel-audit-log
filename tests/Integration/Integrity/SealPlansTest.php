<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use Tests\Concerns\ExplainsStatements;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for the plans MySQL and PostgreSQL choose for the entries
 * side of the seal candidate and sweep window queries; covers nothing, as
 * planner choices are not code PHPUnit attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SealPlansTest extends TestCase
{
    use ExplainsStatements, SealsEntries;

    /** @var int How many rows are stored and sealed; with fewer, MySQL scans and sorts. */
    private const int ROWS = 5000;

    /** @var int The batch every run seals and reads its windows in. */
    private const int BATCH = 500;

    /** @var int How far before its high-water mark a recent pass starts, in seconds: about 60 of the rows. */
    private const int LOOKBACK = 60;

    /** @var int The instant the first row is recorded at, as a Unix timestamp: 2026-11-01T00:00:00Z; each next is a second later. */
    private const int FIRST = 1793491200;

    /** @var string When every sealer runs: after every row. */
    private const string SEALED_AT = '2026-11-01 02:00:00';

    /**
     * Store the rows and seal them in batches.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (self::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Only the MySQL and PostgreSQL plans are checked.');
        }

        $this->useBatch(self::BATCH);

        app(ConfigRepository::class)->set('audit-log.integrity.seal.lookback_seconds', self::LOOKBACK);

        $this->sealAt(self::SEALED_AT);

        self::insertRows(0, self::ROWS);

        $this->sealAll();
    }

    /**
     * The recent pass reads its lookback as a range of the recorded index.
     *
     * @return void
     */
    public function testTheCandidateQueryReadsARangeOfTheRecordedIndex(): void
    {
        self::insertRows(self::ROWS, 20);

        $statements = self::captureEntryReads(function (): void {
            self::assertSame(20, $this->sealer()->seal()->entries());
        });

        self::assertCount(1, $statements);
        self::assertReadsARangeOfTheRecordedIndex($statements[0]);
    }

    /**
     * A sweep window after its cursor reads a range of the recorded index.
     *
     * @return void
     */
    public function testASweepWindowReadsARangeOfTheRecordedIndex(): void
    {
        $statements = self::captureEntryReads(function (): void {
            self::assertTrue($this->sealer()->sweep()->isSweepComplete());
        });

        self::assertCount(self::ROWS / self::BATCH + 1, $statements);
        self::assertReadsARangeOfTheRecordedIndex($statements[8]);
    }

    /**
     * Assert the plan reads the entries through a range of the recorded index
     * bounded by both times, never scans them whole, and sorts no more rows
     * than a batch; how the members are joined is left to the planner.
     *
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return void
     *
     * @throws \JsonException
     */
    private static function assertReadsARangeOfTheRecordedIndex(array $statement): void
    {
        $connection = self::connection();

        self::analyse($connection, EntrySettings::table());
        self::analyse($connection, IntegrityTables::membersTable());

        $plan = $connection->getDriverName() === 'mysql' ? self::mysqlPlan($connection, $statement) : self::pgsqlPlan($connection, $statement);

        self::assertTrue($plan['bounded'], $plan['text']);
        self::assertFalse($plan['scanned'], $plan['text']);
        self::assertLessThanOrEqual(self::BATCH, $plan['sorted'], $plan['text']);
    }

    /**
     * The plan facts from MySQL's tree plan: whether a range of the recorded
     * index has both bounds, whether the entries are scanned whole, and the
     * most rows a sort is estimated to take.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return array{bounded: bool, scanned: bool, sorted: float, text: string}
     */
    private static function mysqlPlan(Connection $connection, array $statement): array
    {
        $text    = self::explain($connection, 'EXPLAIN FORMAT=TREE ', $statement);
        $entries = '(?:e|' . preg_quote(self::entriesTable($connection), '/') . ')';
        $range   = '/index range scan on ' . $entries . ' using ' . preg_quote(self::recordedIndex(), '/') . ' over (.*?)(?:, with index condition|  \(cost=|$)/im';

        preg_match_all($range, $text, $ranges);

        return [
            'bounded' => array_filter($ranges[1], self::isMysqlRangeBounded(...)) !== [],
            'scanned' => preg_match('/(?:table scan|index scan) on ' . $entries . '\b/i', $text) === 1,
            'sorted'  => self::mysqlSortRows($text),
            'text'    => $text,
        ];
    }

    /**
     * Whether a range of MySQL's tree plan bounds `recorded_at` from below and
     * from above.
     *
     * @param  string  $over
     * @return bool
     */
    private static function isMysqlRangeBounded(string $over): bool
    {
        return preg_match('/\'[^\']*\' <=? recorded_at\b/', $over) === 1 && preg_match('/\brecorded_at <= \'/', $over) === 1;
    }

    /**
     * The most rows a sort of MySQL's tree plan is estimated to give or take
     * from the line below it, since a limited sort's own estimate is capped at
     * its limit; infinite when an estimate cannot be read.
     *
     * @param  string  $text
     * @return float
     */
    private static function mysqlSortRows(string $text): float
    {
        $lines = explode("\n", $text);
        $most  = 0.0;

        foreach (preg_grep('/-> Sort\b/', $lines) ?: [] as $number => $line) {
            foreach ([$line, $lines[$number + 1] ?? ''] as $step) {
                $most = max($most, preg_match('/\brows=([0-9.e+]+)\)/', $step, $match) === 1 ? (float) $match[1] : INF);
            }
        }

        return $most;
    }

    /**
     * The plan facts from PostgreSQL's JSON plan: whether the recorded index is
     * read with both bounds, whether the entries are scanned whole, and the
     * most rows a sort is estimated to take.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return array{bounded: bool, scanned: bool, sorted: float, text: string}
     *
     * @throws \JsonException
     */
    private static function pgsqlPlan(Connection $connection, array $statement): array
    {
        [$tree, $text] = self::jsonExplain($connection, $statement);

        $table = self::entriesTable($connection);
        $plan  = ['bounded' => false, 'scanned' => false, 'sorted' => 0.0, 'text' => $text];

        foreach (new \RecursiveIteratorIterator(new \RecursiveArrayIterator($tree), \RecursiveIteratorIterator::SELF_FIRST) as $node) {
            if (!is_array($node) || !is_string($node['Node Type'] ?? null)) {
                continue;
            }

            $condition = is_string($node['Index Cond'] ?? null) ? $node['Index Cond'] : '';

            $plan['bounded'] = $plan['bounded'] || (($node['Index Name'] ?? null) === self::recordedIndex() && self::isPgsqlRangeBounded($condition));
            $plan['scanned'] = $plan['scanned'] || (($node['Relation Name'] ?? null) === $table && self::isPgsqlScanWhole($node['Node Type'], $condition));
            $plan['sorted']  = max($plan['sorted'], self::pgsqlSortRows($node));
        }

        return $plan;
    }

    /**
     * Whether a PostgreSQL index condition bounds `recorded_at` from below and
     * from above.
     *
     * @param  string  $condition
     * @return bool
     */
    private static function isPgsqlRangeBounded(string $condition): bool
    {
        return preg_match('/recorded_at <= /', $condition) === 1 && preg_match('/recorded_at >=? /', $condition) === 1;
    }

    /**
     * Whether a PostgreSQL plan node of the type reads its table whole.
     *
     * @param  string  $type
     * @param  string  $condition
     * @return bool
     */
    private static function isPgsqlScanWhole(string $type, string $condition): bool
    {
        return $type === 'Seq Scan' || (in_array($type, ['Index Scan', 'Index Only Scan'], true) && $condition === '');
    }

    /**
     * The rows a PostgreSQL plan node sorts: none when it is no sort, and
     * infinite when its estimate cannot be read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $node
     * @return float
     */
    private static function pgsqlSortRows(array $node): float
    {
        if (!in_array($node['Node Type'] ?? null, ['Sort', 'Incremental Sort'], true)) {
            return 0.0;
        }

        return is_numeric($node['Plan Rows'] ?? null) ? (float) $node['Plan Rows'] : INF;
    }

    /**
     * Capture the reads of the entries the work runs: each candidate query and
     * each sweep window, in order.
     *
     * @param  \Closure(): void  $work
     * @return list<array{sql: string, bindings: array<array-key, scalar|null>}>
     */
    private static function captureEntryReads(\Closure $work): array
    {
        /** @var \ArrayObject<int, array{sql: string, bindings: array<array-key, scalar|null>}> $reads */
        $reads = new \ArrayObject;
        $table = self::entriesTable(self::connection());

        self::connection()->listen(static function (QueryExecuted $query) use ($reads, $table): void {
            if (!str_starts_with($query->sql, 'select') || !str_contains($query->sql, $table)) {
                return;
            }

            /** @var array<array-key, scalar|null> $bindings */
            $bindings = $query->bindings;

            $reads->append(['sql' => $query->sql, 'bindings' => $bindings]);
        });

        $work();

        return array_values($reads->getArrayCopy());
    }

    /**
     * Insert the number of rows from the offset given, each recorded a second
     * after the one before, with a well-formed id and HMAC.
     *
     * @param  int  $offset
     * @param  int  $count
     * @return void
     */
    private static function insertRows(int $offset, int $count): void
    {
        $rows = [];

        for ($number = $offset; $number < $offset + $count; $number++) {
            $time   = gmdate('Y-m-d H:i:s', self::FIRST + $number) . '.000000';
            $rows[] = [
                'id'                => sprintf('0195f4a2-7b1c-7000-8000-%012x', $number + 1),
                'record_version'    => 1,
                'event'             => 'invoice.approved',
                'event_version'     => 1,
                'category'          => 'finance',
                'outcome'           => 'success',
                'provenance'        => 'captured',
                'source_id'         => 'app',
                'occurred_at'       => $time,
                'recorded_at'       => $time,
                'integrity_version' => 1,
                'key_id'            => 'k1',
                'hmac'              => str_repeat('0', 64),
            ];
        }

        foreach (array_chunk($rows, 200) as $chunk) {
            self::connection()->table(EntrySettings::table())->insert($chunk);
        }
    }

    /**
     * The name of the entries table's index of `(recorded_at, id)`.
     *
     * @return string
     */
    private static function recordedIndex(): string
    {
        return EntrySettings::table() . '_recorded_index';
    }

    /**
     * The entries table's name on the connection, with its prefix.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private static function entriesTable(Connection $connection): string
    {
        return $connection->getTablePrefix() . EntrySettings::table();
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
