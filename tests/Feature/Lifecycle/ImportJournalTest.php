<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportJournal;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for where an import batch stands in the lifecycle journal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportJournal::class)]
final class ImportJournalTest extends TestCase
{
    use WritesTheJournal;

    /** @var string When every row is appended, unless a test moves the clock. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string The batch every lookup is of. */
    private const string BATCH = '01932b4e-b000-7000-8000-000000000001';

    /** @var int Journal rows the subject reads by one statement. */
    private const int PAGE = 500;

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An empty journal has neither a start nor a finish.
     *
     * @return void
     */
    public function testAnEmptyJournalHasNoStart(): void
    {
        self::assertSame([null, null], $this->of());
    }

    /**
     * A started batch has its start row and no finish.
     *
     * @return void
     */
    public function testAStartedBatchHasNoFinish(): void
    {
        $started = $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => self::BATCH]);

        [$start, $finish] = $this->of();

        self::assertNotNull($start);
        self::assertSame([$started->sequence, $started->operationId], [$start->sequence, $start->operationId]);
        self::assertNull($finish);
    }

    /**
     * A finished batch has its finish row and payload.
     *
     * @return void
     */
    public function testAFinishedBatchHasItsFinishAndPayload(): void
    {
        $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => self::BATCH]);

        $finished = $this->journalRow(JournalKind::IMPORT_FINISHED, ['batch_id' => self::BATCH, 'status' => 'complete']);

        [, $finish] = $this->of();

        self::assertNotNull($finish);
        self::assertSame([JournalKind::IMPORT_FINISHED, $finished->sequence], [$finish[0]->kind, $finish[0]->sequence]);
        self::assertSame(['batch_id' => self::BATCH, 'status' => 'complete'], $finish[1]);
    }

    /**
     * Another batch's start and finish are not this batch's.
     *
     * @return void
     */
    public function testAnotherBatchIsNotThisOne(): void
    {
        $other = Str::uuid7()->toString();

        $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => $other]);
        $this->journalRow(JournalKind::IMPORT_FINISHED, ['batch_id' => $other, 'status' => 'complete']);

        self::assertSame([null, null], $this->of());
    }

    /**
     * A start journalled before the time read from is not found.
     *
     * @return void
     */
    public function testAStartBeforeTheTimeReadFromIsNotFound(): void
    {
        CarbonImmutable::setTestNow((new CarbonImmutable(self::NOW, 'UTC'))->subSecond());

        $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => self::BATCH]);

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        self::assertSame([null, null], $this->of());
    }

    /**
     * The start is found past a page of other batches' starts, the next page
     * read after the last sequence seen.
     *
     * @return void
     */
    public function testTheStartIsFoundPastAPageOfOtherBatches(): void
    {
        $this->otherStarts();

        $started    = $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => self::BATCH]);
        $statements = $this->journalReads();

        [$start] = $this->of();

        self::assertNotNull($start);
        self::assertSame([self::PAGE + 1, $started->id], [$start->sequence, $start->id]);
        self::assertSame([
            [JournalKind::IMPORT_STARTED->value, self::since(), 0],
            [JournalKind::IMPORT_STARTED->value, self::since(), self::PAGE],
            [JournalKind::IMPORT_FINISHED->value, self::since(), 0],
        ], $statements->getArrayCopy());
    }

    /**
     * A full page of other batches' starts is followed by an empty page, and
     * the batch has no start.
     *
     * @return void
     */
    public function testAFullPageOfOtherBatchesHasNoStart(): void
    {
        $this->otherStarts();

        $statements = $this->journalReads();

        self::assertSame([null, null], $this->of());
        self::assertSame([
            [JournalKind::IMPORT_STARTED->value, self::since(), 0],
            [JournalKind::IMPORT_STARTED->value, self::since(), self::PAGE],
        ], $statements->getArrayCopy());
    }

    /**
     * Rows of `[the columns a tamper stores, the finding]`.
     *
     * @return iterable<string, array{0: array<string, string>, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideBrokenRows(): iterable
    {
        yield from [
            'an edited column'        => [['reason' => 'other.reason'], Finding::JOURNAL_SIGNATURE],
            'an edited digest'        => [['payload_digest' => str_repeat('c', 64)], Finding::JOURNAL_SIGNATURE],
            'an unknown key'          => [['key_id' => 'retired'], Finding::JOURNAL_KEY],
            'a non-canonical payload' => [['payload' => '{"batch_id": "' . self::BATCH . '"}'], Finding::JOURNAL_MALFORMED],
            'an unreadable time'      => [['occurred_at' => 'not-a-time'], Finding::JOURNAL_MALFORMED],
        ];
    }

    /**
     * A row that does not verify refuses the lookup, naming the finding and the
     * row.
     *
     * @param  array<string, string>  $columns
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    #[DataProvider('provideBrokenRows')]
    public function testABrokenRowRefuses(array $columns, Finding $finding): void
    {
        $started = $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => self::BATCH]);

        $this->tamperJournal($started->sequence, $columns);

        try {
            $this->of();
        } catch (JournalBrokenException $exception) {
            self::assertSame([$finding, $started->id], [$exception->finding, $exception->rowId]);

            return;
        }

        self::fail('Expected the journal to be refused as broken.');
    }

    /**
     * Journal a page of starts, each of another batch.
     *
     * @return void
     */
    private function otherStarts(): void
    {
        for ($start = 1; $start <= self::PAGE; $start++) {
            $this->journalRow(JournalKind::IMPORT_STARTED, ['batch_id' => Str::uuid7()->toString()]);
        }
    }

    /**
     * Record the bindings of each select of the journal table from now on.
     *
     * @return \ArrayObject<int, list<int|string|null>>
     */
    private function journalReads(): \ArrayObject
    {
        /** @var \ArrayObject<int, list<int|string|null>> $log */
        $log     = new \ArrayObject;
        $journal = LifecycleTables::journalTable();

        DB::listen(static function (QueryExecuted $query) use ($log, $journal): void {
            if (!str_starts_with(strtolower($query->sql), 'select') || !preg_match('/\b' . $journal . '\b/', $query->sql)) {
                return;
            }

            $log->append(array_values(array_map(static fn (mixed $binding): int|string|null => is_int($binding) || is_string($binding) ? $binding : null, $query->bindings)));
        });

        return $log;
    }

    /**
     * Where the batch stands, read from the frozen time on the maintenance
     * connection.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: ?array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function of(): array
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        self::assertInstanceOf(Connection::class, $connection);

        return app(ImportJournal::class)->of($connection, self::BATCH, self::since());
    }

    /**
     * The frozen time as the database stores it.
     *
     * @return string
     */
    private static function since(): string
    {
        return StoredTime::toStorage(StoredTime::format(new CarbonImmutable(self::NOW, 'UTC')));
    }
}
