<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeals;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Statement-budget contract for a prune chunk: a chunk costs exactly its budget
 * of reads and writes whatever the entries it deletes, up to 500, and never
 * begins a savepoint or rolls back; each further 500 ids cost one more
 * statement per list of ids it names (the candidates, the outbox, the receipts
 * and the three deletes), never one per entry; a whole run over one entry and
 * over hundreds costs the same; and a dry run writes nothing. Every budget
 * counts statements, fixed or measured against another measured in the same
 * process, never a clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneChunk::class)]
#[CoversClass(Pruner::class)]
final class PruneChunkBudgetTest extends PerformanceContractTestCase
{
    use SealsEntries, WritesTheJournal;

    /** @var string When every entry happened: past its thirty days. */
    private const string OCCURRED_AT = '2026-09-01T10:00:00.000000Z';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-10-31 12:00:00';

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-10-31 13:00:00';

    /** @var string When every chunk's record says it pruned. */
    private const string PRUNED_AT = '2026-11-01T12:00:00.123456Z';

    /** @var string The run every chunk belongs to. */
    private const string RUN = '01932b4e-c000-7000-8000-000000000001';

    /** @var int The reads a run spends on a seal it pruned before: the seal, its members and its present members. */
    private const int EMPTIED_SEAL_READS = 3;

    /** @var int The reads of a chunk of at most 500 ids, on every engine: the journal head reread and the rows after it, the candidates, the seal's prune records, the outbox, the receipts, the journal head the prune row is appended onto, and one of each engine's own (SQLite's trigger catalogue, MySQL's isolation level set, PostgreSQL's isolation level read). */
    private const int CHUNK_READS = 8;

    /** @var int The writes of a chunk of at most 500 ids: the lock row, the three deletes and the prune row. */
    private const int CHUNK_WRITES = 5;

    /** @var int How many lists of ids a chunk names, each at most 500 ids: the candidates, the outbox, the receipts and the three deletes. */
    private const int ID_LISTS = 6;

    /**
     * Keep every category thirty days, bind the configured policy, seal at the
     * test's time, and start the journal with a policy row, so every chunk
     * advances from a head.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        $this->sealAt(self::SEALED_AT);
        $this->journalRow(JournalKind::POLICY, ['version' => 'budget:1', 'policy' => 'budget', 'settings' => null]);
    }

    /**
     * A chunk of 100 entries and one of 500 cost the same statements, exactly
     * the chunk's budget: its reads and its writes, and no savepoint.
     *
     * @return void
     */
    public function testAChunkCostsAFixedNumberOfStatements(): void
    {
        [$hundred, $fiveHundred] = $this->seals([100, 500]);

        $small = $this->statementsOfAChunk($hundred);
        $large = $this->statementsOfAChunk($fiveHundred);

        self::assertSame([100, 500], [$small[1], $large[1]]);
        self::assertSame($small[0], $large[0]);
        self::assertSame([self::CHUNK_READS + self::CHUNK_WRITES, self::CHUNK_WRITES], [$small[0], $small[2]]);
        self::assertSame([self::CHUNK_READS + self::CHUNK_WRITES, self::CHUNK_WRITES], [$large[0], $large[2]]);
    }

    /**
     * A chunk of 1,000 entries costs one statement more per list of ids it
     * names than a chunk of 500.
     *
     * @return void
     */
    public function testEachFiveHundredIdsCostOneStatementPerIdList(): void
    {
        [$fiveHundred, $thousand] = $this->seals([500, 1000]);

        $small = $this->statementsOfAChunk($fiveHundred);
        $large = $this->statementsOfAChunk($thousand);

        self::assertSame([500, 1000], [$small[1], $large[1]]);
        self::assertSame($small[0] + self::ID_LISTS, $large[0]);
    }

    /**
     * A whole run over a seal of one entry and one over a seal of 300 cost the
     * same statements but for the reads of the first seal, which the second run
     * walks again with nothing left in it: nothing is issued per entry.
     *
     * @return void
     */
    public function testNoStatementIsIssuedPerEntry(): void
    {
        // A first run journals the policy, so neither run measured writes it
        $this->statementsOfARun();

        $this->bulk(1);
        $this->sealAll();

        $one = $this->statementsOfARun();

        $this->bulk(300);
        $this->sealAll();

        $many = $this->statementsOfARun();

        self::assertSame([1, 300], [$one[1], $many[1]]);
        self::assertSame($one[0] + self::EMPTIED_SEAL_READS, $many[0]);
    }

    /**
     * A dry run over sealed entries past their retention issues no write.
     *
     * @return void
     */
    public function testADryRunIssuesNoWrite(): void
    {
        $this->bulk(200);
        $this->sealAll();

        $statements = [];

        $this->capture(function () use (&$statements): void {
            self::assertSame(200, array_sum(app(Pruner::class)->run(true)->plan['seals'] ?? []));

            $statements = $this->capturedStatements();
        });

        self::assertNotSame([], $statements);
        self::assertSame([], array_values(array_filter($statements, static fn (string $sql): bool => preg_match('/^\s*select\b/i', $sql) !== 1)));
    }

    /**
     * Insert and seal entries in seals of the sizes given, in order, and return
     * each seal, authenticated.
     *
     * @param  list<int>  $sizes
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal>
     */
    private function seals(array $sizes): array
    {
        $seals = [];

        foreach ($sizes as $index => $size) {
            $this->bulk($size);
            $this->sealAll();

            $seal = app(PruneSeals::class)->load($this->maintenance(), $index + 1);

            self::assertInstanceOf(PruneSeal::class, $seal);

            $seals[] = $seal;
        }

        return $seals;
    }

    /**
     * How many statements one chunk of every member of the seal costs, from its
     * lock to its commit, how many entries it deleted, and how many of the
     * statements wrote, once it is known to have begun no savepoint and rolled
     * nothing back; the replay it starts from is verified first, outside the
     * count.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @return array{0: int, 1: int, 2: int}
     */
    private function statementsOfAChunk(PruneSeal $seal): array
    {
        $replay    = JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId())->verify($this->maintenance());
        $decisions = new RetentionDecisions(app(RetentionPolicy::class), CarbonImmutable::now());
        $ids       = $seal->memberIds;

        $outcome = $this->capture(static fn (): PruneChunkOutcome => app(MaintenanceTransaction::class)->run(
            self::RUN,
            static fn (Connection $connection): PruneChunkOutcome => app(PruneChunk::class)->run($connection, $replay, $decisions, $seal, $ids, self::RUN, self::PRUNED_AT),
        ));

        self::assertInstanceOf(PruneChunkOutcome::class, $outcome);
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());

        return [count($this->capturedStatements()), count($outcome->deleted), count($this->capturedWrites())];
    }

    /**
     * How many statements a whole run costs, and how many entries it deleted.
     *
     * @return array{0: int, 1: int}
     */
    private function statementsOfARun(): array
    {
        $result = $this->capture(static fn () => app(Pruner::class)->run());

        return [count($this->capturedStatements()), $result->deleted];
    }

    /**
     * Insert the number of captured records past their retention, as the store
     * writes them, twenty rows to a statement.
     *
     * @param  int  $count
     * @return void
     */
    private function bulk(int $count): void
    {
        $finaliser = new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class));
        $codec     = app(RowCodec::class);
        $base      = RecordFactory::captured(occurredAt: self::OCCURRED_AT);
        $rows      = [];

        for ($index = 0; $index < $count; $index++) {
            $rows[] = $codec->encode($finaliser->finalise(RecordFactory::withFields(['id' => Str::uuid7()->toString()], $base)));
        }

        foreach (array_chunk($rows, 20) as $chunk) {
            $this->maintenance()->table(EntrySettings::table())->insert($chunk);
        }
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
