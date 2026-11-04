<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\PruneCommand;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:prune`: it runs a prune and prints its run id,
 * status, counts, skipped seals, cursor and remaining seals; plans one with
 * `--dry-run`, printing the plan per pair and per seal and writing nothing;
 * takes a time budget from 60 to 86400 seconds and refuses any other before a
 * statement runs; writes one JSON object with `--json`; exits 1 for a failed
 * run and for a skipped seal; warns when the record could not be written; and
 * prints no value of an entry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCommand::class)]
final class PruneCommandTest extends TestCase
{
    use ReadsTheTrail, SealsEntries, WritesTheJournal;

    /** @var string When every run starts. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry happened: past thirty days. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string A value of an entry no output may hold. */
    private const string SECRET = 'SECRET-VALUE-4242';

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Freeze the clock, keep entries thirty days, bind the configured policy
     * and the journal's ledger, report to a recording handler, and register the
     * command with the console kernel, which keeps the test independent of the
     * provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new PruneCommand);
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
     * A run deletes what retention no longer keeps, prints its run id, status
     * and counts, and exits 0.
     *
     * @return void
     */
    public function testARunPrintsWhatItDid(): void
    {
        $this->storeOld(3);
        $this->sealAll();

        self::assertSame(0, $this->prune());

        $runId = self::propertiesOf($this->readRecords('audit_log.pruned')[0])['operation_id'] ?? null;

        self::assertIsString($runId);

        self::assertStringContainsString(sprintf('Run %s: complete.', $runId), $this->printed);
        self::assertStringContainsString('Deleted 3 entries from 1 seals.', $this->printed);
        self::assertStringContainsString('Kept 0 held and 0 pending delivery.', $this->printed);
        self::assertStringContainsString('Skipped 0 seals.', $this->printed);
        self::assertStringContainsString('Cursor 1, 0 seals remaining.', $this->printed);
        self::assertStringNotContainsString('could not be written', $this->printed);
        self::assertSame(0, $this->entries());
    }

    /**
     * A dry run prints its plan, what it would delete, per pair and per seal,
     * exits 0 and writes nothing: no entry deleted, no journal row, no record.
     *
     * @return void
     */
    public function testADryRunPrintsItsPlanAndWritesNothing(): void
    {
        $this->storeOld(2);
        $this->sealAll();

        self::assertSame(0, $this->prune(['--dry-run' => true]));

        self::assertMatchesRegularExpression('/^Dry run [0-9a-f-]{36}: complete\.$/m', $this->printed);
        self::assertStringContainsString('Would delete 2 entries from 1 seals.', $this->printed);
        self::assertStringContainsString(sprintf('Plan finance, tenant %s, cut-off 2026-11-15T00:00:00.000000Z: 2 eligible.', self::tenantDigest()), $this->printed);
        self::assertStringContainsString('Plan seal 1: 2 eligible.', $this->printed);
        self::assertStringNotContainsString('could not be written', $this->printed);
        self::assertSame(2, $this->entries());
        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->readRecords());
    }

    /**
     * A dry run's plan names a pair of no tenant as such.
     *
     * @return void
     */
    public function testAPlanNamesAPairOfNoTenant(): void
    {
        $finaliser = new RecordFinaliser(FrozenClock::at('2026-12-02 12:00:00'), app(RecordSigner::class));
        $record    = RecordFactory::withFields(['occurred_at' => self::OLD, 'tenant_type' => null, 'tenant_id' => null]);

        app(DatabaseAuditStore::class)->store($finaliser->finalise($record));

        $this->sealAt('2026-12-02 13:00:00');
        $this->sealAll();

        self::assertSame(0, $this->prune(['--dry-run' => true]));
        self::assertStringContainsString('Plan finance, no tenant, cut-off 2026-11-15T00:00:00.000000Z: 1 eligible.', $this->printed);
    }

    /**
     * `--json` names each pair's tenant of a dry run's plan by its digest, as
     * the printed plan does, never by its reference.
     *
     * @return void
     */
    public function testJsonNamesAPlansTenantByItsDigest(): void
    {
        $this->storeOld(1);
        $this->sealAll();

        self::assertSame(0, $this->prune(['--dry-run' => true, '--json' => true]));

        $result = json_decode(trim($this->printed), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($result);
        self::assertSame([
            'pairs' => [['category' => 'finance', 'tenant' => self::tenantDigest(), 'cutoff' => '2026-11-15T00:00:00.000000Z', 'eligible' => 1]],
            'seals' => [1 => 1],
        ], $result['plan'] ?? null);
    }

    /**
     * `--json` writes the result as one JSON object, and nothing else.
     *
     * @return void
     */
    public function testJsonWritesTheResultAsOneObject(): void
    {
        $this->storeOld(1);
        $this->sealAll();

        self::assertSame(0, $this->prune(['--json' => true]));

        $lines = array_values(array_filter(explode("\n", $this->printed), static fn (string $line): bool => $line !== ''));

        self::assertCount(1, $lines);

        $result = json_decode($lines[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($result);
        self::assertSame(['complete', 1, 1], [$result['status'] ?? null, $result['deleted'] ?? null, $result['seals'] ?? null]);
        self::assertSame([true, false], [$result['recorded'] ?? null, $result['dry_run'] ?? null]);
    }

    /**
     * A time budget within its range is taken.
     *
     * @return void
     */
    public function testATimeBudgetWithinItsRangeIsTaken(): void
    {
        self::assertSame(0, $this->prune(['--max-seconds' => '60']));
        self::assertSame(0, $this->prune(['--max-seconds' => '86400']));
    }

    /**
     * Rows of `[value]`: time budgets the command refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedBudgets(): iterable
    {
        yield from [
            'below the least' => ['59'],
            'above a day'     => ['86401'],
            'not a number'    => ['soon'],
            'a fraction'      => ['60.5'],
            'negative'        => ['-60'],
            'nothing'         => [''],
        ];
    }

    /**
     * A time budget out of range, or not a number, is refused with exit 2
     * before any statement runs.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedBudgets')]
    public function testARefusedTimeBudgetExitsTwoBeforeAnyStatement(string $value): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->prune(['--max-seconds' => $value]));
        self::assertStringContainsString('The --max-seconds option must be an integer from 60 to 86400.', $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * A failed run, here on a journal that fails verification, prints its
     * status and reason and exits 1.
     *
     * @return void
     */
    public function testAFailedRunExitsOne(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        self::assertSame(1, $this->prune());
        self::assertMatchesRegularExpression('/^Run [0-9a-f-]{36}: failed \(journal_broken\)\.$/m', $this->printed);
    }

    /**
     * A run that skipped a seal it could not authenticate prints the seal's id
     * and exits 1, though it ended partial.
     *
     * @return void
     */
    public function testASkippedSealExitsOne(): void
    {
        $tampered = $this->storeOld(2)[0];
        $this->sealAll();

        DB::connection(StorageConnection::forMaintenance())->table(EntrySettings::table())->where('id', $tampered)->update(['event' => 'invoice.forged']);

        self::assertSame(1, $this->prune());

        $sealId = (string) $this->seals()[0]['id'];

        self::assertStringContainsString(': partial.', $this->printed);
        self::assertStringContainsString(sprintf('Skipped 1 seals: %s.', $sealId), $this->printed);
    }

    /**
     * A dry run that would skip a seal still exits 0: it is a plan.
     *
     * @return void
     */
    public function testADryRunThatWouldSkipASealExitsZero(): void
    {
        $tampered = $this->storeOld(1)[0];
        $this->sealAll();

        DB::connection(StorageConnection::forMaintenance())->table(EntrySettings::table())->where('id', $tampered)->update(['event' => 'invoice.forged']);

        self::assertSame(0, $this->prune(['--dry-run' => true]));
    }

    /**
     * A run whose record could not be written says so, and still exits 0, since
     * the run stands.
     *
     * @return void
     */
    public function testAnUnrecordedRunWarns(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['held']);

        self::assertSame(0, $this->prune());
        self::assertStringContainsString('The run\'s audit_log.pruned record could not be written; audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * What stops the command is named by its class alone, and exits 1.
     *
     * @return void
     */
    public function testAFailureIsNamedByItsClass(): void
    {
        DB::connection(StorageConnection::forMaintenance())->beginTransaction();

        try {
            self::assertSame(1, $this->prune());
        } finally {
            DB::connection(StorageConnection::forMaintenance())->rollBack();
        }

        self::assertStringContainsString('The prune stopped with LogicException.', $this->printed);
    }

    /**
     * Nothing a run, a dry run or `--json` prints holds a value of an entry: a
     * property, its subject, its client address or its context.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $this->storeOld(2);
        $this->sealAll();

        $this->prune(['--dry-run' => true]);

        $printed = $this->printed;

        $this->prune(['--dry-run' => true, '--json' => true]);

        $printed .= $this->printed;

        $this->prune(['--json' => true]);

        $printed .= $this->printed;

        foreach ([self::SECRET, 'inv_0042', '203.0.113.7', 'Mozilla', 'invoices.approve', 'org_01'] as $value) {
            self::assertStringNotContainsString($value, $printed, $value);
        }
    }

    /**
     * Store the number of entries that happened past thirty days, each holding
     * a secret property, and return their ids.
     *
     * @param  int  $count
     * @return list<string>
     */
    private function storeOld(int $count): array
    {
        $finaliser = new RecordFinaliser(FrozenClock::at('2026-12-02 12:00:00'), app(RecordSigner::class));
        $ids       = [];

        for ($index = 0; $index < $count; $index++) {
            $record = $finaliser->finalise(RecordFactory::captured(['card' => self::SECRET], occurredAt: self::OLD));

            app(DatabaseAuditStore::class)->store($record);

            $ids[] = $record->record->id;
        }

        $this->sealAt('2026-12-02 13:00:00');

        return $ids;
    }

    /**
     * The number of entries the test stored, not the package's own records.
     *
     * @return int
     */
    private function entries(): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('event', 'invoice.approved')->count();
    }

    /**
     * Count every statement run from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function countStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = $query->sql;
        });

        return $statements;
    }

    /**
     * Run the command with the options given, keep what it printed, and return
     * its exit code.
     *
     * @param  array<string, bool|string>  $parameters
     * @return int
     */
    private function prune(array $parameters = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:prune', $parameters);
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * The digest a plan names the tenant of every stored entry by.
     *
     * @return string
     */
    private static function tenantDigest(): string
    {
        return substr(hash('sha256', '["organisation","org_01"]'), 0, 12);
    }
}
