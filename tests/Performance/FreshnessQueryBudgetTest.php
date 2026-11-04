<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\FreshnessChecks;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Fixtures\Integrity\RecordingAnchor;

/**
 * Statement-budget contract for `audit-log:check --freshness`: a run makes a
 * fixed number of reads, whatever the entries and the outbox hold, and writes
 * nothing. With every signal applicable it reads the log's oldest entry, the
 * five progress rows of sealing, the sweep, verification, retention and the
 * last anchoring, the last failure to anchor and the outbox's oldest row due:
 * eight reads, each a point read by name or the first row of an index. With
 * none of the optional signals applicable it reads the oldest entry and the
 * three progress rows of sealing, the sweep and verification alone. It begins
 * no transaction, savepoint or rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessChecks::class)]
#[CoversClass(CheckCommand::class)]
final class FreshnessQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var int The reads of a run with every signal applicable. */
    private const int EVERY_SIGNAL_READS = 8;

    /** @var int The reads of a run with no optional signal applicable. */
    private const int CORE_SIGNAL_READS = 4;

    /**
     * Register the command with the console kernel and bind the retention
     * policy the package binds by default.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new CheckCommand);

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * With every signal applicable a run makes eight reads and writes nothing,
     * in no transaction.
     *
     * @return void
     */
    public function testARunWithEverySignalReadsAFixedBudget(): void
    {
        $this->everythingApplies();

        $code = $this->assertStatementBudget(self::EVERY_SIGNAL_READS, 0, 0, 0, fn (): int => $this->freshness());

        self::assertSame(0, $code);
        self::assertSame(0, $this->assertTransactionBudget(0, 0, fn (): int => $this->freshness()));
    }

    /**
     * With no optional signal applicable a run reads the oldest entry and the
     * three core progress rows alone, and writes nothing.
     *
     * @return void
     */
    public function testARunWithTheCoreSignalsReadsLess(): void
    {
        self::assertSame(0, $this->assertStatementBudget(self::CORE_SIGNAL_READS, 0, 0, 0, fn (): int => $this->freshness()));
    }

    /**
     * A run makes the same statements with two hundred entries and two hundred
     * outbox rows as with one of each: nothing is read per row.
     *
     * @return void
     */
    public function testARunReadsNoMoreWithMoreRows(): void
    {
        $this->everythingApplies();
        $this->storeRows(1);

        $this->capture(fn (): int => $this->freshness());

        $few = $this->capturedStatements();

        $this->storeRows(200);

        self::assertSame(200, DB::table('audit_log_entries')->count());
        self::assertSame(200, DB::table('audit_log_outbox')->count());

        $this->capture(fn (): int => $this->freshness());

        self::assertSame($few, $this->capturedStatements());
        self::assertSame([], $this->capturedWrites());
    }

    /**
     * Make every optional signal apply, each with recent progress: entries are
     * kept for a finite time, an anchor is bound and records go through the
     * outbox.
     *
     * @return void
     */
    private function everythingApplies(): void
    {
        app(ConfigRepository::class)->set(['audit-log.retention.after_days' => 30, 'audit-log.delivery.mode' => 'outbox']);

        $this->app?->instance(CheckpointAnchor::class, new RecordingAnchor);

        $progress = app(IntegrityProgress::class);
        $now      = CarbonImmutable::now();
        $at       = StoredTime::format($now);

        $progress->put(IntegrityProgress::SEAL_LAST_RUN, ['at' => $at], $now);
        $progress->put(IntegrityProgress::SWEEP_COMPLETED, ['at' => $at], $now);
        $progress->put(IntegrityProgress::VERIFY_LAST_FULL, ['at' => $at, 'passed' => true], $now);
        $progress->put(IntegrityProgress::RETENTION_LAST_RUN, ['at' => $at, 'status' => 'complete'], $now);
        $progress->put(IntegrityProgress::ANCHOR_LAST, ['anchored_at' => $at], $now);
    }

    /**
     * Replace the entries and the outbox with the number of rows given in each,
     * all recorded and due now.
     *
     * @param  int  $count
     * @return void
     */
    private function storeRows(int $count): void
    {
        DB::table('audit_log_entries')->delete();
        DB::table('audit_log_outbox')->delete();

        foreach (array_chunk(range(1, $count), 50) as $numbers) {
            DB::table('audit_log_entries')->insert(array_map(self::entry(...), $numbers));
            DB::table('audit_log_outbox')->insert(array_map(self::outboxRow(...), $numbers));
        }
    }

    /**
     * Run `audit-log:check --freshness` and return its exit code.
     *
     * @return int
     */
    private function freshness(): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:check', ['--freshness' => true]);
    }

    /**
     * An entries row with every column a row must have, numbered so each row's
     * id is its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function entry(int $number): array
    {
        return [
            'id'                => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'billing',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => self::NOW,
            'recorded_at'       => self::NOW,
            'integrity_version' => 1,
            'key_id'            => 'test-key',
            'hmac'              => str_repeat('a', 64),
        ];
    }

    /**
     * An outbox row due now, numbered so each row's id is its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function outboxRow(int $number): array
    {
        return [
            'id'           => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
            'payload'      => 'payload',
            'attempts'     => 0,
            'available_at' => self::NOW,
            'created_at'   => self::NOW,
        ];
    }
}
