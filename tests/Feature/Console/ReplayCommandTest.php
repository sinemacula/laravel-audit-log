<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\ReplayCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Symfony\Component\Console\Exception\InvalidOptionException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:replay`: it refuses to run with nothing named
 * and has no way to replay an unsigned line, prints the counts, a record
 * retention pruned among them, and then line numbers, ids and classes and never
 * a value or a message, keeps a hostile id off the console, exits non-zero when
 * a line was skipped or a record failed, and runs the spill and then the outbox
 * when told both.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReplayCommand::class)]
#[CoversClass(ReplayResult::class)]
final class ReplayCommandTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, PrunesByHand, SealsEntries, SearchesForSecrets, SeedsTheOutbox;

    /** @var list<string> The files each test wrote. */
    private array $files = [];

    /**
     * Stop the clock and register the command with the console kernel, which
     * keeps the test independent of the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo('2026-11-01T12:00:00.000000Z');

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new ReplayCommand);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Roll back any transaction a test left open, put the clock back and remove
     * the files the test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * With neither option the command refuses, says why and changes nothing.
     *
     * @return void
     */
    public function testNeitherOptionIsInvalid(): void
    {
        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        self::assertSame(2, $this->replay());
        self::assertSame("Say what to replay: --spill with the path of a file, --outbox, or both.\n", $this->printed());
        self::assertSame('2026-11-01T11:00:00.000000Z', $this->outboxRow($id)['failed_at'] ?? null);
    }

    /**
     * A dry run alone names nothing to replay.
     *
     * @return void
     */
    public function testADryRunAloneIsInvalid(): void
    {
        self::assertSame(2, $this->replay(['--dry-run' => true]));
    }

    /**
     * There is no option that replays an unsigned line.
     *
     * @return void
     */
    public function testAllowUnsignedIsNoOption(): void
    {
        self::assertFalse((new ReplayCommand)->getDefinition()->hasOption('allow-unsigned'));

        $this->expectException(InvalidOptionException::class);

        $this->replay(['--spill' => $this->file(''), '--allow-unsigned' => true]);
    }

    /**
     * The command has the three options it says, and takes a path for one.
     *
     * @return void
     */
    public function testHasTheThreeOptions(): void
    {
        $definition = (new ReplayCommand)->getDefinition();

        self::assertFalse($definition->getOption('outbox')->acceptValue());
        self::assertTrue($definition->getOption('spill')->acceptValue());
        self::assertFalse($definition->getOption('dry-run')->acceptValue());
    }

    /**
     * A run prints the count of each outcome, then each event: its line number,
     * its outcome and its id.
     *
     * @return void
     */
    public function testPrintsCountsAndIds(): void
    {
        $good = $this->finalisedRecord();
        $bad  = $this->finalisedRecord();
        $path = $this->file(self::lineOf($good) . "\n" . str_replace('1200.00', '9999.00', self::lineOf($bad)) . "\n");

        $this->replay(['--spill' => $path]);

        self::assertSame(
            "Spill: replayed 1, would replay 0, pruned 0, failed 0, deferred 0, skipped 1.\n"
            . "Skipped as signature_mismatch: 1.\n"
            . 'line 1: replayed ' . $good->record->id . "\n"
            . 'line 2: signature_mismatch ' . $bad->record->id . "\n",
            $this->printed(),
        );
    }

    /**
     * A dry run prints what it would do, and changes nothing.
     *
     * @return void
     */
    public function testADryRunPrintsWhatItWouldDo(): void
    {
        $record = $this->finalisedRecord();

        self::assertSame(0, $this->replay(['--spill' => $this->file(self::lineOf($record) . "\n"), '--dry-run' => true]));
        self::assertSame(
            "Spill: replayed 0, would replay 1, pruned 0, failed 0, deferred 0, skipped 0.\n"
            . 'line 1: would_replay ' . $record->record->id . "\n",
            $this->printed(),
        );
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A spill line and an outbox row whose records retention pruned are printed
     * as pruned, by line and id for the spill, and exit zero: neither is stored
     * again.
     *
     * @return void
     */
    public function testPrintsThePrunedAndExitsZero(): void
    {
        $spilled = $this->finalisedRecord();
        $queued  = $this->finalisedRecord();

        $this->enqueue($queued, ['failed_at' => '2026-11-01T11:00:00.000000Z', 'attempts' => 10]);
        $this->tombstone($spilled);
        $this->tombstone($queued);

        self::assertSame(0, $this->replay(['--spill' => $this->file(self::lineOf($spilled) . "\n"), '--outbox' => true]));
        self::assertSame(
            "Spill: replayed 0, would replay 0, pruned 1, failed 0, deferred 0, skipped 0.\n"
            . 'line 1: pruned ' . $spilled->record->id . "\n"
            . "Outbox: replayed 0, would replay 0, pruned 1, failed 0, deferred 0, skipped 0.\n",
            $this->printed(),
        );
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A dry run of the outbox lists each failed row and leaves it failed.
     *
     * @return void
     */
    public function testADryRunOfTheOutboxListsItsRows(): void
    {
        $id = $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        self::assertSame(0, $this->replay(['--outbox' => true, '--dry-run' => true]));
        self::assertSame(
            "Outbox: replayed 0, would replay 1, pruned 0, failed 0, deferred 0, skipped 0.\n"
            . 'outbox: would_replay ' . $id . "\n",
            $this->printed(),
        );
        self::assertSame('2026-11-01T11:00:00.000000Z', $this->outboxRow($id)['failed_at'] ?? null);
    }

    /**
     * A failed store prints the class of its failure, and no secret planted in
     * a record or in the failure's message reaches the output.
     *
     * @return void
     */
    public function testPrintsNoPayload(): void
    {
        $this->bindFailingStore(new \DomainException('Down: ' . self::SECRET));

        $record   = $this->finalisedRecord(RecordFactory::captured(['note' => self::SECRET]));
        $unsigned = FailureSpill::line(['unsigned' => true, ...RecordFactory::captured(['note' => self::SECRET])->toArray()]);
        $tampered = str_replace('1200.00', '9999.00', self::lineOf($this->finalisedRecord(RecordFactory::captured(['amount' => '1200.00', 'note' => self::SECRET]))));
        $cut      = substr(self::lineOf($record), 0, -2);

        $path = $this->file(implode("\n", [self::lineOf($record), $unsigned, $tampered, $cut]) . "\n");

        self::assertStringContainsString(self::SECRET, (string) file_get_contents($path));

        $this->replay(['--spill' => $path]);

        $printed = $this->printed();

        self::assertStringContainsString('line 1: failed ' . $record->record->id . ' (DomainException)', $printed);
        self::assertFalse(self::holdsText($printed, self::SECRET), 'The planted secret was printed.');
    }

    /**
     * An id that is not a lower-case UUID reaches no console, escape sequences
     * included, whichever way the line is refused.
     *
     * @return void
     */
    public function testAHostileIdIsNotPrinted(): void
    {
        $hostile = "\e[31mHOSTILE\e[0m";
        $record  = $this->finalisedRecord();
        $altered = CanonicalEncoder::encode([...$record->toArray(), 'id' => $hostile]);
        $unknown = CanonicalEncoder::encode(['unsigned' => true, 'id' => $hostile]);
        $path    = $this->file(FailureSpill::MARKER . $altered . "\n" . FailureSpill::MARKER . $unknown . "\n");

        $this->replay(['--spill' => $path]);

        $printed = $this->printed();

        self::assertStringNotContainsString('HOSTILE', $printed);
        self::assertStringNotContainsString("\e", $printed);
        self::assertStringContainsString("line 1: signature_mismatch\n", $printed);
        self::assertStringContainsString("line 2: unsigned\n", $printed);
    }

    /**
     * A line skipped makes the run exit non-zero.
     *
     * @return void
     */
    public function testASkippedLineExitsNonZero(): void
    {
        self::assertSame(1, $this->replay(['--spill' => $this->file(FailureSpill::MARKER . '{"id":"x"}' . "\n")]));
    }

    /**
     * A record the store refused makes the run exit non-zero.
     *
     * @return void
     */
    public function testAFailedStoreExitsNonZero(): void
    {
        $this->bindFailingStore(new \DomainException('Down.'));

        self::assertSame(1, $this->replay(['--spill' => $this->file(self::lineOf($this->finalisedRecord()) . "\n")]));
    }

    /**
     * A row that fails again in the outbox makes the run exit non-zero.
     *
     * @return void
     */
    public function testAFailedDestinationOnTheOutboxExitsNonZero(): void
    {
        $this->bindFailingStore(new \DomainException('Down.'));
        $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        self::assertSame(1, $this->replay(['--outbox' => true]));
        self::assertSame("Outbox: replayed 0, would replay 0, pruned 0, failed 1, deferred 0, skipped 0.\n", $this->printed());
    }

    /**
     * A run in which everything was replayed exits zero.
     *
     * @return void
     */
    public function testACleanRunExitsZero(): void
    {
        self::assertSame(0, $this->replay(['--spill' => $this->file(self::lineOf($this->finalisedRecord()) . "\n")]));
        self::assertSame(1, $this->entryCount());
    }

    /**
     * Told both, it replays the spill and then the outbox, and prints each.
     *
     * @return void
     */
    public function testBothOptionsRun(): void
    {
        $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        $exit = $this->replay(['--spill' => $this->file(self::lineOf($this->finalisedRecord()) . "\n"), '--outbox' => true]);

        self::assertSame(0, $exit);
        self::assertSame(2, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertMatchesRegularExpression('/\ASpill: replayed 1,.*\nline 1: replayed \S+\nOutbox: replayed 1,.*\n\z/', $this->printed());
    }

    /**
     * Told both, a failure of either is the run's, in either order, and neither
     * stops the other: protects against a code taken from the last run alone.
     *
     * @return void
     */
    public function testAFailureOfEitherIsTheRuns(): void
    {
        $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        $exit = $this->replay(['--spill' => $this->file(FailureSpill::MARKER . '{"id":"x"}' . "\n"), '--outbox' => true]);

        self::assertSame(1, $exit);
        self::assertSame(0, $this->outboxCount());

        $this->seedOutboxRow(RecordFactory::captured()->id, 'not-an-encrypted-payload', ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        self::assertSame(1, $this->replay(['--spill' => $this->file(self::lineOf($this->finalisedRecord()) . "\n"), '--outbox' => true]));
    }

    /**
     * A file that cannot be read is named, the run exits non-zero, and the
     * outbox is still replayed.
     *
     * @return void
     */
    public function testAMissingFileExitsNonZero(): void
    {
        $path = sys_get_temp_dir() . '/audit-log-no-such-spill-file.log';

        self::assertSame(1, $this->replay(['--spill' => $path]));
        self::assertSame(sprintf("The spill file [%s] cannot be read.\n", $path), $this->printed());

        $this->enqueue($this->finalisedRecord(), ['failed_at' => '2026-11-01T11:00:00.000000Z']);

        self::assertSame(1, $this->replay(['--spill' => $path, '--outbox' => true]));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Whatever else stops a run is named by its class alone, never its message,
     * which for a query holds its bindings.
     *
     * @return void
     */
    public function testAStoppedRunPrintsOnlyItsClass(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        self::assertSame(1, $this->replay(['--outbox' => true]));
        self::assertSame("The outbox replay stopped with LogicException.\n", $this->printed());
    }

    /**
     * The events past the bound are counted, not printed.
     *
     * @return void
     */
    public function testTheEventsPastTheBoundAreCounted(): void
    {
        $line = FailureSpill::MARKER . '{"id":"x"}' . "\n";

        self::assertSame(1, $this->replay(['--spill' => $this->file(str_repeat($line, ReplayResult::MAX_EVENTS + 3))]));

        $printed = $this->printed();

        self::assertStringEndsWith("line 1000: malformed\nAnd 3 more.\n", $printed);
        self::assertStringContainsString("skipped 1003.\nSkipped as malformed: 1003.\n", $printed);
    }

    /**
     * Run the command with the options given and return its exit code.
     *
     * @param  array<string, bool|string>  $options
     * @return int
     */
    private function replay(array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:replay', $options);
    }

    /**
     * What the last run printed.
     *
     * @return string
     */
    private function printed(): string
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->output();
    }

    /**
     * Bind a store that throws the failure from every call and joins no
     * transaction.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function bindFailingStore(\Throwable $failure): void
    {
        app()->instance(AuditStore::class, CallbackStore::failingWith($failure, false));
    }

    /**
     * Make the record one retention pruned: stored, sealed, its entry deleted
     * and a signed record of its prune bound, which is what the tombstones
     * read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     */
    private function tombstone(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $this->store()->store($record);
        $this->sealAt('2026-11-02 12:00:00');

        self::assertSame(1, $this->sealAll()->entries());

        $this->pruneByHand($record->record->id);
    }

    /**
     * The spill line of the finalised record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    private static function lineOf(FinalisedRecord $record): string
    {
        return FailureSpill::line($record->toArray());
    }

    /**
     * A file holding the contents, removed when the test ends.
     *
     * @param  string  $contents
     * @return string
     */
    private function file(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, $contents);

        return $path;
    }
}
