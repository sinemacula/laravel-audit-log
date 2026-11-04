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
use SineMacula\Laravel\AuditLog\Console\ReconcileCommand;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:reconcile`: it writes the records the journal
 * says are missing and prints the counts, once, within the days `--since` looks
 * back, 7 by default and from 1 to 3650; refuses any other `--since`
 * with exit 2 before any statement; writes one JSON object with `--json`;
 * exits 1 when an operation could not be verified or the run stopped, naming
 * the class; and prints no value of an operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReconcileCommand::class)]
final class ReconcileCommandTest extends TestCase
{
    use ReadsTheTrail, WritesTheJournal;

    /** @var string When the operations run. */
    private const string NOW = '2026-11-02 09:00:00';

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Freeze the clock, report to a recording handler, and register the command
     * with the console kernel, which keeps the test independent of the
     * provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new ReconcileCommand);
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
     * With nothing journalled there is nothing to reconcile, and it exits 0.
     *
     * @return void
     */
    public function testNothingToReconcile(): void
    {
        self::assertSame(0, $this->reconcile());
        self::assertSame("Examined 0 operations: recorded 0, already recorded 0, unverifiable 0, unfinished 0, failed 0.\n", $this->printed);
    }

    /**
     * A record the journal says is missing is written, once: a second run finds
     * it recorded already.
     *
     * @return void
     */
    public function testAMissingRecordIsWrittenOnce(): void
    {
        $this->unrecordedHold(HoldScope::all());

        self::assertSame(0, $this->reconcile());
        self::assertSame("Examined 1 operations: recorded 1, already recorded 0, unverifiable 0, unfinished 0, failed 0.\n", $this->printed);
        self::assertCount(1, $this->readRecords('audit_log.held'));

        self::assertSame(0, $this->reconcile());
        self::assertSame("Examined 1 operations: recorded 0, already recorded 1, unverifiable 0, unfinished 0, failed 0.\n", $this->printed);
    }

    /**
     * Only the operations journalled within the days `--since` looks back are
     * reconciled, seven unless it says otherwise.
     *
     * @return void
     */
    public function testOnlyTheDaysLookedBackAreReconciled(): void
    {
        $this->unrecordedHold(HoldScope::all());

        CarbonImmutable::setTestNow((new CarbonImmutable(self::NOW, 'UTC'))->addDays(10));

        self::assertSame(0, $this->reconcile());
        self::assertStringStartsWith('Examined 0 operations', $this->printed);

        self::assertSame(0, $this->reconcile(['--since' => '11']));
        self::assertStringStartsWith('Examined 1 operations: recorded 1,', $this->printed);
    }

    /**
     * `--json` writes the counts as one JSON object.
     *
     * @return void
     */
    public function testJsonWritesTheCountsAsOneObject(): void
    {
        $this->unrecordedHold(HoldScope::all());

        self::assertSame(0, $this->reconcile(['--json' => true]));
        self::assertSame("{\"examined\":1,\"recorded\":1,\"already_recorded\":0,\"unverifiable\":0,\"unfinished\":0,\"failed\":0}\n", $this->printed);
    }

    /**
     * An operation whose journal row does not verify is never recorded, and
     * leaves the reconciliation incomplete, so it exits 1.
     *
     * @return void
     */
    public function testAnUnverifiableOperationExitsOne(): void
    {
        $this->unrecordedHold(HoldScope::all());
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        self::assertSame(1, $this->reconcile());
        self::assertStringContainsString('unverifiable 1', $this->printed);
        self::assertSame([], $this->readRecords('audit_log.held'));
    }

    /**
     * What stops the run is named by its class alone, and exits 1.
     *
     * @return void
     */
    public function testAFailureIsNamedByItsClass(): void
    {
        app(ConfigRepository::class)->set('audit-log.lifecycle.journal_table', 'audit_log_missing');

        self::assertSame(1, $this->reconcile());
        self::assertSame("The reconciliation stopped with Illuminate\\Database\\QueryException.\n", $this->printed);
    }

    /**
     * The days looked back of the least and the greatest are taken.
     *
     * @return void
     */
    public function testTheBoundsAreTaken(): void
    {
        self::assertSame(0, $this->reconcile(['--since' => '1']));
        self::assertSame(0, $this->reconcile(['--since' => '3650']));
    }

    /**
     * Rows of `[value]`: days looked back the command refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedDays(): iterable
    {
        yield from [
            'none'           => ['0'],
            'over ten years' => ['3651'],
            'not a number'   => ['week'],
            'a fraction'     => ['1.5'],
            'negative'       => ['-7'],
            'nothing'        => [''],
        ];
    }

    /**
     * Days out of range, or not a number, are refused with exit 2 before any
     * statement runs.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedDays')]
    public function testRefusedDaysExitTwoBeforeAnyStatement(string $value): void
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = $query->sql;
        });

        self::assertSame(2, $this->reconcile(['--since' => $value]));
        self::assertSame("The --since option must be an integer from 1 to 3650.\n", $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * Nothing printed, as a line or as JSON, holds a value an operation names.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $this->unrecordedHold(HoldScope::tenants(Reference::of('organisation', 'org_secret')));

        $this->reconcile();

        $printed = $this->printed;

        $this->reconcile(['--json' => true]);

        $printed .= $this->printed;

        self::assertStringNotContainsString('org_secret', $printed);
        self::assertStringNotContainsString('case.review', $printed);
    }

    /**
     * Place a hold of the scope whose record could not be written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return void
     */
    private function unrecordedHold(HoldScope $scope): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.redaction.keys', ['basis']);

        $result = app(AuditLifecycle::class)->hold($scope, new Authority(Reference::of('App\Models\User', '7'), 'case.review'), HoldBasis::LEGAL_CLAIM);

        $config->set('audit-log.redaction.keys', []);

        self::assertFalse($result->recorded);
    }

    /**
     * Run the command with the options given, keep what it printed, and return
     * its exit code.
     *
     * @param  array<string, bool|string>  $options
     * @return int
     */
    private function reconcile(array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:reconcile', $options);
        $this->printed = $kernel->output();

        return $exit;
    }
}
