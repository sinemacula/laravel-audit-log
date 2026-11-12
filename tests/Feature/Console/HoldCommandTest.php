<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\HoldCommand;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\CountsStatements;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:hold`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldCommand::class)]
final class HoldCommandTest extends TestCase
{
    use CountsStatements, ReadsTheTrail, WritesTheJournal;

    /** @var array<string, string> The options of the authority every hold is placed on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.review'];

    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000e1';

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Freeze the clock, record reports, and register the command.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new HoldCommand);
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
     * A hold of every entry is placed, its id printed and recorded.
     *
     * @return void
     */
    public function testAHoldIsPlacedAndItsIdPrinted(): void
    {
        self::assertSame(0, $this->hold(['--all' => true, '--basis' => 'legal_claim']));

        $holds = $this->holds();

        self::assertCount(1, $holds);
        self::assertSame(sprintf("Placed hold %s.\n", $holds[0]->id), $this->printed);
        self::assertSame(HoldScope::all()->toArray(), $holds[0]->scope->toArray());
        self::assertSame(HoldBasis::LEGAL_CLAIM, $holds[0]->basis);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $holds[0]->operator->toArray());
        self::assertSame(['case.review', null, null], [$holds[0]->reason, $holds[0]->externalReference, $holds[0]->reviewBy]);
        self::assertCount(1, $this->readRecords('audit_log.held'));
    }

    /**
     * Every scope dimension is taken.
     *
     * @return void
     */
    public function testEveryDimensionIsTaken(): void
    {
        $exit = $this->hold([
            '--tenant'       => ['organisation:org_02', 'organisation:org_01'],
            '--tenantless'   => true,
            '--about'        => ['user:42', 'App\Models\User:7'],
            '--category'     => ['security', 'finance'],
            '--from'         => '2026-01-01',
            '--to'           => '2026-06-01T12:00:00+01:00',
            '--import-batch' => self::BATCH,
            '--basis'        => 'regulatory',
            '--review-by'    => '2027-01-31',
            '--reference'    => 'app:ticket-123',
        ]);

        self::assertSame(0, $exit);

        $expected = HoldScope::tenants(Reference::of('organisation', 'org_01'), Reference::of('organisation', 'org_02'))
            ->withTenantless()
            ->about(Reference::of('user', '42'), Reference::of('App\Models\User', '7'))
            ->categories('finance', 'security')
            ->occurredBetween(new CarbonImmutable('2026-01-01', 'UTC'), new CarbonImmutable('2026-06-01 11:00:00', 'UTC'))
            ->importBatch(self::BATCH);

        $hold = $this->holds()[0];

        self::assertSame($expected->toArray(), $hold->scope->toArray());
        self::assertSame(HoldBasis::REGULATORY, $hold->basis);
        self::assertSame('2027-01-31T00:00:00.000000Z', $hold->reviewBy);
        self::assertSame('app:ticket-123', $hold->externalReference);
    }

    /**
     * `--tenantless` and `--tenant` each start the scope alone.
     *
     * @return void
     */
    public function testEachStartAlone(): void
    {
        self::assertSame(0, $this->hold(['--tenantless' => true, '--basis' => 'other']));
        self::assertSame(0, $this->hold(['--tenant' => ['organisation:org_01'], '--basis' => 'investigation']));

        $holds = $this->holds();

        self::assertSame(HoldScope::tenantless()->toArray(), $holds[0]->scope->toArray());
        self::assertSame(HoldScope::tenants(Reference::of('organisation', 'org_01'))->toArray(), $holds[1]->scope->toArray());
    }

    /**
     * Rows of `[options, message]`: every malformed option.
     *
     * @return iterable<string, array{0: array<string, bool|list<string>|string>, 1: string}>
     */
    public static function provideRefusedOptions(): iterable
    {
        $start     = 'Start the scope with exactly one of --all, --tenant or --tenantless; --tenant may take --tenantless too.';
        $backwards = 'A hold scope\'s window must start before it ends.';

        yield from [
            'no start'                 => [['--basis' => 'other'], $start],
            'every entry and a tenant' => [['--all' => true, '--tenant' => ['organisation:org_01'], '--basis' => 'other'], $start],
            'every entry and none'     => [['--all' => true, '--tenantless' => true, '--basis' => 'other'], $start],
            'no basis'                 => [['--all' => true], 'The --basis option is required.'],
            'an unknown basis'         => [['--all' => true, '--basis' => 'litigation'], 'The --basis option must be legal_claim, regulatory, investigation or other.'],
            'a tenant with no id'      => [['--tenant' => ['organisation'], '--basis' => 'other'], 'The --tenant option must name a reference as `type:id`'],
            'a reference with no type' => [['--all' => true, '--about' => [':42'], '--basis' => 'other'], 'The --about option must name a reference as `type:id`'],
            'a category in capitals'   => [['--all' => true, '--category' => ['Finance'], '--basis' => 'other'], 'A hold scope\'s categories must each be'],
            'a start that is no time'  => [['--all' => true, '--from' => 'yesterday', '--basis' => 'other'], 'The --from option must be an ISO-8601 time'],
            'an end that is no time'   => [['--all' => true, '--to' => '2026-02-30', '--basis' => 'other'], 'The --to option must be an ISO-8601 time'],
            'a window backwards'       => [['--all' => true, '--from' => '2026-06-01', '--to' => '2026-01-01', '--basis' => 'other'], $backwards],
            'a batch that is no id'    => [['--all' => true, '--import-batch' => 'batch-1', '--basis' => 'other'], 'A hold scope\'s import batch must be a lower-case UUID.'],
            'a review that is no date' => [['--all' => true, '--review-by' => 'next year', '--basis' => 'other'], 'The --review-by option must be an ISO-8601 time'],
            'no operator'              => [['--all' => true, '--basis' => 'other', '--by-type' => ''], 'The --by-type option is required.'],
            'a reason that is prose'   => [['--all' => true, '--basis' => 'other', '--reason' => 'Case review'], 'The --reason option must be'],
        ];
    }

    /**
     * Each malformed option exits 2, printing why, before any statement runs.
     *
     * @param  array<string, bool|list<string>|string>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedOptions')]
    public function testARefusedOptionExitsTwoBeforeAnyStatement(array $options, string $message): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->hold($options));
        self::assertStringContainsString($message, $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * A hold refused at run time exits 1, named by its class alone.
     *
     * @return void
     */
    public function testARefusedHoldExitsOne(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        self::assertSame(1, $this->hold(['--all' => true, '--basis' => 'other']));
        self::assertSame("The hold was refused with SineMacula\\Laravel\\AuditLog\\Lifecycle\\JournalBrokenException.\n", $this->printed);
    }

    /**
     * A hold whose record could not be written is still placed and warns.
     *
     * @return void
     */
    public function testAnUnrecordedHoldWarns(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        self::assertSame(0, $this->hold(['--all' => true, '--basis' => 'other']));
        self::assertCount(1, $this->holds());
        self::assertStringContainsString('The hold\'s audit_log.held record could not be written; audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * Nothing printed holds a tenant or a reference the scope names.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $this->hold(['--tenant' => ['organisation:org_secret'], '--about' => ['user:secret-42'], '--basis' => 'other']);

        self::assertStringStartsWith('Placed hold ', $this->printed);
        self::assertStringNotContainsString('org_secret', $this->printed);
        self::assertStringNotContainsString('secret-42', $this->printed);
    }

    /**
     * The active holds, replayed from the verified journal.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>
     */
    private function holds(): array
    {
        return app(AuditLifecycle::class)->holds();
    }

    /**
     * Run the command over the authority's options and return its exit code.
     *
     * @param  array<string, bool|list<string>|string>  $options
     * @return int
     */
    private function hold(array $options): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:hold', $options + self::AUTHORITY);
        $this->printed = $kernel->output();

        return $exit;
    }
}
