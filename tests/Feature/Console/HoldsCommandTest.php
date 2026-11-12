<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\HoldsCommand;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldResult;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:holds`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldsCommand::class)]
final class HoldsCommandTest extends TestCase
{
    use WritesTheJournal;

    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000e1';

    /** @var string When every hold is placed. */
    private const string PLACED_AT = '2026-11-02T09:00:00.000000Z';

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

        CarbonImmutable::setTestNow(new CarbonImmutable(self::PLACED_AT, 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new HoldsCommand);
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
     * With no hold active it says so, and exits 0.
     *
     * @return void
     */
    public function testNoHoldIsActive(): void
    {
        self::assertSame(0, $this->holds());
        self::assertSame("No hold is active.\n", $this->printed);
    }

    /**
     * Each active hold is listed with its fields and scope dimensions.
     *
     * @return void
     */
    public function testTheActiveHoldsAreListed(): void
    {
        $all    = $this->place(HoldScope::all(), HoldBasis::LEGAL_CLAIM);
        $narrow = $this->place(self::narrowScope(), HoldBasis::REGULATORY, new CarbonImmutable('2027-01-31', 'UTC'));

        self::assertSame(0, $this->holds());
        self::assertSame(implode("\n", [
            sprintf('%s legal_claim, placed %s, review none, scope %s.', $all->hold->id, self::PLACED_AT, HoldScope::all()->digest()),
            '  tenants any, tenantless kept, about anyone, categories any, from open, to open, import batch any.',
            sprintf('%s regulatory, placed %s, review 2027-01-31T00:00:00.000000Z, scope %s.', $narrow->hold->id, self::PLACED_AT, self::narrowScope()->digest()),
            '  tenants 2, tenantless not kept, about 1, categories finance security, from 2026-01-01T00:00:00.000000Z,'
                . ' to 2026-06-01T00:00:00.000000Z, import batch ' . self::BATCH . '.',
            '',
        ]), $this->printed);
    }

    /**
     * The holds are read from the verified journal, not the projection.
     *
     * @return void
     */
    public function testTheHoldsAreReadFromTheJournalNotTheProjection(): void
    {
        $hold = $this->place(HoldScope::all(), HoldBasis::OTHER);

        DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable())->delete();

        self::assertSame(0, $this->holds());
        self::assertStringStartsWith($hold->hold->id . ' other, ', $this->printed);
    }

    /**
     * `--json` writes the listing as one JSON object.
     *
     * @return void
     */
    public function testJsonWritesTheListingAsOneObject(): void
    {
        $hold = $this->place(self::narrowScope(), HoldBasis::INVESTIGATION);

        self::assertSame(0, $this->holds(['--json' => true]));
        self::assertSame([
            'holds' => [[
                'id'           => $hold->hold->id,
                'basis'        => 'investigation',
                'placed_at'    => self::PLACED_AT,
                'review_by'    => null,
                'scope_digest' => self::narrowScope()->digest(),
                'dimensions'   => [
                    'tenants'      => 2,
                    'tenantless'   => false,
                    'about'        => 1,
                    'categories'   => ['finance', 'security'],
                    'from'         => '2026-01-01T00:00:00.000000Z',
                    'to'           => '2026-06-01T00:00:00.000000Z',
                    'import_batch' => self::BATCH,
                ],
            ]],
        ], json_decode(trim($this->printed), true, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * With no hold active, `--json` writes an empty listing.
     *
     * @return void
     */
    public function testJsonWithNoHold(): void
    {
        self::assertSame(0, $this->holds(['--json' => true]));
        self::assertSame("{\"holds\":[]}\n", $this->printed);
    }

    /**
     * `--rebuild` rebuilds the projection and says how many holds it has.
     *
     * @return void
     */
    public function testRebuildRebuildsTheProjection(): void
    {
        $this->place(HoldScope::all(), HoldBasis::OTHER);
        $this->place(HoldScope::tenantless(), HoldBasis::OTHER);

        $projection = DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable());

        $projection->delete();

        self::assertSame(0, $this->holds(['--rebuild' => true]));
        self::assertSame("The holds projection holds 2 active holds.\n", $this->printed);
        self::assertSame(2, $projection->count());

        self::assertSame(0, $this->holds(['--rebuild' => true, '--json' => true]));
        self::assertSame("{\"rebuilt\":2}\n", $this->printed);
    }

    /**
     * A journal failing verification exits 1, named by the failure's class.
     *
     * @return void
     */
    public function testABrokenJournalExitsOne(): void
    {
        $this->place(HoldScope::all(), HoldBasis::OTHER);
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        $message = "The holds could not be read: SineMacula\\Laravel\\AuditLog\\Lifecycle\\JournalBrokenException.\n";

        self::assertSame(1, $this->holds());
        self::assertSame($message, $this->printed);
        self::assertSame(1, $this->holds(['--rebuild' => true]));
        self::assertSame($message, $this->printed);
    }

    /**
     * Nothing printed holds a tenant or reference a scope names.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $this->place(HoldScope::tenants(Reference::of('organisation', 'org_secret'))->about(Reference::of('user', 'secret-42')), HoldBasis::OTHER);

        $this->holds();

        $printed = $this->printed;

        $this->holds(['--json' => true]);

        $printed .= $this->printed;

        self::assertStringNotContainsString('org_secret', $printed);
        self::assertStringNotContainsString('secret-42', $printed);
    }

    /**
     * A scope narrowed on every dimension.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope
     */
    private static function narrowScope(): HoldScope
    {
        return HoldScope::tenants(Reference::of('organisation', 'org_01'), Reference::of('organisation', 'org_02'))
            ->about(Reference::of('user', '42'))
            ->categories('security', 'finance')
            ->occurredBetween(new CarbonImmutable('2026-01-01', 'UTC'), new CarbonImmutable('2026-06-01', 'UTC'))
            ->importBatch(self::BATCH);
    }

    /**
     * Place a hold of the scope, on the basis and with the review date given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?\DateTimeInterface  $reviewBy
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldResult
     */
    private function place(HoldScope $scope, HoldBasis $basis, ?\DateTimeInterface $reviewBy = null): HoldResult
    {
        return app(AuditLifecycle::class)->hold($scope, new Authority(Reference::of('App\Models\User', '7'), 'case.review'), $basis, $reviewBy);
    }

    /**
     * Run the command, keep what it printed, and return its exit code.
     *
     * @param  array<string, bool>  $options
     * @return int
     */
    private function holds(array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:holds', $options);
        $this->printed = $kernel->output();

        return $exit;
    }
}
