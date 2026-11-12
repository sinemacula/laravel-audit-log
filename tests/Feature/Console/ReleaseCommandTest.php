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
use SineMacula\Laravel\AuditLog\Console\ReleaseCommand;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\CountsStatements;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:release`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReleaseCommand::class)]
final class ReleaseCommandTest extends TestCase
{
    use CountsStatements, ReadsTheTrail, WritesTheJournal;

    /** @var array<string, string> The options of the authority every release is asked for on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.closed'];

    /** @var string A hold id no hold was ever placed under. */
    private const string UNKNOWN = '01932b4e-d000-7000-8000-00000000ffff';

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

        $kernel->registerCommand(new ReleaseCommand);
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
     * An active hold is released, printed, and recorded, exiting 0.
     *
     * @return void
     */
    public function testAnActiveHoldIsReleased(): void
    {
        $holdId = $this->placeHold();

        self::assertSame(0, $this->release($holdId, ['--reference' => 'app:ticket-9']));
        self::assertSame(sprintf("Released hold %s.\n", $holdId), $this->printed);
        self::assertSame([], app(AuditLifecycle::class)->holds());

        $records = $this->readRecords('audit_log.released');

        self::assertCount(1, $records);
        self::assertSame(['success', 'App\Models\User', '7'], [$records[0]['outcome'], $records[0]['actor_type'], $records[0]['actor_id']]);
    }

    /**
     * A hold never placed is refused and recorded `denied`, exiting 1.
     *
     * @return void
     */
    public function testAnUnknownHoldExitsOne(): void
    {
        self::assertSame(1, $this->release(self::UNKNOWN));
        self::assertSame(sprintf("The hold %s is not active; only an active hold is released.\n", self::UNKNOWN), $this->printed);

        $records = $this->readRecords('audit_log.released');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'unknown_hold'], [$records[0]['outcome'], $records[0]['reason']]);
    }

    /**
     * A hold released already is not active, so a second release exits 1.
     *
     * @return void
     */
    public function testASecondReleaseExitsOne(): void
    {
        $holdId = $this->placeHold();

        self::assertSame(0, $this->release($holdId));
        self::assertSame(1, $this->release($holdId));
        self::assertStringContainsString('is not active', $this->printed);
    }

    /**
     * A release refused at run time for another reason exits 1, named by class.
     *
     * @return void
     */
    public function testAnotherRefusalIsNamedByItsClass(): void
    {
        $holdId = $this->placeHold();

        $this->tamperJournal(1, ['reason' => 'case.edited']);

        self::assertSame(1, $this->release($holdId));
        self::assertSame("The release was refused with SineMacula\\Laravel\\AuditLog\\Lifecycle\\JournalBrokenException.\n", $this->printed);
    }

    /**
     * Rows of `[hold, options, message]`: each malformed input.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string}>
     */
    public static function provideRefusals(): iterable
    {
        $notAnId = 'The hold must be named by its id, a lower-case UUID v7.';

        yield from [
            'words'                => ['the-legal-hold', [], $notAnId],
            'upper case'           => [strtoupper(self::UNKNOWN), [], $notAnId],
            'a version 4 UUID'     => ['01932b4e-d000-4000-8000-00000000ffff', [], $notAnId],
            'a trailing newline'   => [self::UNKNOWN . "\n", [], $notAnId],
            'no operator id'       => [self::UNKNOWN, ['--by-id' => ''], 'The --by-id option is required.'],
            'a reason that is not' => [self::UNKNOWN, ['--reason' => 'Closed!'], 'The --reason option must be'],
            'a reference too long' => [self::UNKNOWN, ['--reference' => str_repeat('a', 192)], 'The --reference option must be 1 to 191 characters'],
        ];
    }

    /**
     * Each refusal exits 2, printing why, before any statement runs.
     *
     * @param  string  $hold
     * @param  array<string, string>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedArgumentExitsTwoBeforeAnyStatement(string $hold, array $options, string $message): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->release($hold, $options));
        self::assertStringContainsString($message, $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * A release whose record could not be written still releases and warns.
     *
     * @return void
     */
    public function testAnUnrecordedReleaseWarns(): void
    {
        $holdId = $this->placeHold();

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['authority_reason']);

        self::assertSame(0, $this->release($holdId));
        self::assertSame([], app(AuditLifecycle::class)->holds());
        self::assertStringContainsString('The release\'s audit_log.released record could not be written; audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * Nothing printed holds a tenant or a reference the hold's scope names.
     *
     * @return void
     */
    public function testItPrintsNoValue(): void
    {
        $scope  = HoldScope::tenants(Reference::of('organisation', 'org_secret'))->about(Reference::of('user', 'secret-42'));
        $holdId = app(AuditLifecycle::class)->hold($scope, self::authority(), HoldBasis::OTHER)->hold->id;

        self::assertSame(0, $this->release($holdId));
        self::assertStringNotContainsString('org_secret', $this->printed);
        self::assertStringNotContainsString('secret-42', $this->printed);
    }

    /**
     * Place a hold of every entry, and return its id.
     *
     * @return string
     */
    private function placeHold(): string
    {
        return app(AuditLifecycle::class)->hold(HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM)->hold->id;
    }

    /**
     * The authority every hold is placed on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }

    /**
     * Run the command on the hold and return its exit code.
     *
     * @param  string  $holdId
     * @param  array<string, string>  $options
     * @return int
     */
    private function release(string $holdId, array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:release', ['hold' => $holdId] + $options + self::AUTHORITY);
        $this->printed = $kernel->output();

        return $exit;
    }
}
