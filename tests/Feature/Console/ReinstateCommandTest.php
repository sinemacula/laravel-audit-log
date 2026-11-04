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
use SineMacula\Laravel\AuditLog\Console\ReinstateCommand;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Lifecycle\Reinstater;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:reinstate`: it reinstates an erased owner,
 * prints the reinstatement, the owner's fingerprint and never the owner, and
 * exits 0; an owner who is not erased exits 1, recorded `denied`; a failure
 * exits 1 printing its class and never its message; and every malformed
 * argument or option exits 2 before any statement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReinstateCommand::class)]
final class ReinstateCommandTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var array<string, string> The options of the authority every reinstatement is asked for on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.reinstate'];

    /** @var array{type: string, id: string} The owner every test reinstates, which nothing printed may name. */
    private const array OWNER = ['type' => 'App\Models\Patient', 'id' => 'secret-42'];

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Freeze the clock, report to a recording handler, bind the package's key
     * wrapper, and register the command with the console kernel, which keeps
     * the test independent of the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->keyWrapper();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new ReinstateCommand);
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
     * An erased owner is reinstated, printed by the journal row, its
     * fingerprint and the floor, recorded, and exits 0; nothing printed names
     * the owner.
     *
     * @return void
     */
    public function testAnErasedOwnerIsReinstated(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');
        $this->eraseByHand(self::owner());

        self::assertSame(0, $this->reinstate(['--reference' => 'app:ticket-9']));

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        $rows  = $this->journalRows();
        $lines = explode("\n", trim($this->printed));

        self::assertCount(3, $lines);
        self::assertMatchesRegularExpression(sprintf('/\AReinstatement [0-9a-f-]{36}: journal row %s\.\z/', $rows[1]['id']), $lines[0]);
        self::assertSame(sprintf('Owner fingerprint %s (key %s).', $fingerprint, $fingerprintKey), $lines[1]);
        self::assertSame('The owner\'s next key of any unit is created above generation 1.', $lines[2]);
        self::assertSame(['app:ticket-9', 'case.reinstate'], [$rows[1]['external_reference'], $rows[1]['reason']]);
        self::assertCount(1, $this->readRecords('audit_log.keys_reinstated'));
        self::assertNoOwnerPrinted();
    }

    /**
     * An owner who is not erased is refused, recorded `denied`, and exits 1.
     *
     * @return void
     */
    public function testAnOwnerNotErasedExitsOne(): void
    {
        self::assertSame(1, $this->reinstate());
        self::assertSame("The owner is not erased; nothing was reinstated.\n", $this->printed);

        $records = $this->readRecords('audit_log.keys_reinstated');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'not_erased'], [$records[0]['outcome'], $records[0]['reason']]);
    }

    /**
     * A failure exits 1 and prints its class, never its message, which can
     * carry a statement's bindings.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAFailurePrintsItsClassNotItsMessage(): void
    {
        $failure = new \RuntimeException('SQLSTATE[HY000]: owner secret-42');

        app()->bind(Reinstater::class, static fn (): never => throw $failure);

        self::assertSame(1, $this->reinstate());
        self::assertSame("The reinstatement failed with RuntimeException.\n", $this->printed);
        self::assertNoOwnerPrinted();
    }

    /**
     * A reinstatement whose record could not be written still reinstates, says
     * so, and exits 0.
     *
     * @return void
     */
    public function testAnUnrecordedReinstatementWarns(): void
    {
        $this->eraseByHand(self::owner());

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['generation_floor']);

        self::assertSame(0, $this->reinstate());
        self::assertStringContainsString('The reinstatement\'s audit_log.keys_reinstated record could not be written', $this->printed);
        self::assertStringContainsString('audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * Rows of `[arguments and options, message]`: each malformed argument or
     * option, and the refusal it prints.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        $owner = 'The owner must be named by its type and id';

        yield from [
            'an empty id'          => [['id' => ''], $owner],
            'an id too long'       => [['id' => str_repeat('s', 192)], $owner],
            'a control in a type'  => [['type' => "App\tPatient"], $owner],
            'no operator id'       => [['--by-id' => ''], 'The --by-id option is required.'],
            'a reason that is not' => [['--reason' => 'Reinstate!'], 'The --reason option must be'],
            'a reference too long' => [['--reference' => str_repeat('a', 192)], 'The --reference option must be 1 to 191 characters'],
        ];
    }

    /**
     * Each refusal exits 2, printing why, before any statement runs.
     *
     * @param  array<string, string>  $given
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedArgumentExitsTwoBeforeAnyStatement(array $given, string $message): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->reinstate($given));
        self::assertStringContainsString($message, $this->printed);
        self::assertStringNotContainsString('secret', $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * Assert nothing printed names the owner.
     *
     * @return void
     */
    private function assertNoOwnerPrinted(): void
    {
        self::assertStringNotContainsString(self::OWNER['id'], $this->printed);
        self::assertStringNotContainsString('Patient', $this->printed);
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
     * Run the command on the owner, with the arguments and options given over
     * the owner's and the authority's, keep what it printed, and return its
     * exit code.
     *
     * @param  array<string, string>  $given
     * @return int
     */
    private function reinstate(array $given = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:reinstate', [...self::OWNER, ...self::AUTHORITY, ...$given]);
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * The owner every test reinstates.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of(self::OWNER['type'], self::OWNER['id']);
    }
}
