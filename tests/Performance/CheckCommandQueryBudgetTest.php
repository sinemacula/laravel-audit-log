<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;

/**
 * Statement-budget contract for `audit-log:check`: a run makes a few reads of
 * the schema and, on MySQL, of the session and the table's engine, whatever the
 * table holds, and never writes, begins a savepoint or rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
final class CheckCommandQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var int The most statements a run may make on any engine. */
    private const int MAX_STATEMENTS = 8;

    /**
     * Register the command with the console kernel, which keeps the test
     * independent of the provider, whose registration
     * `AuditLogServiceProviderTest::testTheCheckCommandIsRegistered` pins.
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
    }

    /**
     * A passing run makes at most eight statements, none of them a write, and
     * begins no savepoint and makes no rollback, on every engine.
     *
     * @return void
     */
    public function testTheCheckMakesBoundedReadsAndNoWrites(): void
    {
        $code = $this->capture(fn (): int => $this->check());

        $statements = implode(' | ', $this->capturedStatements());

        self::assertSame(0, $code);
        self::assertNotSame([], $this->capturedStatements());
        self::assertLessThanOrEqual(self::MAX_STATEMENTS, count($this->capturedStatements()), "Statements: {$statements}");
        self::assertSame([], $this->capturedWrites(), "Statements: {$statements}");
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
    }

    /**
     * A run reads no more with 200 entries in the table than with none.
     *
     * @return void
     */
    public function testTheCheckReadsNoMoreWithMoreEntries(): void
    {
        $this->capture(fn (): int => $this->check());

        $empty = $this->capturedStatements();

        DB::table('audit_log_entries')->insert(array_map(self::row(...), range(1, 200)));

        $this->capture(fn (): int => $this->check());

        $full = $this->capturedStatements();

        self::assertSame(200, DB::table('audit_log_entries')->count());
        self::assertSame($empty, $full);
    }

    /**
     * Run the command and return its exit code.
     *
     * @return int
     */
    private function check(): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:check');
    }

    /**
     * An entries row with every column a row must have, numbered so each row's
     * id is its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function row(int $number): array
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
}
