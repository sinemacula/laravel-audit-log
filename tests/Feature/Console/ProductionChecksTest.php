<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\ProductionChecks;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\TestCase;

/**
 * Feature tests for the production checks of `audit-log:check`: in production
 * the testing fake store bound as the store, or as a destination of a stack, is
 * a problem, and each disabled seal, sweep or verification schedule is a note
 * that leaves the exit code as it is; in any other environment neither is
 * checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProductionChecks::class)]
#[CoversClass(CheckCommand::class)]
final class ProductionChecksTest extends TestCase
{
    /** @var string The problem of the fake bound as a destination, by its id. */
    private const string FAKE = 'The testing fake store is bound as the destination [%s], which keeps records in memory and loses them; bind a real store.';

    /** @var string The note on a disabled schedule, by its setting and its command. */
    private const string UNSCHEDULED = '`audit-log.%s` is disabled, so the package does not schedule `%s`; run it elsewhere and monitor it with'
        . ' `audit-log:check --freshness`.';

    /**
     * Register the command with the console kernel, with the default channel,
     * policy and key wrapper of a default install, so a good install passes.
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

        $this->config()->set('logging.default', 'stack');

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bindIf(KeyWrapper::class, LocalKeyWrapper::class);
    }

    /**
     * Put the application back in the testing environment, so the migrations
     * roll back without asking for confirmation.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->app?->instance('env', 'testing');

        parent::tearDown();
    }

    /**
     * A good install in production passes, with a `production` subject that is
     * OK and no note.
     *
     * @return void
     */
    public function testAGoodInstallPassesInProduction(): void
    {
        $this->inProduction();

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertContains('[production] OK', $output);
        self::assertSame([], array_values(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[production] note:'))));
    }

    /**
     * The fake bound as the store in production is a problem that fails the
     * run.
     *
     * @return void
     */
    public function testTheFakeStoreInProductionIsAProblem(): void
    {
        $this->inProduction();

        FakeAuditStore::fake($this->app);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[production] ' . sprintf(self::FAKE, 'store'), $output);
    }

    /**
     * Each destination of a stack that is the fake is a problem, named by its
     * id, and a real destination is not.
     *
     * @return void
     */
    public function testAFakeDestinationOfAStackIsAProblem(): void
    {
        $this->inProduction();

        $this->app?->instance(AuditStore::class, new StackAuditStore([
            'null' => new NullAuditStore,
            'fake' => FakeAuditStore::fake(new Container),
            'copy' => FakeAuditStore::fake(new Container),
        ]));

        self::assertSame([sprintf(self::FAKE, 'fake'), sprintf(self::FAKE, 'copy')], $this->checks()->problems());
    }

    /**
     * A store that cannot be resolved is a problem, named by the class of what
     * was thrown and never its message.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAStoreThatCannotBeResolvedIsAProblem(): void
    {
        $this->app?->bind(AuditStore::class, static fn (): never => throw new \RuntimeException('secret detail'));

        self::assertSame(['The bound store could not be resolved (RuntimeException).'], $this->checks()->problems());
    }

    /**
     * Outside production the fake is no problem and the subject is not listed,
     * so tests and staging are free to bind it.
     *
     * @return void
     */
    public function testTheFakeOutsideProductionIsNoProblem(): void
    {
        FakeAuditStore::fake($this->app);

        $this->config()->set('audit-log.integrity.seal.schedule', null);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([], array_values(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[production]'))));
        self::assertSame([], $this->checks()->subject());
        self::assertSame([], $this->checks()->notes());
    }

    /**
     * Each disabled seal, sweep or verification schedule is a note in
     * production, in that order, which leaves the exit code as it is, and a
     * malformed one is left to `config`.
     *
     * @return void
     */
    public function testDisabledSchedulesAreNotedWithoutFailing(): void
    {
        $this->inProduction();

        $this->config()->set([
            'audit-log.integrity.seal.schedule'       => null,
            'audit-log.integrity.seal.sweep_schedule' => '',
            'audit-log.integrity.verify.schedule'     => null,
        ]);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([
            '[production] note: ' . sprintf(self::UNSCHEDULED, 'integrity.seal.schedule', 'audit-log:seal'),
            '[production] note: ' . sprintf(self::UNSCHEDULED, 'integrity.seal.sweep_schedule', 'audit-log:seal --sweep'),
            '[production] note: ' . sprintf(self::UNSCHEDULED, 'integrity.verify.schedule', 'audit-log:verify --strict --sweep-first'),
        ], array_values(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[production] note:'))));

        $this->config()->set('audit-log.integrity.seal.schedule', 'often');

        self::assertSame([
            sprintf(self::UNSCHEDULED, 'integrity.seal.sweep_schedule', 'audit-log:seal --sweep'),
            sprintf(self::UNSCHEDULED, 'integrity.verify.schedule', 'audit-log:verify --strict --sweep-first'),
        ], $this->checks()->notes());
    }

    /**
     * Put the application in production.
     *
     * @return void
     */
    private function inProduction(): void
    {
        $this->app?->instance('env', ProductionChecks::ENVIRONMENT);
    }

    /**
     * The production checks, resolved as the command resolves them.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\ProductionChecks
     */
    private function checks(): ProductionChecks
    {
        return app(ProductionChecks::class);
    }

    /**
     * Run `audit-log:check` and return its exit code and its non-empty lines.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function check(): array
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $code = $kernel->call('audit-log:check');

        return [$code, array_values(array_filter(array_map(trim(...), explode("\n", $kernel->output())), static fn (string $line): bool => $line !== ''))];
    }

    /**
     * The configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
