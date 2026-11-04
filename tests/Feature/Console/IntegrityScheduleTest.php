<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\EventMutex;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\IntegritySchedule;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use Tests\TestCase;

/**
 * Feature tests for the runs the package schedules: sealing every five minutes,
 * the sweep, the strict verification and the prune daily by default, each at
 * the expression its setting gives or not at all, the prune only when it can
 * delete something, each kept from overlapping itself, on one server only when
 * the cache store is shared, and a malformed schedule left out and reported
 * without stopping the others or the schedule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegritySchedule::class)]
final class IntegrityScheduleTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The message a malformed sealing schedule is reported with. */
    private const string MALFORMED_SEAL = '`audit-log.integrity.seal.schedule` must be a cron expression, or null or empty to schedule nothing.';

    /** @var string The message a malformed prune schedule is reported with. */
    private const string MALFORMED_PRUNE = '`audit-log.retention.schedule` must be a cron expression, or null or empty to schedule nothing.';

    /** @var string The message a category map that is not a map is reported with. */
    private const string MALFORMED_CATEGORIES = '`audit-log.retention.categories` must be a map of categories to days, each from 0 to 36500, 0 meaning forever.';

    /** @var string The prune's default expression. */
    private const string PRUNE_DEFAULT = '30 3 * * *';

    /** @var list<string> The messages of what the handler was given to report, in order. */
    private array $reported = [];

    /**
     * Each run is scheduled by default, at its default expression: sealing
     * every five minutes, the sweep and the strict verification daily.
     *
     * @return void
     */
    public function testTheThreeRunsAreScheduledByDefault(): void
    {
        self::assertSame([
            'audit-log:seal'                          => '*/5 * * * *',
            'audit-log:seal --sweep'                  => '15 3 * * *',
            'audit-log:verify --strict --sweep-first' => '45 3 * * *',
        ], self::runs($this->register()));
        self::assertSame([], $this->reported);
    }

    /**
     * Rows of `[the schedule setting, the run it schedules, the value]`: each
     * setting set to `null`, and to the empty string an empty env line gives.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideTurnedOffRuns(): iterable
    {
        yield from [
            'sealing at null'        => ['seal.schedule', 'audit-log:seal', null],
            'sealing empty'          => ['seal.schedule', 'audit-log:seal', ''],
            'the sweep at null'      => ['seal.sweep_schedule', 'audit-log:seal --sweep', null],
            'the sweep empty'        => ['seal.sweep_schedule', 'audit-log:seal --sweep', ''],
            'the verification null'  => ['verify.schedule', 'audit-log:verify --strict', null],
            'the verification empty' => ['verify.schedule', 'audit-log:verify --strict', ''],
        ];
    }

    /**
     * A run whose setting is `null` or empty is not scheduled, nothing is
     * reported, and the other two still are.
     *
     * @param  string  $setting
     * @param  string  $command
     * @param  ?string  $value
     * @return void
     */
    #[DataProvider('provideTurnedOffRuns')]
    public function testEachRunCanBeTurnedOff(string $setting, string $command, ?string $value): void
    {
        $this->config()->set('audit-log.integrity.' . $setting, $value);

        $runs = self::runs($this->register());

        self::assertArrayNotHasKey($command, $runs);
        self::assertCount(2, $runs);
        self::assertSame([], $this->reported);
    }

    /**
     * Each run is scheduled at the expression its setting gives.
     *
     * @return void
     */
    public function testACustomExpressionIsUsed(): void
    {
        $this->config()->set([
            'audit-log.integrity.seal.schedule'       => '*/2 * * * *',
            'audit-log.integrity.seal.sweep_schedule' => '0 1 * * 0',
            'audit-log.integrity.verify.schedule'     => '30 4 1 * *',
        ]);

        self::assertSame([
            'audit-log:seal'                          => '*/2 * * * *',
            'audit-log:seal --sweep'                  => '0 1 * * 0',
            'audit-log:verify --strict --sweep-first' => '30 4 1 * *',
        ], self::runs($this->register()));
    }

    /**
     * Each run is kept from overlapping itself: sealing for a quarter of an
     * hour, the sweep and the verification for a day.
     *
     * @return void
     */
    public function testEachRunIsWithoutOverlapping(): void
    {
        $events = self::events($this->register());

        self::assertSame(['audit-log:seal' => 15, 'audit-log:seal --sweep' => 1380, 'audit-log:verify --strict --sweep-first' => 1380], array_map(
            static fn (ScheduledEvent $event): int => $event->withoutOverlapping ? $event->expiresAt : 0,
            $events,
        ));
    }

    /**
     * Rows of `[the default cache store's driver, whether a run is kept to one
     * server]`: only a store every server shares can hold that lock.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideCacheDrivers(): iterable
    {
        yield from [
            'redis'     => ['redis', true],
            'memcached' => ['memcached', true],
            'database'  => ['database', true],
            'dynamodb'  => ['dynamodb', true],
            'array'     => ['array', false],
            'file'      => ['file', false],
        ];
    }

    /**
     * Each run is kept to one server exactly when the default cache store's
     * driver is one every server shares, read from configuration alone.
     *
     * @param  string  $driver
     * @param  bool  $shared
     * @return void
     */
    #[DataProvider('provideCacheDrivers')]
    public function testOnOneServerOnlyOnASharedCache(string $driver, bool $shared): void
    {
        $this->config()->set(['cache.default' => 'audit-cache', 'cache.stores.audit-cache' => ['driver' => $driver]]);

        $events = self::events($this->register());

        self::assertCount(3, $events);

        foreach ($events as $command => $event) {
            self::assertSame($shared, $event->onOneServer, $command);
        }
    }

    /**
     * Every run starts in the background, so a long sweep or verification never
     * holds up the application's tasks due in the same minute.
     *
     * @return void
     */
    public function testEveryRunIsInTheBackground(): void
    {
        $events = self::events($this->register());

        self::assertCount(3, $events);

        foreach ($events as $command => $event) {
            self::assertTrue($event->runInBackground, $command);
        }
    }

    /**
     * Rows of `[default store's driver, the scheduler's store's driver, kept to
     * one server]`: the store the scheduler takes its locks in decides, never
     * the default store.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideSchedulerStores(): iterable
    {
        yield from [
            'a shared scheduler store beside a local default' => ['file', 'redis', true],
            'a local scheduler store beside a shared default' => ['redis', 'file', false],
        ];
    }

    /**
     * Each run is kept to one server exactly when the store the scheduler's
     * locks are taken in, as `Schedule::useCache()` set it, is shared, whatever
     * the default store is.
     *
     * @param  string  $default
     * @param  string  $scheduler
     * @param  bool  $shared
     * @return void
     */
    #[DataProvider('provideSchedulerStores')]
    public function testTheSchedulersStoreDecidesOneServer(string $default, string $scheduler, bool $shared): void
    {
        $this->config()->set([
            'cache.default'                => 'default-store',
            'cache.stores.default-store'   => ['driver' => $default],
            'cache.stores.scheduler-store' => ['driver' => $scheduler],
        ]);

        $schedule = (new Schedule)->useCache('scheduler-store');

        $this->schedule()->register($schedule);

        foreach (self::events($schedule) as $command => $event) {
            self::assertSame($shared, $event->onOneServer, $command);
        }
    }

    /**
     * A scheduler whose locks the cache does not back says nothing of a shared
     * store, so no run is kept to one server, even on a shared default store.
     *
     * @return void
     */
    public function testAMutexTheCacheDoesNotBackKeepsNoRunToOneServer(): void
    {
        $this->config()->set(['cache.default' => 'audit-cache', 'cache.stores.audit-cache' => ['driver' => 'redis']]);
        $this->app?->instance(EventMutex::class, \Mockery::mock(EventMutex::class));

        $events = self::events($this->register());

        self::assertCount(3, $events);

        foreach ($events as $command => $event) {
            self::assertFalse($event->onOneServer, $command);
        }
    }

    /**
     * A default cache store that is not named, or names no configured store,
     * keeps no run to one server.
     *
     * @return void
     */
    public function testAnUnnamedOrUnconfiguredCacheStoreIsNotShared(): void
    {
        $this->config()->set('cache.default', null);

        foreach (self::events($this->register()) as $command => $event) {
            self::assertFalse($event->onOneServer, $command);
        }

        $this->config()->set('cache.default', 'absent');

        foreach (self::events($this->register()) as $command => $event) {
            self::assertFalse($event->onOneServer, $command);
        }
    }

    /**
     * A default cache store that is not a string is not read as a name, even
     * one that would print as the name of a shared store, since the cache
     * manager would not resolve it.
     *
     * @return void
     */
    public function testACacheStoreThatIsNotAStringIsNotShared(): void
    {
        $this->config()->set([
            'cache.default' => new class implements \Stringable {
                /**
                 * The name of a shared store.
                 *
                 * @return string
                 */
                #[\Override]
                public function __toString(): string
                {
                    return 'shared';
                }
            },
            'cache.stores.shared' => ['driver' => 'redis'],
        ]);

        $events = self::events($this->register());

        self::assertCount(3, $events);

        foreach ($events as $command => $event) {
            self::assertFalse($event->onOneServer, $command);
        }
    }

    /**
     * The shared drivers are the ones the framework can lock across servers.
     *
     * @return void
     */
    public function testTheSharedDriversAreListed(): void
    {
        self::assertSame(['redis', 'memcached', 'database', 'dynamodb'], IntegritySchedule::SHARED_CACHE_DRIVERS);
    }

    /**
     * A malformed schedule schedules nothing for its run and is reported, by
     * its key and never its value, and registering throws nothing.
     *
     * @return void
     */
    public function testAMalformedScheduleSchedulesNothingAndIsReported(): void
    {
        $this->config()->set('audit-log.integrity.seal.schedule', 'every five minutes');

        $runs = self::runs($this->register());

        self::assertArrayNotHasKey('audit-log:seal', $runs);
        self::assertSame([self::MALFORMED_SEAL], $this->reported);
        self::assertStringNotContainsString('every five minutes', implode(' ', $this->reported));
    }

    /**
     * The runs whose settings are well formed are registered beside a malformed
     * one, and a schedule that is not a string is refused as well.
     *
     * @return void
     */
    public function testTheOtherRunsSurviveAMalformedOne(): void
    {
        $this->config()->set('audit-log.integrity.seal.sweep_schedule', ['15 3 * * *']);

        self::assertSame([
            'audit-log:seal'                          => '*/5 * * * *',
            'audit-log:verify --strict --sweep-first' => '45 3 * * *',
        ], self::runs($this->register()));
        self::assertSame(['`audit-log.integrity.seal.sweep_schedule` must be a cron expression, or null or empty to schedule nothing.'], $this->reported);
    }

    /**
     * Every schedule malformed registers nothing and reports each, in the order
     * the runs are registered.
     *
     * @return void
     */
    public function testEveryMalformedScheduleIsReported(): void
    {
        $this->config()->set([
            'audit-log.integrity.seal.schedule'       => '61 * * * *',
            'audit-log.integrity.seal.sweep_schedule' => 42,
            'audit-log.integrity.verify.schedule'     => 'daily',
        ]);

        self::assertSame([], self::runs($this->register()));
        self::assertSame([
            self::MALFORMED_SEAL,
            '`audit-log.integrity.seal.sweep_schedule` must be a cron expression, or null or empty to schedule nothing.',
            '`audit-log.integrity.verify.schedule` must be a cron expression, or null or empty to schedule nothing.',
        ], $this->reported);
    }

    /**
     * Registering reads configuration only: it issues no query.
     *
     * @return void
     */
    public function testRegisteringMakesNoQuery(): void
    {
        $this->config()->set(['cache.default' => 'audit-cache', 'cache.stores.audit-cache' => ['driver' => 'database']]);

        $statements = 0;

        DB::listen(static function () use (&$statements): void {
            $statements++;
        });

        $this->register();

        self::assertSame(0, $statements);
    }

    /**
     * `schedule:list` lists the three runs and exits 0, so the application's
     * own schedule resolves with them.
     *
     * @return void
     */
    public function testScheduleListShowsTheRuns(): void
    {
        $exit   = Artisan::call('schedule:list');
        $output = Artisan::output();

        self::assertSame(0, $exit);
        self::assertStringContainsString('audit-log:seal', $output);
        self::assertStringContainsString('audit-log:seal --sweep', $output);
        self::assertStringContainsString('audit-log:verify --strict', $output);
    }

    /**
     * `schedule:list` still exits 0 beside a malformed schedule, listing the
     * runs that are well formed.
     *
     * @return void
     */
    public function testScheduleListSurvivesAMalformedSchedule(): void
    {
        $this->config()->set('audit-log.integrity.verify.schedule', 'nightly');
        $this->app?->instance(ExceptionHandler::class, $this->handler());
        $this->app?->forgetInstance(Schedule::class);

        $exit   = Artisan::call('schedule:list');
        $output = Artisan::output();

        self::assertSame(0, $exit);
        self::assertStringContainsString('audit-log:seal --sweep', $output);
        self::assertStringNotContainsString('audit-log:verify', $output);
        self::assertSame(['`audit-log.integrity.verify.schedule` must be a cron expression, or null or empty to schedule nothing.'], $this->reported);
    }

    /**
     * Rows of `[the retention settings, whether the prune is scheduled]`: the
     * configured policy is pruned only when the default retention, or a
     * category's, is a number of days.
     *
     * @return iterable<string, array{0: array<string, array<string, int>|int>, 1: bool}>
     */
    public static function provideRetentions(): iterable
    {
        yield from [
            'nothing set'                                => [[], false],
            'everything kept forever'                    => [['after_days' => 0, 'categories' => ['security' => 0]], false],
            'a preservation alone'                       => [['preserve' => ['security' => 0]], false],
            'a default retention'                        => [['after_days' => 365], true],
            'one category kept for less'                 => [['categories' => ['security' => 30]], true],
            'a category kept for less, the rest forever' => [['after_days' => 0, 'categories' => ['audit' => 0, 'security' => 1]], true],
        ];
    }

    /**
     * The configured policy's prune is scheduled, at its default expression,
     * exactly when something is retained for less than forever.
     *
     * @param  array<string, array<string, int>|int>  $retention
     * @param  bool  $scheduled
     * @return void
     */
    #[DataProvider('provideRetentions')]
    public function testThePruneIsScheduledOnlyWhenSomethingIsRetainedForLess(array $retention, bool $scheduled): void
    {
        $this->useConfiguredPolicy();

        foreach ($retention as $setting => $value) {
            $this->config()->set('audit-log.retention.' . $setting, $value);
        }

        $runs = self::runs($this->register());

        self::assertSame($scheduled ? self::PRUNE_DEFAULT : null, $runs['audit-log:prune'] ?? null);
        self::assertCount($scheduled ? 4 : 3, $runs);
        self::assertSame([], $this->reported);
    }

    /**
     * Whether the prune can delete something is read whatever its schedule:
     * with the configured policy, exactly when something is retained for less
     * than forever, even with no prune scheduled.
     *
     * @param  array<string, array<string, int>|int>  $retention
     * @param  bool  $scheduled
     * @return void
     */
    #[DataProvider('provideRetentions')]
    public function testThePruneCanDeleteWhateverItsSchedule(array $retention, bool $scheduled): void
    {
        $this->useConfiguredPolicy();
        $this->config()->set('audit-log.retention.schedule', null);

        foreach ($retention as $setting => $value) {
            $this->config()->set('audit-log.retention.' . $setting, $value);
        }

        self::assertSame($scheduled, $this->schedule()->prunes());
    }

    /**
     * A policy left unbound counts as the configured one: it is scheduled
     * exactly when the configuration keeps something for less than forever.
     *
     * @return void
     */
    public function testAnUnboundPolicyCountsAsTheConfiguredOne(): void
    {
        $this->app?->offsetUnset(RetentionPolicy::class);

        self::assertArrayNotHasKey('audit-log:prune', self::runs($this->register()));

        $this->config()->set('audit-log.retention.after_days', 90);

        self::assertSame(self::PRUNE_DEFAULT, self::runs($this->register())['audit-log:prune'] ?? null);
        self::assertSame([], $this->reported);
    }

    /**
     * A custom policy's prune is always scheduled, whatever the configuration
     * keeps, since its answers cannot be known ahead; the policy is resolved
     * but never asked.
     *
     * @return void
     */
    public function testACustomPolicyIsAlwaysScheduled(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldNotReceive('version', 'retainFor', 'preserveFor');

        $this->app?->instance(RetentionPolicy::class, $policy);
        $this->config()->set(['audit-log.retention.after_days' => 0, 'audit-log.retention.schedule' => '0 2 * * 6']);

        self::assertSame('0 2 * * 6', self::runs($this->register())['audit-log:prune'] ?? null);
        self::assertSame([], $this->reported);
    }

    /**
     * A bound policy that cannot be resolved is reported and the prune is still
     * scheduled, so the run refuses the policy and records it; the other runs
     * are registered and nothing is thrown.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAPolicyThatCannotBeResolvedIsReportedAndThePruneScheduled(): void
    {
        $this->app?->bind(RetentionPolicy::class, static fn (): RetentionPolicy => throw new \RuntimeException('The policy cannot be built.'));

        $runs = self::runs($this->register());

        self::assertSame(self::PRUNE_DEFAULT, $runs['audit-log:prune'] ?? null);
        self::assertCount(4, $runs);
        self::assertSame(['The policy cannot be built.'], $this->reported);
    }

    /**
     * Rows of `[the policy bound, the schedule setting]`: `null` and the empty
     * string an empty env line gives, under the configured policy keeping
     * something for less and under a custom one.
     *
     * @return iterable<string, array{0: bool, 1: ?string}>
     */
    public static function provideNullSchedules(): iterable
    {
        yield from [
            'the configured policy at null' => [false, null],
            'the configured policy empty'   => [false, ''],
            'a custom policy at null'       => [true, null],
            'a custom policy empty'         => [true, ''],
        ];
    }

    /**
     * A prune schedule of `null` or empty registers no prune, whatever the
     * policy, reports nothing and leaves the other runs registered.
     *
     * @param  bool  $custom
     * @param  ?string  $value
     * @return void
     */
    #[DataProvider('provideNullSchedules')]
    public function testANullScheduleRegistersNoPrune(bool $custom, ?string $value): void
    {
        $custom ? $this->app?->instance(RetentionPolicy::class, \Mockery::mock(RetentionPolicy::class)) : $this->useConfiguredPolicy();

        $this->config()->set(['audit-log.retention.after_days' => 30, 'audit-log.retention.schedule' => $value]);

        $runs = self::runs($this->register());

        self::assertArrayNotHasKey('audit-log:prune', $runs);
        self::assertCount(3, $runs);
        self::assertSame([], $this->reported);
    }

    /**
     * Rows of `[the setting, its malformed value, the message reported]`: the
     * schedule itself, and a retention the configured policy's decision reads
     * with every other retention kept forever.
     *
     * @return iterable<string, array{0: string, 1: int|list<int|string>|string, 2: string}>
     */
    public static function provideMalformedPruneSettings(): iterable
    {
        yield from [
            'a schedule that is no cron'    => ['schedule', 'nightly', self::MALFORMED_PRUNE],
            'a schedule out of range'       => ['schedule', '30 25 * * *', self::MALFORMED_PRUNE],
            'a schedule that is a list'     => ['schedule', ['30 3 * * *'], self::MALFORMED_PRUNE],
            'a retention out of range'      => ['after_days', 36501, '`audit-log.retention.after_days` must be an integer from 0 to 36500.'],
            'a category map that is a list' => ['categories', [30], self::MALFORMED_CATEGORIES],
        ];
    }

    /**
     * A malformed prune setting registers no prune and is reported, by its key
     * and never its value; the other runs are registered and nothing is thrown.
     *
     * @param  string  $setting
     * @param  int|list<int|string>|string  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedPruneSettings')]
    public function testAMalformedScheduleIsReportedAndRegistersNothing(string $setting, array|int|string $value, string $message): void
    {
        $this->useConfiguredPolicy();
        $this->config()->set('audit-log.retention.' . $setting, $value);

        if ($setting === 'schedule') {
            $this->config()->set('audit-log.retention.after_days', 30);
        }

        $runs = self::runs($this->register());

        self::assertArrayNotHasKey('audit-log:prune', $runs);
        self::assertCount(3, $runs);
        self::assertSame([$message], $this->reported);
    }

    /**
     * The prune starts in the background, is kept from overlapping itself for
     * 23 hours, inside the day between runs, and on a shared cache runs on one
     * server only.
     *
     * @return void
     */
    public function testThePruneRunsInTheBackgroundWithoutOverlapOnOneServer(): void
    {
        $this->useConfiguredPolicy();
        $this->config()->set([
            'audit-log.retention.after_days' => 365,
            'cache.default'                  => 'audit-cache',
            'cache.stores.audit-cache'       => ['driver' => 'redis'],
        ]);

        $prune = self::events($this->register())['audit-log:prune'] ?? null;

        self::assertInstanceOf(ScheduledEvent::class, $prune);
        self::assertTrue($prune->runInBackground);
        self::assertTrue($prune->withoutOverlapping);
        self::assertSame(1380, $prune->expiresAt);
        self::assertTrue($prune->onOneServer);

        $this->config()->set('cache.stores.audit-cache.driver', 'file');

        $prune = self::events($this->register())['audit-log:prune'] ?? null;

        self::assertInstanceOf(ScheduledEvent::class, $prune);
        self::assertFalse($prune->onOneServer);
    }

    /**
     * Registering the prune, under the configured policy or a custom one,
     * issues no query.
     *
     * @return void
     */
    public function testRegisteringThePruneMakesNoQuery(): void
    {
        $this->config()->set([
            'audit-log.retention.after_days' => 30,
            'cache.default'                  => 'audit-cache',
            'cache.stores.audit-cache'       => ['driver' => 'database'],
        ]);

        $statements = 0;

        DB::listen(static function () use (&$statements): void {
            $statements++;
        });

        $this->useConfiguredPolicy();
        self::assertArrayHasKey('audit-log:prune', self::runs($this->register()));

        $this->app?->instance(RetentionPolicy::class, \Mockery::mock(RetentionPolicy::class));
        self::assertArrayHasKey('audit-log:prune', self::runs($this->register()));

        self::assertSame(0, $statements);
    }

    /**
     * `schedule:list` lists the prune beside the other runs once something is
     * kept for less than forever.
     *
     * @return void
     */
    public function testScheduleListShowsThePrune(): void
    {
        $this->config()->set('audit-log.retention.after_days', 365);
        $this->app?->forgetInstance(Schedule::class);

        $exit   = Artisan::call('schedule:list');
        $output = Artisan::output();

        self::assertSame(0, $exit);
        self::assertStringContainsString('audit-log:prune', $output);
        self::assertStringContainsString('audit-log:seal --sweep', $output);
    }

    /**
     * Register the package's runs on a schedule of their own, with a handler
     * that keeps what it is given to report.
     *
     * @return \Illuminate\Console\Scheduling\Schedule
     */
    private function register(): Schedule
    {
        $schedule = new Schedule;

        $this->schedule()->register($schedule);

        return $schedule;
    }

    /**
     * The package's schedule over the application's configuration and
     * container, with a handler that keeps what it is given to report.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\IntegritySchedule
     */
    private function schedule(): IntegritySchedule
    {
        $config = $this->config();

        return new IntegritySchedule(new SealSettings($config), new RetentionSettings($config), app(Container::class), $config, $this->handler());
    }

    /**
     * A handler that keeps the message of each exception it is given to report.
     *
     * @return \Illuminate\Contracts\Debug\ExceptionHandler
     */
    private function handler(): ExceptionHandler
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(function (\Throwable $exception): void {
            $this->reported[] = $exception->getMessage();
        });

        return $handler;
    }

    /**
     * The runs on the schedule, each command after `artisan` with its cron
     * expression.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return array<string, string>
     */
    private static function runs(Schedule $schedule): array
    {
        return array_map(static fn (ScheduledEvent $event): string => $event->expression, self::events($schedule));
    }

    /**
     * The events on the schedule, by the command each runs after `artisan`.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return array<string, \Illuminate\Console\Scheduling\Event>
     */
    private static function events(Schedule $schedule): array
    {
        $events = [];

        foreach ($schedule->events() as $event) {

            if (preg_match('/\'artisan\' (.+)\z/', (string) $event->command, $matches) !== 1) {
                continue;
            }

            $events[$matches[1]] = $event;
        }

        return $events;
    }

    /**
     * Bind the policy the package binds, the configured one.
     *
     * @return void
     */
    private function useConfiguredPolicy(): void
    {
        $this->app?->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
