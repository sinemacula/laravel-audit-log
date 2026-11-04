<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\FreshnessChecks;
use SineMacula\Laravel\AuditLog\Console\IntegritySchedule;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:check --freshness`: each signal is ok within its
 * limit, stale past it, failed when its run says so and never run without
 * progress, which is a problem only when its run is scheduled and the log's
 * oldest entry is past the limit; a disabled schedule is still judged; the
 * outbox is judged only in outbox mode; `--json` writes the closed list of
 * fields; a malformed setting fails the run under `[config]`; the ordinary
 * check runs no freshness check; and nothing is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessChecks::class)]
#[CoversClass(CheckCommand::class)]
final class FreshnessChecksTest extends TestCase
{
    /** @var string The time every check is judged at, in UTC. */
    private const string NOW = '2026-11-04 12:00:00.000000';

    /** @var int The default sealing limit, in seconds: 30 minutes. */
    private const int SEAL_LIMIT = 1800;

    /** @var int The default daily limit, in seconds: a day and two hours. */
    private const int DAILY_LIMIT = 93600;

    /** @var int The default outbox limit, in seconds: 15 minutes. */
    private const int OUTBOX_LIMIT = 900;

    /** @var string What a malformed schedule must be, after its key. */
    private const string CRON = 'must be a cron expression, or null or empty to schedule nothing.';

    /** @var list<string> What a fresh install prints: nothing has run, nothing is due, and the optional signals do not apply. */
    private const array FRESH_INSTALL = [
        '[freshness] sealing: never_run (limit 1800s)',
        '[freshness] sweep: never_run (limit 93600s)',
        '[freshness] verification: never_run (limit 93600s)',
        '[freshness] retention: not_applicable',
        '[freshness] anchoring: not_applicable',
        '[freshness] outbox: not_applicable',
    ];

    /**
     * Register the command with the console kernel, freeze the clock, and bind
     * the retention policy the package binds by default.
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

        app()->instance(Clock::class, FrozenClock::at(self::NOW));

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * A fresh install has recorded nothing and holds no entry, so nothing is
     * stale and the run passes.
     *
     * @return void
     */
    public function testAFreshInstallIsNotStale(): void
    {
        self::assertSame([0, self::FRESH_INSTALL], $this->freshness());
    }

    /**
     * Every signal within its limit is ok, with its age and its limit, and the
     * run passes.
     *
     * @return void
     */
    public function testEverySignalWithinItsLimitIsOk(): void
    {
        $this->everythingApplies();
        $this->recordEveryRun(60);
        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000001', 120);

        self::assertSame([0, [
            '[freshness] sealing: ok (age 60s, limit 1800s)',
            '[freshness] sweep: ok (age 60s, limit 93600s)',
            '[freshness] verification: ok (age 60s, limit 93600s)',
            '[freshness] retention: ok (age 60s, limit 93600s)',
            '[freshness] anchoring: ok (age 60s)',
            '[freshness] outbox: ok (age 120s, limit 900s)',
        ]], $this->freshness());
    }

    /**
     * Rows of `[the progress name, its other fields, the signal, its limit]`:
     * each signal judged by its age against a limit.
     *
     * @return iterable<string, array{0: string, 1: array<string, bool|string>, 2: string, 3: int}>
     */
    public static function provideAgedSignals(): iterable
    {
        yield from [
            'sealing'      => [IntegrityProgress::SEAL_LAST_RUN, [], 'sealing', self::SEAL_LIMIT],
            'sweep'        => [IntegrityProgress::SWEEP_COMPLETED, [], 'sweep', self::DAILY_LIMIT],
            'verification' => [IntegrityProgress::VERIFY_LAST_FULL, ['passed' => true], 'verification', self::DAILY_LIMIT],
            'retention'    => [IntegrityProgress::RETENTION_LAST_RUN, ['status' => 'complete'], 'retention', self::DAILY_LIMIT],
        ];
    }

    /**
     * Each signal is ok at its limit and stale one second past it, which fails
     * the run.
     *
     * @param  string  $name
     * @param  array<string, bool|string>  $fields
     * @param  string  $signal
     * @param  int  $limit
     * @return void
     */
    #[DataProvider('provideAgedSignals')]
    public function testEachSignalIsStalePastItsLimit(string $name, array $fields, string $signal, int $limit): void
    {
        $this->everythingApplies();
        $this->recordEveryRun(60);
        $this->record($name, $limit, $fields);

        [$code, $output] = $this->freshness();

        self::assertSame(0, $code);
        self::assertContains(sprintf('[freshness] %s: ok (age %ds, limit %ds)', $signal, $limit, $limit), $output);

        $this->record($name, $limit + 1, $fields);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains(sprintf('[freshness] %s: stale (age %ds, limit %ds)', $signal, $limit + 1, $limit), $output);
    }

    /**
     * A verification that did not pass is failed, however recent, and fails the
     * run.
     *
     * @return void
     */
    public function testAVerificationThatDidNotPassFails(): void
    {
        $this->recordEveryRun(60);
        $this->record(IntegrityProgress::VERIFY_LAST_FULL, 60, ['passed' => false, 'strict' => true]);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] verification: failed (age 60s, limit 93600s)', $output);
    }

    /**
     * A prune run that failed is failed, however recent, and a partial one is
     * ok.
     *
     * @return void
     */
    public function testAFailedPruneFails(): void
    {
        $this->everythingApplies();
        $this->recordEveryRun(60);
        $this->record(IntegrityProgress::RETENTION_LAST_RUN, 60, ['status' => 'partial']);

        self::assertSame(0, $this->freshness()[0]);

        $this->record(IntegrityProgress::RETENTION_LAST_RUN, 60, ['status' => 'failed']);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] retention: failed (age 60s, limit 93600s)', $output);
    }

    /**
     * Retention applies only once something is kept for less than forever, or a
     * policy of the application's own is bound.
     *
     * @return void
     */
    public function testRetentionAppliesOnlyWhenThePruneCanDelete(): void
    {
        $this->record(IntegrityProgress::RETENTION_LAST_RUN, self::DAILY_LIMIT + 1);

        self::assertContains('[freshness] retention: not_applicable', $this->freshness()[1]);

        $this->app?->bind(RetentionPolicy::class, static fn (): RetentionPolicy => self::createStub(RetentionPolicy::class));

        self::assertTrue(app(IntegritySchedule::class)->prunes());
        self::assertContains('[freshness] retention: stale (age 93601s, limit 93600s)', $this->freshness()[1]);
    }

    /**
     * Anchoring fails while the last failure to anchor is newer than the last
     * seal anchored, or there is a failure and no seal anchored, and is ok once
     * a seal is anchored after it; it has no limit.
     *
     * @return void
     */
    public function testAnAnchorFailureNewerThanTheLastAnchoringFails(): void
    {
        $this->app?->instance(CheckpointAnchor::class, new RecordingAnchor);

        self::assertContains('[freshness] anchoring: never_run', $this->freshness()[1]);

        $this->record(IntegrityProgress::ANCHOR_LAST_FAILURE, 600, ['sequence' => 3, 'class' => \RuntimeException::class]);

        self::assertContains('[freshness] anchoring: failed', $this->freshness()[1]);

        $this->record(IntegrityProgress::ANCHOR_LAST, 900, ['sequence' => 2, 'anchor' => 'recording'], 'anchored_at');

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] anchoring: failed (age 900s)', $output);

        $this->record(IntegrityProgress::ANCHOR_LAST, 300, ['sequence' => 3, 'anchor' => 'recording'], 'anchored_at');

        self::assertContains('[freshness] anchoring: ok (age 300s)', $this->freshness()[1]);
    }

    /**
     * An anchor that cannot be resolved anchors nothing, so anchoring fails.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAnAnchorThatCannotBeResolvedFails(): void
    {
        $this->app?->bind(CheckpointAnchor::class, static fn (): never => throw new \RuntimeException('no anchor'));

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] anchoring: failed', $output);
    }

    /**
     * A run that never ran is a problem once its run is scheduled and the log's
     * oldest entry is older than its limit, and not while the entry is within
     * it.
     *
     * @return void
     */
    public function testANeverRunSignalIsAProblemOnceTheLogIsOlderThanItsLimit(): void
    {
        $this->entryRecorded(self::SEAL_LIMIT);

        self::assertSame([0, self::FRESH_INSTALL], $this->freshness());

        $this->entryRecorded(self::SEAL_LIMIT + 1);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertSame(self::FRESH_INSTALL, $output);
    }

    /**
     * A run whose package schedule is disabled is no problem for never having
     * run, but is still judged by what it recorded, since it runs elsewhere.
     *
     * @return void
     */
    public function testADisabledScheduleIsStillChecked(): void
    {
        $this->config()->set([
            'audit-log.integrity.seal.schedule'       => null,
            'audit-log.integrity.seal.sweep_schedule' => '',
            'audit-log.integrity.verify.schedule'     => null,
        ]);

        $this->entryRecorded(self::DAILY_LIMIT + 1);

        self::assertSame([0, self::FRESH_INSTALL], $this->freshness());

        $this->record(IntegrityProgress::SEAL_LAST_RUN, self::SEAL_LIMIT + 1);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] sealing: stale (age 1801s, limit 1800s)', $output);
    }

    /**
     * In outbox mode the oldest row that has not failed is judged by when it
     * fell due; a failed row is not waiting for a drain, and an empty outbox is
     * ok.
     *
     * @return void
     */
    public function testTheOutboxBacklogIsJudgedInOutboxMode(): void
    {
        $this->config()->set('audit-log.delivery.mode', 'outbox');

        self::assertContains('[freshness] outbox: ok (limit 900s)', $this->freshness()[1]);

        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000001', 7200, 7000);
        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000002', self::OUTBOX_LIMIT);

        self::assertContains('[freshness] outbox: ok (age 900s, limit 900s)', $this->freshness()[1]);

        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000003', self::OUTBOX_LIMIT + 1);

        [$code, $output] = $this->freshness();

        self::assertSame(1, $code);
        self::assertContains('[freshness] outbox: stale (age 901s, limit 900s)', $output);
    }

    /**
     * Out of outbox mode the outbox is not judged, whatever it holds.
     *
     * @return void
     */
    public function testTheOutboxIsNotJudgedInSyncMode(): void
    {
        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000001', 86400);

        self::assertSame([0, self::FRESH_INSTALL], $this->freshness());
    }

    /**
     * The monitoring settings set the limits, read in minutes.
     *
     * @return void
     */
    public function testTheLimitsAreTheMonitoringSettings(): void
    {
        $this->config()->set([
            'audit-log.monitor.seal_minutes'   => 5,
            'audit-log.monitor.daily_minutes'  => '60',
            'audit-log.monitor.outbox_minutes' => 1,
            'audit-log.delivery.mode'          => 'outbox',
        ]);

        self::assertSame([
            '[freshness] sealing: never_run (limit 300s)',
            '[freshness] sweep: never_run (limit 3600s)',
            '[freshness] verification: never_run (limit 3600s)',
            '[freshness] retention: not_applicable',
            '[freshness] anchoring: not_applicable',
            '[freshness] outbox: ok (limit 60s)',
        ], $this->freshness()[1]);
    }

    /**
     * Rows of `[the malformed setting, its value, the problem]`.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'a seal limit too short'    => ['monitor.seal_minutes', 4, '[config] `audit-log.monitor.seal_minutes` must be an integer from 5 to 1440.'],
            'a daily limit too long'    => ['monitor.daily_minutes', 10081, '[config] `audit-log.monitor.daily_minutes` must be an integer from 60 to 10080.'],
            'an outbox limit of words'  => ['monitor.outbox_minutes', 'soon', '[config] `audit-log.monitor.outbox_minutes` must be an integer from 1 to 1440.'],
            'a malformed seal schedule' => ['integrity.seal.schedule', 'often', '[config] `audit-log.integrity.seal.schedule` ' . self::CRON],
        ];
    }

    /**
     * A malformed setting fails the run, named under `config` by its key and
     * never its value, and no signal is printed.
     *
     * @param  string  $setting
     * @param  int|string  $value
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedSettingFailsTheRun(string $setting, int|string $value, string $problem): void
    {
        $this->config()->set('audit-log.' . $setting, $value);

        self::assertSame([1, [$problem]], $this->freshness());
        self::assertSame([1, [$problem]], $this->freshness(['--json' => true]));
    }

    /**
     * Progress that cannot be read fails the run, named by the class of what
     * was thrown and never the statement.
     *
     * @return void
     */
    public function testProgressThatCannotBeReadFailsTheRun(): void
    {
        $this->config()->set('audit-log.integrity.state_table', 'audit_absent_state');

        self::assertSame([1, ['[freshness] The progress could not be read (Illuminate\Database\QueryException).']], $this->freshness());
    }

    /**
     * With `--json` each signal is one JSON object of exactly its name, its
     * status, its age and its limit in seconds, `null` where it has none, and
     * the exit code is the same.
     *
     * @return void
     */
    public function testJsonWritesTheClosedListOfFields(): void
    {
        $this->record(IntegrityProgress::SEAL_LAST_RUN, self::SEAL_LIMIT + 1);

        [$code, $output] = $this->freshness(['--json' => true]);

        $rows = array_map(static fn (string $line): mixed => json_decode($line, true, 512, JSON_THROW_ON_ERROR), $output);

        self::assertSame(1, $code);
        self::assertSame([
            ['signal' => 'sealing', 'status' => 'stale', 'age_seconds' => 1801, 'limit_seconds' => 1800],
            ['signal' => 'sweep', 'status' => 'never_run', 'age_seconds' => null, 'limit_seconds' => 93600],
            ['signal' => 'verification', 'status' => 'never_run', 'age_seconds' => null, 'limit_seconds' => 93600],
            ['signal' => 'retention', 'status' => 'not_applicable', 'age_seconds' => null, 'limit_seconds' => null],
            ['signal' => 'anchoring', 'status' => 'not_applicable', 'age_seconds' => null, 'limit_seconds' => null],
            ['signal' => 'outbox', 'status' => 'not_applicable', 'age_seconds' => null, 'limit_seconds' => null],
        ], $rows);
    }

    /**
     * The ordinary check runs no freshness check, so stale progress never fails
     * a deploy, and `--json` without `--freshness` is refused.
     *
     * @return void
     */
    public function testTheOrdinaryCheckRunsNoFreshnessCheck(): void
    {
        $this->record(IntegrityProgress::SEAL_LAST_RUN, self::SEAL_LIMIT + 1);

        $kernel = $this->kernel();

        $kernel->call('audit-log:check');

        self::assertStringNotContainsString('[freshness]', $kernel->output());

        self::assertSame(2, $kernel->call('audit-log:check', ['--json' => true]));
        self::assertStringContainsString('`--json` is given only with `--freshness`.', $kernel->output());
    }

    /**
     * A run writes nothing: the progress and the outbox are as they were.
     *
     * @return void
     */
    public function testNothingIsWritten(): void
    {
        $this->config()->set('audit-log.delivery.mode', 'outbox');
        $this->everythingApplies();
        $this->recordEveryRun(self::DAILY_LIMIT + 1);
        $this->dueInTheOutbox('0195f4a2-7b1c-7000-8000-000000000001', 7200);
        $this->entryRecorded(self::DAILY_LIMIT + 1);

        $before = [DB::table(IntegrityTables::stateTable())->orderBy('name')->get()->all(), DB::table('audit_log_outbox')->get()->all()];

        self::assertSame(1, $this->freshness()[0]);
        self::assertEquals($before, [DB::table(IntegrityTables::stateTable())->orderBy('name')->get()->all(), DB::table('audit_log_outbox')->get()->all()]);
    }

    /**
     * Make every optional signal apply: entries are kept for a finite time, an
     * anchor is bound and records go through the outbox.
     *
     * @return void
     */
    private function everythingApplies(): void
    {
        $this->config()->set(['audit-log.retention.after_days' => 30, 'audit-log.delivery.mode' => 'outbox']);

        $this->app?->instance(CheckpointAnchor::class, new RecordingAnchor);
    }

    /**
     * Record every run the signals read as having ended the seconds given ago,
     * passing.
     *
     * @param  int  $ago
     * @return void
     */
    private function recordEveryRun(int $ago): void
    {
        $this->record(IntegrityProgress::SEAL_LAST_RUN, $ago, ['seals' => 1, 'entries' => 1, 'sweep' => false]);
        $this->record(IntegrityProgress::SWEEP_COMPLETED, $ago);
        $this->record(IntegrityProgress::VERIFY_LAST_FULL, $ago, ['head' => 1, 'passed' => true, 'strict' => true]);
        $this->record(IntegrityProgress::RETENTION_LAST_RUN, $ago, ['run_id' => 'run', 'status' => 'complete', 'deleted' => 0, 'cursor' => null]);
        $this->record(IntegrityProgress::ANCHOR_LAST, $ago, ['sequence' => 1, 'anchor' => 'recording'], 'anchored_at');
    }

    /**
     * Record progress under the name, its time the seconds given ago under the
     * field given, with the other fields given.
     *
     * @param  string  $name
     * @param  int  $ago
     * @param  array<string, scalar|null>  $fields
     * @param  string  $field
     * @return void
     */
    private function record(string $name, int $ago, array $fields = [], string $field = 'at'): void
    {
        $at = self::now()->subSeconds($ago);

        app(IntegrityProgress::class)->put($name, [$field => StoredTime::format($at), ...$fields], $at);
    }

    /**
     * Put a row in the outbox that fell due the seconds given ago, failed the
     * seconds given ago when given.
     *
     * @param  string  $id
     * @param  int  $dueAgo
     * @param  ?int  $failedAgo
     * @return void
     */
    private function dueInTheOutbox(string $id, int $dueAgo, ?int $failedAgo = null): void
    {
        DB::table('audit_log_outbox')->insert([
            'id'           => $id,
            'payload'      => 'payload',
            'attempts'     => 0,
            'available_at' => self::stored($dueAgo),
            'failed_at'    => $failedAgo === null ? null : self::stored($failedAgo),
            'created_at'   => self::stored($dueAgo),
        ]);
    }

    /**
     * Put an entry in the log recorded the seconds given ago; only its time is
     * read.
     *
     * @param  int  $ago
     * @return void
     */
    private function entryRecorded(int $ago): void
    {
        DB::table('audit_log_entries')->delete();

        DB::table('audit_log_entries')->insert([
            'id'                => '0195f4a2-7b1c-7000-8000-000000000001',
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'billing',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => self::stored($ago),
            'recorded_at'       => self::stored($ago),
            'integrity_version' => 1,
            'key_id'            => 'test-key',
            'hmac'              => str_repeat('a', 64),
        ]);
    }

    /**
     * Run `audit-log:check --freshness` with the options given and return its
     * exit code and its non-empty lines.
     *
     * @param  array<string, bool>  $options
     * @return array{0: int, 1: list<string>}
     */
    private function freshness(array $options = []): array
    {
        $kernel = $this->kernel();
        $code   = $kernel->call('audit-log:check', ['--freshness' => true, ...$options]);

        return [$code, array_values(array_filter(array_map(trim(...), explode("\n", $kernel->output())), static fn (string $line): bool => $line !== ''))];
    }

    /**
     * The console kernel.
     *
     * @return \Illuminate\Contracts\Console\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel;
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

    /**
     * The time the seconds given before the frozen time, as the database stores
     * it.
     *
     * @param  int  $ago
     * @return string
     */
    private static function stored(int $ago): string
    {
        return self::now()->subSeconds($ago)->format('Y-m-d H:i:s.u');
    }

    /**
     * The frozen time.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return new CarbonImmutable(self::NOW, 'UTC');
    }
}
