<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\FreshnessSignal;

/**
 * Unit tests that keep the documentation in step with the operations checks:
 * the operations guide's section on monitoring names each option of
 * `audit-log:check`, every freshness signal and status, every field `--json`
 * writes and every monitoring setting with its range, and says what a clock
 * must run; its section on scale says that partitioning is not supported; and
 * the README's usage names `audit-log:check --freshness` and has a row for each
 * monitoring setting with the env var the shipped file reads.
 *
 * A drift guard: it catches an omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class FreshnessDocumentationTest extends TestCase
{
    /** @var list<string> The freshness signals, in the order a run reports them. */
    private const array SIGNALS = ['sealing', 'sweep', 'verification', 'retention', 'anchoring', 'outbox'];

    /** @var list<string> The fields `--json` writes for each signal. */
    private const array FIELDS = ['signal', 'status', 'age_seconds', 'limit_seconds'];

    /** @var array<string, string> The env var of each monitoring setting, by its key under `audit-log.`. */
    private const array SETTINGS = [
        'monitor.seal_minutes'   => 'AUDIT_LOG_MONITOR_SEAL_MINUTES',
        'monitor.daily_minutes'  => 'AUDIT_LOG_MONITOR_DAILY_MINUTES',
        'monitor.outbox_minutes' => 'AUDIT_LOG_MONITOR_OUTBOX_MINUTES',
    ];

    /**
     * Rows of `[text]`: each option `audit-log:check` declares, each signal,
     * each status, each field and each monitoring setting, in code type.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNames(): iterable
    {
        foreach ((new CheckCommand)->getDefinition()->getOptions() as $option) {
            yield '--' . $option->getName() => ['`--' . $option->getName() . '`'];
        }

        foreach ([...self::SIGNALS, ...self::statuses(), ...self::FIELDS, ...array_keys(self::SETTINGS)] as $name) {
            yield $name => ['`' . $name . '`'];
        }
    }

    /**
     * Each name is in the operations guide's section on monitoring.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideNames')]
    public function testTheMonitorSectionNamesIt(string $text): void
    {
        self::assertStringContainsString($text, self::section('docs/guides/operations.md', 'Monitor'), sprintf('The operations guide does not name %s.', $text));
    }

    /**
     * The options are read from what the command declares, which are exactly
     * `--freshness` and `--json`, and the statuses from the signal's constants,
     * so the check above is not empty by construction.
     *
     * @return void
     */
    public function testTheRowsAreWhatTheCodeDeclares(): void
    {
        self::assertSame(['freshness', 'json'], array_keys((new CheckCommand)->getDefinition()->getOptions()));
        self::assertSame(['ok', 'stale', 'failed', 'never_run', 'not_applicable'], self::statuses());
    }

    /**
     * The section on monitoring leads with the freshness check, gives each
     * monitoring setting's range, and says that clocks run NTP and that an
     * entry far ahead is `future_unsealed`.
     *
     * @return void
     */
    public function testTheMonitorSectionLeadsWithTheFreshnessCheck(): void
    {
        $section = self::section('docs/guides/operations.md', 'Monitor');
        $prose   = (string) preg_replace('/\s+/', ' ', $section);

        self::assertLessThan(strpos($section, '`integrity.state_table`'), strpos($section, '`php artisan audit-log:check --freshness`'));

        self::assertStringContainsString('`monitor.seal_minutes` is 5 to 1440, `monitor.daily_minutes` 60 to 10080 and `monitor.outbox_minutes` 1 to 1440', $prose);

        self::assertStringContainsString('**Clocks.**', $section);
        self::assertStringContainsString('must run NTP', $prose);
        self::assertStringContainsString('`future_unsealed`', $prose);
    }

    /**
     * The section on scale says what one table holds, that pruning is batched,
     * where hundreds of millions of rows go, and that partitioning is not
     * supported because the primary key is `id` alone.
     *
     * @return void
     */
    public function testTheScaleSectionSaysPartitioningIsNotSupported(): void
    {
        $prose = (string) preg_replace('/\s+/', ' ', self::section('docs/guides/operations.md', 'Scale'));

        $statements = ['tens of millions of rows', '`retention.batch`', 'hundreds of millions of rows', 'warehouse or SIEM', 'Partitioning is not supported', 'is `id` alone'];

        foreach ($statements as $text) {
            self::assertStringContainsString($text, $prose);
        }
    }

    /**
     * The README's usage names the freshness check, and its configuration table
     * has a row for each monitoring setting naming the env var the shipped file
     * reads it from.
     *
     * @return void
     */
    public function testTheReadmeNamesTheFreshnessCheckAndItsSettings(): void
    {
        self::assertStringContainsString('`php artisan audit-log:check --freshness`', self::section('README.md', 'Usage'));

        $readme = self::read('README.md');
        $config = self::read('config/audit-log.php');

        foreach (self::SETTINGS as $key => $env) {
            self::assertMatchesRegularExpression('/^\| `' . preg_quote($key, '/') . '` +\| [^|]+\| `' . $env . '` +\|/m', $readme, $key);
            self::assertStringContainsString("env('{$env}',", $config, $key);
        }
    }

    /**
     * The statuses a signal may have, from its constants.
     *
     * @return list<string>
     */
    private static function statuses(): array
    {
        return array_values(array_filter((new \ReflectionClass(FreshnessSignal::class))->getConstants(), is_string(...)));
    }

    /**
     * The `## ` section of the file with the heading, up to the next one.
     *
     * @param  string  $path
     * @param  string  $heading
     * @return string
     */
    private static function section(string $path, string $heading): string
    {
        $text = self::read($path);

        self::assertSame(1, preg_match('/^## ' . preg_quote($heading, '/') . '\n(.*?)(?=^## |\z)/ms', $text, $matches), sprintf('%s has no section %s.', $path, $heading));

        return $matches[1];
    }

    /**
     * The file of the repository at the path.
     *
     * @param  string  $path
     * @return string
     */
    private static function read(string $path): string
    {
        $text = file_get_contents(dirname(__DIR__, 3) . '/' . $path);

        self::assertIsString($text);

        return $text;
    }
}
