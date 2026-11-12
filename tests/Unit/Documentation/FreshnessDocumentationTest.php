<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\FreshnessSignal;

/**
 * A drift guard for the freshness check in the operations guide and the README:
 * it catches an omission or a rename, not wrong prose.
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
     * Rows of `[text]`: every option, signal, status, field and setting.
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
     * The rows come from the command and the signal, so the check is not empty.
     *
     * @return void
     */
    public function testTheRowsAreWhatTheCodeDeclares(): void
    {
        self::assertSame(['freshness', 'json'], array_keys((new CheckCommand)->getDefinition()->getOptions()));
        self::assertSame(['ok', 'stale', 'failed', 'never_run', 'not_applicable'], self::statuses());
    }

    /**
     * The monitoring section leads with the freshness check, ranges and clocks.
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
     * The scale section rules out partitioning: the key is `id` alone.
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
     * The README names the freshness check and each monitoring env var.
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
