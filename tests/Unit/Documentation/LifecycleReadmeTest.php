<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests that keep the README in step with the lifecycle: every leaf of the
 * lifecycle, retention and import settings has its row in the configuration
 * table with the env var the shipped file reads, or none for a map; the six
 * lifecycle commands, the facade's way into the lifecycle and the retention and
 * import guides are named, and each guide is there; and Laravel's
 * `model:prune`, which the package never used, is named nowhere.
 *
 * A drift guard: it catches an omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleReadmeTest extends TestCase
{
    /** @var list<string> The sections of the shipped configuration the lifecycle reads. */
    private const array SECTIONS = ['lifecycle', 'retention', 'import'];

    /** @var list<string> The lifecycle's commands. */
    private const array COMMANDS = ['audit-log:hold', 'audit-log:holds', 'audit-log:import', 'audit-log:prune', 'audit-log:reconcile', 'audit-log:release'];

    /** @var list<string> The guides the README links for the lifecycle. */
    private const array GUIDES = ['docs/guides/retention.md', 'docs/guides/import.md'];

    /**
     * Rows of `[leaf, the env var it reads or null for a map]`: every leaf of
     * the lifecycle, retention and import settings the shipped file holds.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideLeaves(): iterable
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);

        foreach (self::SECTIONS as $section) {
            self::assertIsArray($config[$section] ?? null, sprintf('The shipped configuration has no `%s` section.', $section));

            foreach (array_keys($config[$section]) as $key) {
                $leaf = $section . '.' . $key;

                yield $leaf => [$leaf, self::envOf($leaf)];
            }
        }
    }

    /**
     * Each leaf has its row in the README's configuration table, naming the env
     * var the shipped file reads it from, or `-` for a map, which has none.
     *
     * @param  string  $leaf
     * @param  ?string  $env
     * @return void
     */
    #[DataProvider('provideLeaves')]
    public function testEveryLifecycleRetentionAndImportLeafNamesItsEnvVarInTheReadme(string $leaf, ?string $env): void
    {
        $row = self::configurationRows()[$leaf] ?? null;

        self::assertNotNull($row, sprintf('The README\'s configuration table has no row for `%s`.', $leaf));
        self::assertSame($env === null ? '-' : '`' . $env . '`', $row[2], sprintf('The README names the wrong env var for `%s`.', $leaf));
    }

    /**
     * The leaves the provider yields are exactly the thirteen settings the
     * lifecycle, retention and import read, so a leaf dropped from the shipped
     * file and from the README together still fails.
     *
     * @return void
     */
    public function testTheLifecycleLeavesAreTheThirteenSettings(): void
    {
        self::assertSame([
            'lifecycle.journal_table' => 'AUDIT_LOG_LIFECYCLE_JOURNAL_TABLE',
            'lifecycle.holds_table'   => 'AUDIT_LOG_LIFECYCLE_HOLDS_TABLE',
            'lifecycle.lock_table'    => 'AUDIT_LOG_LIFECYCLE_LOCK_TABLE',
            'retention.after_days'    => 'AUDIT_LOG_RETENTION_AFTER_DAYS',
            'retention.categories'    => null,
            'retention.preserve'      => null,
            'retention.batch'         => 'AUDIT_LOG_RETENTION_BATCH',
            'retention.max_seconds'   => 'AUDIT_LOG_RETENTION_MAX_SECONDS',
            'retention.schedule'      => 'AUDIT_LOG_RETENTION_SCHEDULE',
            'import.batches_table'    => 'AUDIT_LOG_IMPORT_BATCHES_TABLE',
            'import.chunk'            => 'AUDIT_LOG_IMPORT_CHUNK',
            'import.max_skew_seconds' => 'AUDIT_LOG_IMPORT_MAX_SKEW_SECONDS',
            'import.max_line_bytes'   => 'AUDIT_LOG_IMPORT_MAX_LINE_BYTES',
        ], array_map(static fn (array $row): ?string => $row[1], iterator_to_array(self::provideLeaves())));
    }

    /**
     * The README names each lifecycle command, the facade's way into the
     * lifecycle and both lifecycle guides, each of which exists.
     *
     * @return void
     */
    public function testTheReadmeNamesTheLifecycleCommandsAndGuides(): void
    {
        $readme = self::readme();

        foreach (self::COMMANDS as $command) {
            self::assertMatchesRegularExpression('/(`|artisan )' . preg_quote($command, '/') . '[`\s]/', $readme, sprintf('The README does not name `%s`.', $command));
        }

        self::assertStringContainsString('AuditLog::lifecycle()->hold(', $readme);

        foreach (self::GUIDES as $guide) {
            self::assertStringContainsString('](' . $guide . ')', $readme, sprintf('The README does not link %s.', $guide));
            self::assertFileExists(self::root() . '/' . $guide);
        }
    }

    /**
     * The maintenance connection's row names everything that runs through it,
     * the import's journal rows among them.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionsRowNamesWhatRunsThroughIt(): void
    {
        $row = self::configurationRows()['storage.maintenance_connection'] ?? null;

        self::assertNotNull($row);
        self::assertStringStartsWith('The connection pruning, holds, the lifecycle journal and imports\' journal rows run through', $row[3]);
    }

    /**
     * Retention is the package's own prune, so the README no longer names
     * Laravel's `model:prune`.
     *
     * @return void
     */
    public function testTheReadmeNoLongerNamesModelPrune(): void
    {
        self::assertStringNotContainsString('model:prune', self::readme());
        self::assertStringContainsString('retention through `audit-log:prune`, scheduled by the package', self::readme());
    }

    /**
     * The env var the shipped file reads the leaf from, or `null` when it reads
     * none, as for a map: the `env()` call on the leaf's own line.
     *
     * @param  string  $leaf
     * @return ?string
     */
    private static function envOf(string $leaf): ?string
    {
        [$section, $key] = explode('.', $leaf, 2);

        $source = (string) file_get_contents(self::root() . '/config/audit-log.php');
        $body   = preg_match('/^    \'' . preg_quote($section, '/') . '\' => \[\n(.*?)^    \],$/ms', $source, $matches) === 1 ? $matches[1] : '';

        self::assertNotSame('', $body, sprintf('The shipped configuration has no `%s` section.', $section));

        $line = preg_match('/^        \'' . preg_quote($key, '/') . '\' +=> (.*),$/m', $body, $value) === 1 ? $value[1] : null;

        self::assertNotNull($line, sprintf('The shipped configuration has no line for `%s`.', $leaf));

        return preg_match('/^env\(\'([A-Z0-9_]+)\'/', $line, $env) === 1 ? $env[1] : null;
    }

    /**
     * Every row of the README's configuration table, by its key without the
     * backticks, as its cells.
     *
     * @return array<string, list<string>>
     */
    private static function configurationRows(): array
    {
        preg_match_all('/^\| `([a-z_.]+)` +\|.*\|$/m', self::readme(), $matches, PREG_SET_ORDER);

        $rows = [];

        foreach ($matches as $match) {
            $rows[$match[1]] = array_map(trim(...), explode('|', trim($match[0], '|')));
        }

        return $rows;
    }

    /**
     * The README.
     *
     * @return string
     */
    private static function readme(): string
    {
        $readme = file_get_contents(self::root() . '/README.md');

        self::assertIsString($readme);

        return $readme;
    }

    /**
     * The repository's root.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
