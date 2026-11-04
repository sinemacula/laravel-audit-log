<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests that keep the README in step with owners' keys and erasure: every
 * leaf of the privacy settings has its row in the configuration table with the
 * env var the shipped file reads, or none for a map, and the default it ships;
 * the features name encryption by default and link the privacy guide, which is
 * there; the usage shows the definition that encrypts a field, the reveal
 * grant, `holdingDataOf()`, an erasure through the facade and the four privacy
 * commands; the maintenance connection's row and the check's paragraph name
 * what the privacy operations add; and the two outcomes of an erasure, and what
 * credentials can still do, are stated apart.
 *
 * A drift guard: it catches an omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PrivacyReadmeTest extends TestCase
{
    /** @var string The section of the shipped configuration the owners' keys read. */
    private const string SECTION = 'privacy';

    /** @var list<string> The privacy commands. */
    private const array COMMANDS = ['audit-log:erase', 'audit-log:keys', 'audit-log:reinstate', 'audit-log:rewrap'];

    /** @var string How the maintenance connection's row starts, naming what runs through it. */
    private const string MAINTENANCE_ROW = 'The connection pruning, holds, the lifecycle journal and imports\' journal rows run through,'
        . ' and erasure, reinstatement and rewrap,';

    /** @var string What the check's paragraph says of a restored database. */
    private const string RESTORE_CHECK = 'After a database restore it fails too, on keys an erasure destroyed and on a database behind its anchor,'
        . ' until `audit-log:erase --reapply` has re-applied the erasures since.';

    /** @var string The guide the README links for owners' keys and erasure. */
    private const string GUIDE = 'docs/guides/privacy.md';

    /** @var list<string> The calls the usage shows, as they are written there. */
    private const array CALLS = [
        '->encrypt(\'card\', KeyOwner::ACTOR)',
        '->revealingEncryptedFields()',
        '->holdingDataOf($customer)',
        'AuditLog::lifecycle()->erase(',
    ];

    /**
     * Rows of `[leaf, the env var it reads or null for a map, its default as
     * the README shows it]`: every leaf of the privacy settings the shipped
     * file holds.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: string}>
     */
    public static function provideLeaves(): iterable
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);
        self::assertIsArray($config[self::SECTION] ?? null, 'The shipped configuration has no `privacy` section.');

        foreach ($config[self::SECTION] as $key => $default) {
            $leaf = self::SECTION . '.' . $key;

            yield $leaf => [$leaf, self::envOf((string) $key), self::shown($default)];
        }
    }

    /**
     * Each leaf has its row in the README's configuration table, naming the
     * default the shipped file falls back to and the env var it reads, or `-`
     * for a map, which has none.
     *
     * @param  string  $leaf
     * @param  ?string  $env
     * @param  string  $default
     * @return void
     */
    #[DataProvider('provideLeaves')]
    public function testEveryPrivacyLeafNamesItsDefaultAndEnvVarInTheReadme(string $leaf, ?string $env, string $default): void
    {
        $row = self::configurationRows()[$leaf] ?? null;

        self::assertNotNull($row, sprintf('The README\'s configuration table has no row for `%s`.', $leaf));
        self::assertSame($default, $row[1], sprintf('The README names the wrong default for `%s`.', $leaf));
        self::assertSame($env === null ? '-' : '`' . $env . '`', $row[2], sprintf('The README names the wrong env var for `%s`.', $leaf));
    }

    /**
     * The leaves the provider yields are exactly the six privacy settings, with
     * the env vars and defaults the package reads, so a leaf dropped from the
     * shipped file and from the README together still fails.
     *
     * @return void
     */
    public function testThePrivacyLeavesAreTheSixSettings(): void
    {
        self::assertSame([
            'privacy.keys'                 => [null, '`[]`'],
            'privacy.current'              => ['AUDIT_LOG_PRIVACY_CURRENT', '`null`'],
            'privacy.subject_keys_table'   => ['AUDIT_LOG_PRIVACY_SUBJECT_KEYS_TABLE', '`audit_log_subject_keys`'],
            'privacy.owner_erasures_table' => ['AUDIT_LOG_PRIVACY_OWNER_ERASURES_TABLE', '`audit_log_owner_erasures`'],
            'privacy.key_uses_table'       => ['AUDIT_LOG_PRIVACY_KEY_USES_TABLE', '`audit_log_key_uses`'],
            'privacy.rewrap_batch'         => ['AUDIT_LOG_PRIVACY_REWRAP_BATCH', '`500`'],
        ], array_map(static fn (array $row): array => [$row[1], $row[2]], iterator_to_array(self::provideLeaves())));
    }

    /**
     * The privacy rows follow the redaction rows and come before the failure
     * rows, in the order the shipped file lists them.
     *
     * @return void
     */
    public function testThePrivacyRowsAreInTheShippedOrder(): void
    {
        $keys  = array_keys(self::configurationRows());
        $first = array_search('privacy.keys', $keys, true);

        self::assertIsInt($first);
        self::assertSame('redaction.max_context_bytes', $keys[$first - 1]);
        self::assertSame(array_keys(iterator_to_array(self::provideLeaves())), array_slice($keys, $first, 6));
        self::assertSame('failure.mode', $keys[$first + 6]);
    }

    /**
     * The features say a field a definition encrypts is sealed under its
     * owner's key by default and erased with it, linking the privacy guide,
     * which the guides table lists too and which exists; and encrypted values
     * are no longer said never to be shown.
     *
     * @return void
     */
    public function testTheFeaturesNameEncryptionByDefaultAndTheGuide(): void
    {
        $readme   = self::readme();
        $features = self::between($readme, '## Features', '## Installation');

        self::assertStringContainsString('**[Owners\' keys and erasure](' . self::GUIDE . ')**', $features);
        self::assertStringContainsString("sealed under a key of its\n" . '  owner\'s by default', $features);
        self::assertStringContainsString('erased by destroying the owner\'s keys', $features);
        self::assertStringContainsString('encrypted values shown only to a scope the access policy grants them', $features);
        self::assertStringNotContainsString('encrypted values never shown', $readme);
        self::assertMatchesRegularExpression('/^\| \[Privacy\]\(' . preg_quote(self::GUIDE, '/') . '\) +\|/m', $readme);
        self::assertFileExists(self::root() . '/' . self::GUIDE);
    }

    /**
     * The usage shows the definition that encrypts a field, the reveal grant,
     * `holdingDataOf()` and an erasure through the facade, and names each
     * privacy command as it is run.
     *
     * @return void
     */
    public function testTheUsageShowsTheCallsAndTheCommands(): void
    {
        $usage = self::between(self::readme(), '### Encrypted fields and erasure', '### Guides');

        foreach (self::CALLS as $call) {
            self::assertStringContainsString($call, $usage, sprintf('The README does not show %s.', $call));
        }

        foreach (self::COMMANDS as $command) {
            self::assertStringContainsString('php artisan ' . $command . ' ', $usage, sprintf('The README does not run `%s`.', $command));
        }

        self::assertStringContainsString('`--partial`', $usage);
        self::assertStringContainsString('`--pending`', $usage);
        self::assertStringContainsString('`audit_log.subject_erased`', $usage);
    }

    /**
     * The usage states the two outcomes of an erasure apart, and that database
     * credentials can still destroy or restore keys, which the package makes
     * detectable and never impossible.
     *
     * @return void
     */
    public function testTheUsageStatesTheTwoOutcomesAndWhatCredentialsCanDo(): void
    {
        $usage = self::flattened(self::between(self::readme(), '### Encrypted fields and erasure', '### Guides'));

        self::assertStringContainsString('An erasure revokes the owner\'s fields in the live store when it commits; it is complete only once the procedure', $usage);
        self::assertStringContainsString('Database credentials can still destroy or restore keys, and `audit-log:verify` and `audit-log:check` make that detectable', $usage);
        self::assertStringContainsString('re-apply the erasures since with `audit-log:erase --reapply=<file>`', $usage);
        self::assertStringContainsString('References, hashes and the members of manifests are not erased.', $usage);
    }

    /**
     * The maintenance connection's row names the privacy operations that run
     * through it, after what ran through it before, and the check's paragraph
     * says a restored database fails until the erasures are re-applied.
     *
     * @return void
     */
    public function testTheMaintenanceRowAndTheCheckNameThePrivacyOperations(): void
    {
        $row = self::configurationRows()['storage.maintenance_connection'] ?? null;

        self::assertNotNull($row);
        self::assertStringStartsWith(self::MAINTENANCE_ROW, $row[3]);
        self::assertStringContainsString(self::RESTORE_CHECK, self::flattened(self::readme()));
    }

    /**
     * The env var the shipped file reads the privacy leaf from, or `null` when
     * it reads none, as for a map: the `env()` call on the leaf's own line.
     *
     * @param  string  $key
     * @return ?string
     */
    private static function envOf(string $key): ?string
    {
        $source = (string) file_get_contents(self::root() . '/config/audit-log.php');
        $body   = preg_match('/^    \'' . self::SECTION . '\' => \[\n(.*?)^    \],$/ms', $source, $matches) === 1 ? $matches[1] : '';

        self::assertNotSame('', $body, 'The shipped configuration has no `privacy` section.');

        $line = preg_match('/^        \'' . preg_quote($key, '/') . '\' +=> (.*),$/m', $body, $value) === 1 ? $value[1] : null;

        self::assertNotNull($line, sprintf('The shipped configuration has no line for `privacy.%s`.', $key));

        return preg_match('/^env\(\'([A-Z0-9_]+)\'/', $line, $env) === 1 ? $env[1] : null;
    }

    /**
     * A shipped default as the README's table shows it, in backticks.
     *
     * @param  array<array-key, string>|int|string|null  $default
     * @return string
     */
    private static function shown(array|int|string|null $default): string
    {
        return '`' . match (true) {
            $default === null  => 'null',
            is_array($default) => '[]',
            default            => (string) $default,
        } . '`';
    }

    /**
     * Every row of the README's configuration table, by its key without the
     * backticks, as its cells, in order.
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
     * The text between the two headings, which the test fails without.
     *
     * @param  string  $text
     * @param  string  $from
     * @param  string  $to
     * @return string
     */
    private static function between(string $text, string $from, string $to): string
    {
        $start = strpos($text, $from);

        self::assertIsInt($start, sprintf('The README has no `%s`.', $from));

        $end = strpos($text, $to, $start);

        self::assertIsInt($end, sprintf('The README has no `%s` after `%s`.', $to, $from));

        return substr($text, $start, $end - $start);
    }

    /**
     * The text with every run of whitespace made one space, so a sentence is
     * found however its lines are wrapped.
     *
     * @param  string  $text
     * @return string
     */
    private static function flattened(string $text): string
    {
        return (string) preg_replace('/\s+/', ' ', $text);
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
