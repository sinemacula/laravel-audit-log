<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ReadsTheDocumentation;

/**
 * A drift guard keeping the README, the configuration guide and the privacy
 * guide in step with owners' keys and erasure: it catches an omission or a
 * rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PrivacyConfigurationTest extends TestCase
{
    use ReadsTheDocumentation;

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

    /** @var list<string> The calls the privacy guide shows, as they are written there. */
    private const array CALLS = [
        'encrypt(\'card\', KeyOwner::ACTOR)',
        'revealingEncryptedFields()',
        'holdingDataOf()',
        'AuditLog::lifecycle()->erase(',
    ];

    /**
     * Rows of `[leaf, env var or null, default as shown]`: every privacy leaf.
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
     * Each leaf has a row in the configuration guide naming its default and env
     * var, or `-` for a map.
     *
     * @param  string  $leaf
     * @param  ?string  $env
     * @param  string  $default
     * @return void
     */
    #[DataProvider('provideLeaves')]
    public function testEveryPrivacyLeafNamesItsDefaultAndEnvVarInTheConfigurationGuide(string $leaf, ?string $env, string $default): void
    {
        $row = self::configurationRows()[$leaf] ?? null;

        self::assertNotNull($row, sprintf('The configuration guide has no row for `%s`.', $leaf));
        self::assertSame($default, $row[1], sprintf('The configuration guide names the wrong default for `%s`.', $leaf));
        self::assertSame($env === null ? '-' : '`' . $env . '`', $row[2], sprintf('The configuration guide names the wrong env var for `%s`.', $leaf));
    }

    /**
     * The leaves are exactly the six privacy settings, so a joint drop fails.
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
     * The privacy rows sit between the redaction and failure rows, in order.
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
     * The README links the privacy guide from its guides table.
     *
     * @return void
     */
    public function testTheReadmeLinksThePrivacyGuide(): void
    {
        self::assertMatchesRegularExpression('/^\| \[Privacy\]\(' . preg_quote(self::GUIDE, '/') . '\) +\|/m', self::readme());
        self::assertFileExists(self::root() . '/' . self::GUIDE);
    }

    /**
     * The privacy guide shows the privacy calls, and names each command, the
     * partial and pending options, the erasure's record and its two outcomes.
     *
     * @return void
     */
    public function testThePrivacyGuideShowsTheCallsAndNamesTheCommandsAndOutcomes(): void
    {
        $guide = self::collapsed(self::read('/' . self::GUIDE));

        foreach (self::CALLS as $call) {
            self::assertStringContainsString($call, $guide, sprintf('The privacy guide does not show %s.', $call));
        }

        foreach (self::COMMANDS as $command) {
            self::assertStringContainsString('`' . $command, $guide, sprintf('The privacy guide does not name `%s`.', $command));
        }

        self::assertStringContainsString('`--partial`', $guide);
        self::assertStringContainsString('`--pending`', $guide);
        self::assertStringContainsString('`audit_log.subject_erased`', $guide);
        self::assertStringContainsString('Revoked in the live store is what the package does', $guide);
        self::assertStringContainsString('Erasure complete is the operator\'s procedure across the estate', $guide);
    }

    /**
     * The maintenance row and the check's paragraph name the privacy steps.
     *
     * @return void
     */
    public function testTheMaintenanceRowAndTheCheckNameThePrivacyOperations(): void
    {
        $row = self::configurationRows()['storage.maintenance_connection'] ?? null;

        self::assertNotNull($row);
        self::assertStringStartsWith(self::MAINTENANCE_ROW, $row[3]);
        self::assertStringContainsString(self::RESTORE_CHECK, self::collapsed(self::read('/docs/guides/configuration.md')));
    }

    /**
     * The env var the shipped file reads the leaf from, or `null` for a map.
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
     * A shipped default as the configuration guide's table shows it, in
     * backticks.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $default
     * @return string
     */
    private static function shown(mixed $default): string
    {
        return '`' . match (true) {
            $default === null                       => 'null',
            is_array($default)                      => '[]',
            is_int($default) || is_string($default) => (string) $default,
            default                                 => self::fail('A privacy default is not null, an array, an integer or a string.'),
        } . '`';
    }
}
