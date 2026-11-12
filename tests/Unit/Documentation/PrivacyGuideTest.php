<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\EraseCommand;
use SineMacula\Laravel\AuditLog\Console\KeysCommand;
use SineMacula\Laravel\AuditLog\Console\ReinstateCommand;
use SineMacula\Laravel\AuditLog\Console\RewrapCommand;

/**
 * A drift guard for the privacy guide: omissions and renames, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PrivacyGuideTest extends TestCase
{
    /** @var string The privacy guide, from the repository's root. */
    private const string GUIDE = '/docs/guides/privacy.md';

    /** @var list<string> The guide's sections, in order. */
    private const array SECTIONS = [
        'Defaults and their trade-offs',
        'Keys',
        'Erasure',
        'Recall',
        'Reinstatement',
        'Rotation and kept units',
        'Restores',
        'What is not erased',
        'Stores and what they hold',
        'Custom encrypters',
        'SQLite and the key session',
        'Commands',
    ];

    /** @var string The two guarantees, stated apart: what credentials can do to keys, and what the evidence makes detectable. */
    private const string GUARANTEES = 'Database credentials can still destroy keys, key uses and markers; the package\'s cryptographic evidence '
        . 'makes unauthorised destruction, substitution or restoration detectable, never impossible.';

    /** @var string What the reveal grant reveals, and what it is not. */
    private const string REVEAL_SCOPE = 'The grant reveals every encrypted field of every entry the scope sees, whoever owns it, '
        . 'and is not an owner-specific projection';

    /** @var array<string, string> Each part of the estate an erasure must reach, by the words its checklist item starts with. */
    private const array ESTATE = [
        'backups'      => 'backups of the database, with their WAL or binlogs, expiring past the erasure',
        'replicas'     => 'replicas',
        'exports'      => 'exports',
        'logs'         => 'logs and error trackers',
        'destinations' => 'destination stores, such as a SIEM',
        'pending'      => 'pending deliveries',
    ];

    /**
     * The guide is titled and has its sections, in order, and no other.
     *
     * @return void
     */
    public function testTheGuideHasItsSections(): void
    {
        $guide = self::withoutCodeBlocks(self::read());

        preg_match_all('/^## (.+)$/m', $guide, $sections);

        self::assertStringStartsWith("# Privacy\n", $guide);
        self::assertSame(self::SECTIONS, $sections[1]);
    }

    /**
     * Rows of `[command, options]`: each privacy command and its options.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function providePrivacyCommands(): iterable
    {
        foreach ([new EraseCommand, new ReinstateCommand, new RewrapCommand, new KeysCommand] as $command) {

            $name    = (string) $command->getName();
            $options = array_map(static fn (string $option): string => '`--' . $option . '`', array_keys($command->getDefinition()->getOptions()));

            yield $name => [$name, $options];
        }
    }

    /**
     * The commands table has a row per privacy command naming each option.
     *
     * @param  string  $command
     * @param  list<string>  $options
     * @return void
     */
    #[DataProvider('providePrivacyCommands')]
    public function testEveryPrivacyCommandAndOptionIsInTheGuide(string $command, array $options): void
    {
        $table   = preg_match('/^ *\| Command +\|.*\n(?: *\|.*(?:\n|\z))*/m', self::section(self::read(), 'Commands'), $match) === 1 ? $match[0] : '';
        $pattern = '/^ *\| `' . preg_quote($command, '/') . '(?: [^`]*)?` +\|.*$/m';
        $row     = preg_match($pattern, $table, $found) === 1 ? $found[0] : '';

        self::assertNotSame('', $row, sprintf('The privacy guide has no row for `%s`.', $command));

        foreach ($options as $option) {
            self::assertStringContainsString($option, $row, sprintf('The privacy guide\'s row for `%s` does not name %s.', $command, $option));
        }
    }

    /**
     * The rows are all four commands' options, so the check is not empty.
     *
     * @return void
     */
    public function testTheCommandRowsAreEveryDeclaredOption(): void
    {
        $rows = iterator_to_array(self::providePrivacyCommands());

        self::assertSame(['audit-log:erase', 'audit-log:reinstate', 'audit-log:rewrap', 'audit-log:keys'], array_keys($rows));
        self::assertSame(['`--rebuild-uses`', '`--dry-run`'], $rows['audit-log:keys'][1]);
        self::assertSame(19, array_sum(array_map(static fn (array $row): int => count($row[1]), $rows)));
    }

    /**
     * Rows of `[section, statement]`: the defaults, limits and duties to state.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function providePrivacyStatements(): iterable
    {
        yield from [
            'two guarantees'       => ['', self::GUARANTEES],
            'sealed by default'    => ['Defaults and their trade-offs', 'Fields a definition encrypts are sealed by default.'],
            'never encrypting'     => ['Defaults and their trade-offs', 'Bind `Privacy\NoFieldEncrypter` as `Contracts\FieldEncrypter` to never encrypt'],
            'forever'              => ['Defaults and their trade-offs', 'Keeping entries forever is not a compliance default'],
            'the reveal scope'     => ['Defaults and their trade-offs', self::REVEAL_SCOPE],
            'units'                => ['Keys', 'A key unit is the owner, the record\'s tenant and the definition\'s category'],
            'domain separation'    => ['Keys', 'The derivation gives domain separation, not independence from `app.key`'],
            'rotation'             => ['Keys', 'Rotation is not rewrap'],
            'the wrapper seam'     => ['Keys', 'The `Contracts\KeyWrapper` seam lets a key service outside the application wrap the data keys.'],
            'backups'              => ['Keys', 'a wrapper whose wrapping keys are destroyed outside the database\'s backups is what lets an erasure reach a backup'],
            'all or nothing'       => ['Erasure', 'An erasure is all or nothing.'],
            'partial'              => ['Erasure', '`--partial`, or `partial: true`, destroys the keys nothing blocks and keeps the rest'],
            'article 17'           => ['Erasure', 'A hold is not a blanket exemption under Article 17 for every fragment of a person.'],
            'units let data go'    => ['Erasure', 'units are what let the owner\'s unrelated data go'],
            'pending'              => ['Erasure', '`--pending` accepts them'],
            'stored first'         => ['Erasure', 'A hold protects a record only once it is stored'],
            'the spill'            => ['Erasure', 'Spilled records awaiting replay are pending evidence the erasure cannot see'],
            'two outcomes'         => ['Erasure', 'Revoked in the live store is what the package does'],
            'complete'             => ['Erasure', 'Erasure complete is the operator\'s procedure across the estate'],
            'recall'               => ['Recall', 'A decryption already returned cannot be recalled.'],
            'reinstatement'        => ['Reinstatement', 'it creates no key and makes no erased field readable'],
            'kept units rotated'   => ['Rotation and kept units', 'a kept key\'s unit then seals nothing for that owner until a reinstatement'],
            'restored keys'        => ['Restores', 'A restored key decrypts until the erasure is re-applied.'],
            'no discovery'         => ['Restores', 'Without an anchor that reports its head, a full restore cannot be found'],
            'the reapply'          => ['Restores', 'only when every owner ended `complete` or `already_erased`'],
            'references'           => ['What is not erased', 'The references in an entry\'s columns'],
            'manifest members'     => ['What is not erased', 'Manifest members under `app.key`'],
            'fingerprints'         => ['What is not erased', 'The journal\'s fingerprints of erased owners'],
            'read filters'         => ['What is not erased', 'The read evidence\'s filters naming an owner'],
            'linkable'             => ['Stores and what they hold', 'Each store holds personal data while what it keeps can be linked to a person'],
            'custom refused'       => ['Custom encrypters', 'an erasure refuses `unsupported_encrypter`, `holdingDataOf()` throws a `\LogicException` naming the bound class'],
            'custom missing keys'  => ['Custom encrypters', 'its UUID references are reported `key_missing` by verify'],
            'the sqlite exception' => ['SQLite and the key session', 'a key created inside a host transaction on SQLite rolls back with it'],
        ];
    }

    /**
     * The guide makes each statement in its section or before the first.
     *
     * @param  string  $section
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('providePrivacyStatements')]
    public function testEachPrivacyStatementIsMade(string $section, string $statement): void
    {
        $guide = self::read();
        $text  = $section === '' ? strstr($guide, "\n## ", true) : self::section($guide, $section);

        self::assertIsString($text);
        self::assertStringContainsString($statement, self::collapsed($text));
    }

    /**
     * The erasure checklist names every part of the estate it must reach.
     *
     * @return void
     */
    public function testTheEstateChecklistIsComplete(): void
    {
        $section = self::section(self::read(), 'Erasure');

        preg_match_all('/^  - (.+(?:\n    .+)*)/m', $section, $items);

        $checklist = array_map(self::collapsed(...), $items[1]);

        self::assertCount(count(self::ESTATE), $checklist);

        foreach (self::ESTATE as $part => $start) {
            $named = array_filter($checklist, static fn (string $item): bool => str_starts_with($item, $start));

            self::assertNotSame([], $named, sprintf('The estate checklist does not name %s.', $part));
        }
    }

    /**
     * The section and checklist scanners read only what they must.
     *
     * @return void
     */
    public function testTheScannersReadOnlyWhatTheyMust(): void
    {
        $markdown = "## Erasure\n\n- An item.\n  - backups of the database\n    wrapped\n  - replicas\n\n## Recall\n\n  - logs\n";
        $section  = self::section($markdown, 'Erasure');

        preg_match_all('/^  - (.+(?:\n    .+)*)/m', $section, $items);

        self::assertSame(['backups of the database wrapped', 'replicas'], array_map(self::collapsed(...), $items[1]));
        self::assertSame('', self::section($markdown, 'Restores'));
    }

    /**
     * The text of the section under the heading, up to the next section.
     *
     * @param  string  $markdown
     * @param  string  $heading
     * @return string
     */
    private static function section(string $markdown, string $heading): string
    {
        $pattern = '/^## ' . preg_quote($heading, '/') . '\n(.*?)(?=^## |\z)/ms';

        return preg_match($pattern, $markdown, $matches) === 1 ? $matches[1] : '';
    }

    /**
     * The Markdown without fenced code, so a `#` comment is never a heading.
     *
     * @param  string  $markdown
     * @return string
     */
    private static function withoutCodeBlocks(string $markdown): string
    {
        return (string) preg_replace('/^ *(```|~~~)[^\n]*\n.*?^ *\1[ \t]*$/ms', '', $markdown);
    }

    /**
     * The text with whitespace runs collapsed, so a wrapped sentence matches.
     *
     * @param  string  $text
     * @return string
     */
    private static function collapsed(string $text): string
    {
        return trim((string) preg_replace('/\s+/', ' ', $text));
    }

    /**
     * The privacy guide.
     *
     * @return string
     */
    private static function read(): string
    {
        $contents = file_get_contents(dirname(__DIR__, 3) . self::GUIDE);

        self::assertIsString($contents, sprintf('%s cannot be read.', self::GUIDE));

        return $contents;
    }
}
