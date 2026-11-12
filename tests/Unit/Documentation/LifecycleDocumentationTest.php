<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\EraseCommand;
use SineMacula\Laravel\AuditLog\Console\HoldCommand;
use SineMacula\Laravel\AuditLog\Console\HoldsCommand;
use SineMacula\Laravel\AuditLog\Console\ImportCommand;
use SineMacula\Laravel\AuditLog\Console\KeysCommand;
use SineMacula\Laravel\AuditLog\Console\PruneCommand;
use SineMacula\Laravel\AuditLog\Console\ReconcileCommand;
use SineMacula\Laravel\AuditLog\Console\ReinstateCommand;
use SineMacula\Laravel\AuditLog\Console\ReleaseCommand;
use SineMacula\Laravel\AuditLog\Console\RewrapCommand;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;

/**
 * A drift guard for the lifecycle note and the operations guide's lifecycle
 * commands: it catches an omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleDocumentationTest extends TestCase
{
    /** @var string The lifecycle note, from the repository's root. */
    private const string LIFECYCLE_NOTE = '/docs/design/lifecycle.md';

    /** @var string The operations guide, from the repository's root. */
    private const string OPERATIONS_GUIDE = '/docs/guides/operations.md';

    /** @var list<string> The lifecycle note's sections, in order: the standard ones around its own. */
    private const array SECTIONS = [
        'Purpose',
        'Invariants',
        'Success Path',
        'Failure / Edge Cases',
        'Journal',
        'Holds',
        'Retention And Pruning',
        'Import',
        'Seams Left',
        'Implementation Anchors',
        'Authoritative Tests',
        'Change Triggers',
    ];

    /** @var list<string> What the note's seams name, each the start of a bullet of its section. */
    private const array SEAMS = ['External verification of an imported bundle'];

    /** @var string The two guarantees, stated apart: what credentials can do, and what the evidence makes detectable. */
    private const string GUARANTEES = 'Database credentials can still destroy rows; '
        . 'the package\'s cryptographic evidence makes unauthorised destruction detectable, never impossible.';

    /** @var string Pattern of a claim that destruction is stopped rather than made detectable. */
    private const string PREVENTION_CLAIM = '/\b(?:prevents?|cannot\s+be\s+(?:deleted|destroyed|removed))\b|(?<!never\s)(?<!not\s)\bimpossible\b/i';

    /**
     * The lifecycle note has exactly the standard sections around its own.
     *
     * @return void
     */
    public function testTheLifecycleNoteHasItsSectionsInOrder(): void
    {
        $note = self::withoutCodeBlocks(self::read(self::LIFECYCLE_NOTE));

        preg_match_all('/^## (.+)$/m', $note, $sections);

        self::assertStringStartsWith("# Lifecycle\n", $note);
        self::assertSame(self::SECTIONS, $sections[1]);
    }

    /**
     * Rows of `[statement]`: the rules and limits the lifecycle note states.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLifecycleStatements(): iterable
    {
        yield from [
            'guarantees'                   => [self::GUARANTEES],
            'lock first'                   => ['The first statement of every maintenance transaction is the lock row\'s `UPDATE`'],
            'after the lock'               => ['Nothing read before the lock decides a deletion.'],
            'exclusion'                    => ['The lock gives exclusion, not fairness.'],
            'sqlite on php 8.3'            => ['on SQLite it takes the database\'s write lock on PHP 8.3'],
            'the retries'                  => ['up to 3 times; the fourth loss is a `Lifecycle\LifecycleContentionException`'],
            'projection'                   => ['The projection is a convenience index, never trusted'],
            'the verified head'            => ['the stored head must be the replay\'s head'],
            'the journal label'            => ['the label `audit-log:lifecycle:<kind>:v1`, a line feed'],
            'the journal derivation'       => ['`hash_hkdf(\'sha256\', $secret, 32, \'sinemacula/audit-log:lifecycle:v1\', \'\')`'],
            'the seal commitment'          => ['Every seal commits to the journal\'s head'],
            'append-only'                  => ['It is append-only: never updated and never deleted'],
            'overlapping holds'            => ['Overlapping holds each count'],
            'the review date'              => ['Nothing releases a hold but a release.'],
            'the conflict refused'         => ['a retention shorter than its preservation is refused'],
            'the cut-off'                  => ['the UTC midnight of the run\'s start less the pair\'s retention'],
            'per entry'                    => ['pruning is per entry and never per segment'],
            'protected'                    => ['Only `audit_log.trail_exported` is protected from retention'],
            'never a checkpoint'           => ['A prune never deletes a checkpoint or a member'],
            'bitmap'                       => ['bit `i % 8` of byte `i / 8`, least significant first'],
            'no coverage for the missing'  => ['Coverage is never issued for a member already missing.'],
            'resurrected'                  => ['A direct store of a pruned record is detected (`resurrected`), not prevented'],
            'the installation'             => ['must read the same through the maintenance connection'],
            'recording follows the commit' => ['The journal row commits with what it describes; the activity record follows the commit.'],
            'fail-closed recording'        => ['Fail-closed names the recording attempt only'],
            'basis'                        => ['The package records the basis it is given and never decides legal necessity.'],
            'archives'                     => ['The package is no write-once archive and claims no compliance.'],
            'the broker rule'              => ['SEC Rule 17a-4'],
            'the records rule'             => ['FINRA Rule 4511'],
            'the card rule'                => ['PCI DSS requirement 10.5.1\'s three months'],
            'article 17'                   => ['A hold is not a blanket exemption under Article 17 for every fragment of a person.'],
            'app.key'                      => ['Export artifacts need `app.key` kept, or listed in `app.previous_keys`, for as long as their verification is promised.'],
            'asserted authority'           => ['`--by-type`, `--by-id` and every `Lifecycle\Authority` assert who asked and prove nothing'],
            'provenance'                   => ['The local signature attests what this installation accepted, not the truth of the event.'],
            'not externally verified'      => ['Every batch records `externally_verified` as `false`'],
            'envelopes dropped'            => ['No value shaped as an envelope is imported in either format'],
            'the source digest derivation' => ['`hash_hkdf(\'sha256\', $secret, 32, \'sinemacula/audit-log:source-digest:v1\', \'\')`'],
            're-import'                    => ['The guarantee holds while the earlier row survives: a re-import after a prune creates new rows'],
            'no savepoint'                 => ['no savepoint is ever opened'],
            'the hold first'               => ['the hold is on the batch before its first entry'],
            'a dry run creates no key'     => ['it creates no key'],
            'the privacy codes'            => ['`audit_log.subject_erased`, `audit_log.keys_reinstated` and `audit_log.keys_rewrapped` are written after'],
            'refusals and failures'        => ['with `journal_broken`, `erasure_failed` or `rewrap_failed`, a code and never the failure\'s message'],
            'the erasure payload'          => ['`erasure` holds `owner_fingerprint`, `fingerprint_key`, `generation_floor`, `partial`, `pending_accepted`'],
            'the reinstate payload'        => ['`reinstate` holds `owner_fingerprint`, `fingerprint_key` and `generation_floor`'],
            'the rewrap payload'           => ['`rewrap` holds `run_id`, `rotate`, `keys`'],
            'the reconciliation payload'   => ['`restore_reconciled` holds `file_sha256`, `owners`, `erased`, `already_erased`, `anchored_sequence` and `anchored_digest`'],
            'a rewrap run reconciled once' => ['so `audit-log:reconcile` records the run once, summing the batches it finds in its window'],
            'the reapply'                  => ['once every owner ended `complete` or `already_erased` and every line named an owner'],
        ];
    }

    /**
     * The lifecycle note makes each statement, however its lines are wrapped.
     *
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideLifecycleStatements')]
    public function testEachLifecycleStatementIsMade(string $statement): void
    {
        self::assertStringContainsString($statement, self::collapsed(self::read(self::LIFECYCLE_NOTE)));
    }

    /**
     * Rows of `[value, section]`: every lifecycle enum value and its section.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        $enums = [
            JournalKind::class  => 'Journal',
            HoldBasis::class    => 'Holds',
            PruneStatus::class  => 'Retention And Pruning',
            ImportFormat::class => 'Import',
            ImportStatus::class => 'Import',
        ];

        foreach ($enums as $enum => $section) {
            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$case->value, $section];
            }
        }
    }

    /**
     * Every lifecycle enum value is named, in code type, in its section.
     *
     * @param  string  $value
     * @param  string  $section
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEachEnumValueIsNamedInItsSection(string $value, string $section): void
    {
        $text = self::section(self::read(self::LIFECYCLE_NOTE), $section);

        self::assertStringContainsString('`' . $value . '`', $text, sprintf('The %s section does not name `%s`.', $section, $value));
    }

    /**
     * The note's seams name the external verification of an imported bundle.
     *
     * @return void
     */
    public function testTheLifecycleNoteNamesTheSeamsLeft(): void
    {
        $section = self::section(self::read(self::LIFECYCLE_NOTE), 'Seams Left');

        preg_match_all('/^- ([^:]+):/m', $section, $seams);

        self::assertSame(self::SEAMS, $seams[1]);
    }

    /**
     * Neither document claims a hold, a prune or the journal stops destruction.
     *
     * @return void
     */
    public function testNeitherDocumentClaimsDestructionIsPrevented(): void
    {
        foreach ([self::LIFECYCLE_NOTE, self::OPERATIONS_GUIDE] as $path) {
            self::assertSame(0, preg_match(self::PREVENTION_CLAIM, self::collapsed(self::read($path))), sprintf('%s claims destruction is prevented.', $path));
        }
    }

    /**
     * The prevention pattern finds each form, and no negation or look-alike.
     *
     * @return void
     */
    public function testThePreventionPatternFindsEachForm(): void
    {
        $claims = [
            'A hold prevents deletion',
            'to prevent a prune',
            'deletion is impossible',
            'Impossible to delete',
            'rows cannot be deleted',
            'it cannot be destroyed',
            "a row cannot\n  be removed",
        ];

        foreach ($claims as $claim) {
            self::assertSame(1, preg_match(self::PREVENTION_CLAIM, $claim), $claim);
        }

        foreach (['detected, not prevented', 'detectable, never impossible', 'detectable, not impossible', 'a preventive control', 'it cannot be read'] as $text) {
            self::assertSame(0, preg_match(self::PREVENTION_CLAIM, $text), $text);
        }
    }

    /**
     * Rows of `[command, options]`: each lifecycle command and its options.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideLifecycleCommands(): iterable
    {
        $commands = [
            new PruneCommand,
            new HoldCommand,
            new ReleaseCommand,
            new HoldsCommand,
            new ImportCommand,
            new ReconcileCommand,
            new EraseCommand,
            new ReinstateCommand,
            new RewrapCommand,
            new KeysCommand,
        ];

        foreach ($commands as $command) {

            $name    = (string) $command->getName();
            $options = array_map(static fn (string $option): string => '`--' . $option . '`', array_keys($command->getDefinition()->getOptions()));

            yield $name => [$name, $options];
        }
    }

    /**
     * The operations guide has a row per lifecycle command naming each option.
     *
     * @param  string  $command
     * @param  list<string>  $options
     * @return void
     */
    #[DataProvider('provideLifecycleCommands')]
    public function testTheOperationsGuideNamesEveryLifecycleCommand(string $command, array $options): void
    {
        $row = self::commandRow(self::read(self::OPERATIONS_GUIDE), $command);

        self::assertNotSame('', $row, sprintf('The operations guide has no row for `%s`.', $command));

        foreach ($options as $option) {
            self::assertStringContainsString($option, $row, sprintf('The operations guide\'s row for `%s` does not name %s.', $command, $option));
        }
    }

    /**
     * The rows are all ten commands' options, so the check is not empty.
     *
     * @return void
     */
    public function testTheCommandRowsAreEveryDeclaredOption(): void
    {
        $rows = iterator_to_array(self::provideLifecycleCommands());

        self::assertSame([
            'audit-log:prune',
            'audit-log:hold',
            'audit-log:release',
            'audit-log:holds',
            'audit-log:import',
            'audit-log:reconcile',
            'audit-log:erase',
            'audit-log:reinstate',
            'audit-log:rewrap',
            'audit-log:keys',
        ], array_keys($rows));
        self::assertSame(['`--dry-run`', '`--max-seconds`', '`--json`'], $rows['audit-log:prune'][1]);
        self::assertSame(
            ['`--by-type`', '`--by-id`', '`--reason`', '`--reference`', '`--partial`', '`--pending`', '`--reapply`'],
            $rows['audit-log:erase'][1],
        );
        self::assertSame(56, array_sum(array_map(static fn (array $row): int => count($row[1]), $rows)));
    }

    /**
     * The row scanner finds only the named command's `Command` table row.
     *
     * @return void
     */
    public function testTheRowScannerFindsOnlyTheCommandsOwnRow(): void
    {
        $markdown = <<<'EOD'
            | Run               | Setting              |
            |-------------------|----------------------|
            | `audit-log:prune` | `retention.schedule` |

            | Command                    | Options               | What  |
            |----------------------------|-----------------------|-------|
            | `audit-log:holds`          | `--rebuild`, `--json` | Lists |
            | `audit-log:hold`           | `--all`               | Holds |
            | `audit-log:release <hold>` | `--by-id`             | Frees |

            | `audit-log:reconcile` | `--since` | After |
            EOD;

        self::assertStringContainsString('`--all`', self::commandRow($markdown, 'audit-log:hold'));
        self::assertStringNotContainsString('`--rebuild`', self::commandRow($markdown, 'audit-log:hold'));
        self::assertStringContainsString('`--by-id`', self::commandRow($markdown, 'audit-log:release'));
        self::assertSame('', self::commandRow($markdown, 'audit-log:prune'));
        self::assertSame('', self::commandRow($markdown, 'audit-log:reconcile'));
    }

    /**
     * The `Command` table row naming the command, or an empty string.
     *
     * @param  string  $markdown
     * @param  string  $command
     * @return string
     */
    private static function commandRow(string $markdown, string $command): string
    {
        $table   = preg_match('/^ *\| Command +\|.*\n(?: *\|.*(?:\n|\z))*/m', $markdown, $match) === 1 ? $match[0] : '';
        $pattern = '/^ *\| `' . preg_quote($command, '/') . '(?: [^`]*)?` +\|.*$/m';

        return preg_match($pattern, $table, $row) === 1 ? $row[0] : '';
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
        return (string) preg_replace('/\s+/', ' ', $text);
    }

    /**
     * A file of the repository, by its path from the root.
     *
     * @param  string  $path
     * @return string
     */
    private static function read(string $path): string
    {
        $contents = file_get_contents(dirname(__DIR__, 3) . $path);

        self::assertIsString($contents, sprintf('%s cannot be read.', $path));

        return $contents;
    }
}
