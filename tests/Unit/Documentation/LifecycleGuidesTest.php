<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\HoldCommand;
use SineMacula\Laravel\AuditLog\Console\HoldsCommand;
use SineMacula\Laravel\AuditLog\Console\ImportCommand;
use SineMacula\Laravel\AuditLog\Console\PruneCommand;
use SineMacula\Laravel\AuditLog\Console\ReconcileCommand;
use SineMacula\Laravel\AuditLog\Console\ReleaseCommand;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLineParser;
use Tests\Concerns\ReadsTheDocumentation;

/**
 * A drift guard for the retention and import guides: it catches an omission or
 * a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleGuidesTest extends TestCase
{
    use ReadsTheDocumentation;

    /** @var string The retention guide, from the repository's root. */
    private const string RETENTION_GUIDE = '/docs/guides/retention.md';

    /** @var string The import guide, from the repository's root. */
    private const string IMPORT_GUIDE = '/docs/guides/import.md';

    /** @var string The privacy guide, from the repository's root, which shows the erasure and key calls. */
    private const string PRIVACY_GUIDE = '/docs/guides/privacy.md';

    /** @var list<string> The retention guide's sections, in order. */
    private const array RETENTION_SECTIONS = ['Retention by category', 'A policy of your own', 'Preservation', 'Holds', 'Prune runs', 'After a prune'];

    /** @var list<string> The import guide's sections, in order. */
    private const array IMPORT_SECTIONS = ['Formats', 'The import format', 'Importing an export', 'Duplicates and conflicts', 'Batches', 'Holds and retention', 'Dry runs'];

    /** @var string The field naming a line's format, which the parser reads before the others. */
    private const string FORMAT_FIELD = 'format';

    /** @var string Pattern of a claim that destruction is prevented; "never impossible" denies one. */
    private const string PREVENTION_CLAIM = '/\b(?:prevents?|(?<!never )impossible|cannot be deleted)\b/i';

    /** @var string Pattern of a call on the lifecycle the facade gives: the method chained after `AuditLog::lifecycle()`. */
    private const string LIFECYCLE_CALL = '/\bAuditLog::lifecycle\(\)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/';

    /**
     * The retention guide has exactly its sections, in order.
     *
     * @return void
     */
    public function testTheRetentionGuideHasItsSections(): void
    {
        $guide = self::read(self::RETENTION_GUIDE);

        self::assertStringStartsWith("# Retention\n", $guide);
        self::assertSame(self::RETENTION_SECTIONS, self::sectionsOf($guide));
    }

    /**
     * The import guide has exactly its sections, in order.
     *
     * @return void
     */
    public function testTheImportGuideHasItsSections(): void
    {
        $guide = self::read(self::IMPORT_GUIDE);

        self::assertStringStartsWith("# Import\n", $guide);
        self::assertSame(self::IMPORT_SECTIONS, self::sectionsOf($guide));
    }

    /**
     * Rows of `[text]`: each lifecycle command and option, as declared.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLifecycleCommands(): iterable
    {
        foreach ([new PruneCommand, new HoldCommand, new ReleaseCommand, new HoldsCommand, new ImportCommand, new ReconcileCommand] as $command) {

            $name = (string) $command->getName();

            yield $name => ['`' . $name . '`'];

            foreach ($command->getDefinition()->getOptions() as $option) {
                yield $name . ' --' . $option->getName() => ['`--' . $option->getName() . '`'];
            }
        }
    }

    /**
     * Each lifecycle command and option is named in the guides.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideLifecycleCommands')]
    public function testEveryLifecycleCommandAndOptionIsInTheGuides(string $text): void
    {
        self::assertStringContainsString($text, self::guides(), sprintf('The lifecycle guides do not name %s.', $text));
    }

    /**
     * The rows are what the commands declare, so the check is not empty.
     *
     * @return void
     */
    public function testTheCommandRowsAreEveryDeclaredOption(): void
    {
        $rows = array_values(array_map(static fn (array $row): string => $row[0], iterator_to_array(self::provideLifecycleCommands())));

        self::assertCount(43, $rows);
        self::assertSame(['`audit-log:prune`', '`--dry-run`', '`--max-seconds`', '`--json`', '`audit-log:hold`', '`--all`'], array_slice($rows, 0, 6));
        self::assertSame(['`audit-log:reconcile`', '`--since`', '`--json`'], [$rows[40], $rows[41], $rows[42]]);
    }

    /**
     * Rows of `[field]`: every field an import line may give, `format` too.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideImportFields(): iterable
    {
        foreach ([self::FORMAT_FIELD, ...ImportLineParser::REQUIRED, ...ImportLineParser::OPTIONAL] as $field) {
            yield $field => [$field];
        }
    }

    /**
     * Every parsed import field has its own row naming its type and rule.
     *
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideImportFields')]
    public function testTheImportFormatIsDocumentedFieldByField(string $field): void
    {
        $section = self::section(self::read(self::IMPORT_GUIDE), 'The import format');

        $row = '/^\| `' . preg_quote($field, '/') . '` +\| [^|]*\S[^|]*\| [^|]*\S[^|]*\|$/m';

        self::assertMatchesRegularExpression($row, $section, sprintf('The import format has no row for `%s`.', $field));
    }

    /**
     * The import format section documents no field the parser does not read.
     *
     * @return void
     */
    public function testTheImportFormatDocumentsNoOtherField(): void
    {
        preg_match_all('/^\| `([a-z_]+)` +\|/m', self::section(self::read(self::IMPORT_GUIDE), 'The import format'), $rows);

        self::assertSame([self::FORMAT_FIELD, ...ImportLineParser::REQUIRED, ...ImportLineParser::OPTIONAL], $rows[1]);
    }

    /**
     * Rows of `[value, guide]`: every lifecycle enum value and its guide.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        $enums = [
            HoldBasis::class       => self::RETENTION_GUIDE,
            PruneStatus::class     => self::RETENTION_GUIDE,
            ImportStatus::class    => self::IMPORT_GUIDE,
            ImportFormat::class    => self::IMPORT_GUIDE,
            ImportRejection::class => self::IMPORT_GUIDE,
        ];

        foreach ($enums as $enum => $guide) {
            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$case->value, $guide];
            }
        }
    }

    /**
     * Every value of the lifecycle's enums is named in its guide, in code type.
     *
     * @param  string  $value
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEveryEnumValueIsInItsGuide(string $value, string $guide): void
    {
        self::assertStringContainsString('`' . $value . '`', self::read($guide), sprintf('%s does not name `%s`.', $guide, $value));
    }

    /**
     * Each `AuditLog::lifecycle()` call shown exists, and at least one is.
     *
     * @return void
     */
    public function testEveryLifecycleCallTheGuidesShowExists(): void
    {
        $calls   = self::lifecycleCallsIn(self::guides());
        $methods = self::lifecycleMethods();

        self::assertNotSame([], $calls, 'The guides show no call on the lifecycle.');
        self::assertSame([], array_values(array_diff($calls, $methods)), 'The guides show lifecycle calls that do not exist.');
    }

    /**
     * Every public lifecycle method is shown on `AuditLog::lifecycle()`.
     *
     * @return void
     */
    public function testEveryLifecycleMethodIsShown(): void
    {
        $methods = self::lifecycleMethods();

        self::assertSame([], array_values(array_diff($methods, self::lifecycleCallsIn(self::guides()))));
    }

    /**
     * The call scanner finds each chained lifecycle call once, however spaced.
     *
     * @return void
     */
    public function testTheCallScannerFindsEveryLifecycleCall(): void
    {
        $text = <<<'EOD'
            AuditLog::lifecycle()->hold($scope, $authority, HoldBasis::OTHER);
            Use `AuditLog::lifecycle()->holds()` to list them.
            AuditLog::lifecycle()
                ->prune(true);
            AuditLog::lifecycle() -> reconcile ();
            AuditLog::lifecycle()->hold($scope);
            AuditLog::lifecycle();
            AuditLog::trail()->count();
            NotAuditLog::lifecycle()->erase();
            $lifecycle->release($holdId);
            EOD;

        self::assertSame(['hold', 'holds', 'prune', 'reconcile'], self::lifecycleCallsIn($text));
    }

    /**
     * No guide claims destruction is prevented; "never impossible" denies it.
     *
     * @return void
     */
    public function testTheGuidesNeverClaimDestructionIsPrevented(): void
    {
        self::assertSame(0, preg_match(self::PREVENTION_CLAIM, self::guides()));
        self::assertSame(1, preg_match(self::PREVENTION_CLAIM, 'Erasure makes a restore impossible.'));
    }

    /**
     * The section headings of a guide, in order.
     *
     * @param  string  $guide
     * @return list<string>
     */
    private static function sectionsOf(string $guide): array
    {
        preg_match_all('/^## (.+)$/m', $guide, $headings);

        return $headings[1];
    }

    /**
     * The methods called on `AuditLog::lifecycle()`, each once, in order.
     *
     * @param  string  $text
     * @return list<string>
     */
    private static function lifecycleCallsIn(string $text): array
    {
        preg_match_all(self::LIFECYCLE_CALL, $text, $calls);

        return array_values(array_unique($calls[1]));
    }

    /**
     * The public methods of the lifecycle, its constructor aside.
     *
     * @return list<string>
     */
    private static function lifecycleMethods(): array
    {
        $methods = (new \ReflectionClass(AuditLifecycle::class))->getMethods(\ReflectionMethod::IS_PUBLIC);

        return array_values(array_diff(array_map(static fn (\ReflectionMethod $method): string => $method->getName(), $methods), ['__construct']));
    }

    /**
     * The guides that show the lifecycle's calls, one after the other.
     *
     * @return string
     */
    private static function guides(): string
    {
        return implode("\n", array_map(self::read(...), [self::RETENTION_GUIDE, self::IMPORT_GUIDE, self::PRIVACY_GUIDE]));
    }
}
