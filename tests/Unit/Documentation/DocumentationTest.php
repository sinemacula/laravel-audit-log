<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;

/**
 * A drift guard for the README, the guides in docs/guides and the design notes
 * in docs/design: every outcome, origin, provenance, field handling and key
 * owner, and every configuration key, is documented; every design note exists,
 * has the standard sections and is listed in the index, which ends with the
 * standard sentence; every test a note cites exists; the vocabulary reserves
 * every prefix and every shipped code sits under one; and every example is
 * valid and neutral, naming no other package of the suite.
 *
 * It catches an omission or a rename, not wrong prose: what the documentation
 * says about each of them is held to the code by review.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DocumentationTest extends TestCase
{
    /** @var list<class-string<\BackedEnum>> The public enums whose every value is documented. */
    private const array ENUMS = [Outcome::class, Origin::class, Provenance::class, FieldHandling::class, KeyOwner::class];

    /** @var list<string> The sections of every design note, in order. */
    private const array SECTIONS = ['Purpose', 'Invariants', 'Success Path', 'Failure / Edge Cases', 'Implementation Anchors', 'Authoritative Tests', 'Change Triggers'];

    /** @var list<string> The design notes the package ships so far. */
    private const array NOTES = ['record-model.md', 'event-definitions.md', 'vocabulary.md'];

    /** @var string The sentence the design index ends with. */
    private const string CLOSING = 'These documents are secondary to the code and tests, not a replacement for them. '
        . 'If a note and a cited test disagree, the test should be treated as authoritative until the mismatch is resolved.';

    /** @var list<string> The code prefixes the vocabulary reserves. */
    private const array RESERVED_PREFIXES = ['authentication.', 'session.', 'account.', 'authorization.', 'mfa.', 'sso.', 'audit_log.'];

    /** @var list<string> Laravel's own configuration files, which an example may read. */
    private const array LARAVEL_CONFIG = ['app', 'auth', 'cache', 'database', 'filesystems', 'logging', 'queue', 'session'];

    /** @var string The package's configuration key. */
    private const string CONFIG_KEY = 'audit-log';

    /** @var string The package's namespace, the one the suite's namespace may be followed by in an example. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string A string-literal argument, single or double quoted. */
    private const string LITERAL = '(?:\'([^\'\\\]*)\'|"([^"\\\]*)")';

    /** @var ?string The README, the guides and the design notes, read once. */
    private static ?string $documentation = null;

    /**
     * Rows of `[enum value, enum]`: every outcome, origin, provenance, field
     * handling and key owner.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        foreach (self::ENUMS as $enum) {
            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$case->value, $enum];
            }
        }
    }

    /**
     * Every value of those enums is named in the documentation, in code type.
     *
     * @param  string  $value
     * @param  string  $enum
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEveryEnumValueIsDocumented(string $value, string $enum): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $value . '`'), sprintf('The documentation does not name the %s value `%s`.', $enum, $value));
    }

    /**
     * Rows of `[key]`: every configuration key the package config ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConfigurationKeys(): iterable
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);

        foreach (self::leafKeys($config) as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every configuration key is named by its full path in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConfigurationKeys')]
    public function testEveryConfigurationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the configuration key `%s`.', $key));
    }

    /**
     * Rows of `[file]`: every design note the package ships so far.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDesignNotes(): iterable
    {
        foreach (self::NOTES as $note) {
            yield $note => [$note];
        }
    }

    /**
     * Every design note the package ships so far exists.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideDesignNotes')]
    public function testEveryDesignNoteExists(string $note): void
    {
        self::assertFileExists(self::root() . '/docs/design/' . $note);
    }

    /**
     * Rows of `[file]`: every design note in docs/design but the index.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNoteFiles(): iterable
    {
        foreach (self::noteFiles() as $note) {
            yield $note => [$note];
        }
    }

    /**
     * Every design note opens with one Title Case heading and has the seven
     * standard sections in order, any other section sitting between the failure
     * and edge cases and the implementation anchors.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideNoteFiles')]
    public function testEveryDesignNoteHasTheStandardSections(string $note): void
    {
        $prose = self::withoutCodeBlocks(self::read('/docs/design/' . $note));

        preg_match_all('/^# (.+)$/m', $prose, $titles);
        preg_match_all('/^## (.+)$/m', $prose, $sections);

        self::assertCount(1, $titles[1], sprintf('%s does not have exactly one title.', $note));
        self::assertStringStartsWith('# ' . $titles[1][0], ltrim($prose), sprintf('%s does not open with its title.', $note));
        self::assertTrue(self::isTitleCase($titles[1][0]), sprintf('The title of %s is not in Title Case.', $note));

        $found    = $sections[1];
        $extra    = array_slice($found, 4, max(0, count($found) - count(self::SECTIONS)));
        $standard = [...array_slice($found, 0, 4), ...array_slice($found, 4 + count($extra))];

        self::assertSame(self::SECTIONS, $standard, sprintf('%s does not have the standard sections in order.', $note));
        self::assertSame([], array_values(array_intersect($extra, self::SECTIONS)), sprintf('%s repeats a standard section.', $note));
    }

    /**
     * The design index lists the standard sections in order and has a bullet
     * for every note file and for no missing one, and its last paragraph is the
     * standard sentence.
     *
     * @return void
     */
    public function testTheDesignIndexListsEveryNoteAndEndsWithTheStandardSentence(): void
    {
        $index = self::read('/docs/design/README.md');

        preg_match_all('/^- `([^`]+\.md)`: /m', $index, $notes);
        preg_match_all('/^- `([^`]+)`$/m', $index, $sections);

        $listed = $notes[1];
        $files  = self::noteFiles();

        sort($listed);
        sort($files);

        $paragraphs = preg_split('/\n\s*\n/', trim($index)) ?: [];

        self::assertStringStartsWith("# Design Notes\n", $index);
        self::assertSame(self::SECTIONS, $sections[1], 'The design index does not list the standard sections in order.');
        self::assertSame($files, $listed, 'The design index does not list exactly the notes in docs/design.');
        self::assertSame(self::CLOSING, preg_replace('/\s+/', ' ', (string) end($paragraphs)), 'The design index does not end with the standard sentence.');
    }

    /**
     * Rows of `[file]`: every design note in docs/design but the index.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCitingNotes(): iterable
    {
        yield from self::provideNoteFiles();
    }

    /**
     * Every test file a note's authoritative tests cite exists, and every test
     * method cited after it is declared in that file; every note cites at least
     * one test.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideCitingNotes')]
    public function testEveryCitedTestExists(string $note): void
    {
        $cited = self::citedTests(self::section(self::read('/docs/design/' . $note), 'Authoritative Tests'));

        self::assertNotSame([], $cited, sprintf('%s cites no test.', $note));

        $missing = [];

        foreach ($cited as $file => $methods) {

            $path = self::root() . '/' . $file;

            if (!is_file($path)) {
                $missing[] = $file;

                continue;
            }

            $source = (string) file_get_contents($path);

            foreach ($methods as $method) {

                if (str_contains($source, 'function ' . $method . '(')) {
                    continue;
                }

                $missing[] = $file . ' ' . $method;
            }
        }

        self::assertSame([], $missing, sprintf('%s cites tests that do not exist.', $note));
    }

    /**
     * The citation scanner pairs each cited test method with the test file
     * cited before it, across wrapped lines, and lists a method cited before
     * any test file under a file that can never exist, so it is refused.
     *
     * @return void
     */
    public function testTheCitationScannerPairsEachMethodWithItsFile(): void
    {
        self::assertSame(['?' => ['testOrphan']], self::citedTests("- `testOrphan` in `src/Records/EventCode.php`\n"));
        self::assertSame(['tests/Unit/AnyTest.php' => ['testOne', 'testTwo']], self::citedTests("- `tests/Unit/AnyTest.php` `testOne`,\n  `testTwo`: `null`\n"));
    }

    /**
     * Rows of `[prefix]`: every code prefix the vocabulary reserves.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedPrefixes(): iterable
    {
        foreach (self::RESERVED_PREFIXES as $prefix) {
            yield $prefix => [$prefix];
        }
    }

    /**
     * Every reserved prefix has a row in the vocabulary's table.
     *
     * @param  string  $prefix
     * @return void
     */
    #[DataProvider('provideReservedPrefixes')]
    public function testEveryReservedPrefixIsInTheVocabulary(string $prefix): void
    {
        $row = '/^\| `' . preg_quote($prefix, '/') . '` +\|/m';

        self::assertSame(1, preg_match($row, self::read('/docs/design/vocabulary.md')), sprintf('The vocabulary has no row for `%s`.', $prefix));
    }

    /**
     * The prefix event codes refuse is one of the reserved prefixes.
     *
     * @return void
     */
    public function testThePackagePrefixIsTheOneEventCodesReserve(): void
    {
        self::assertContains(EventCode::RESERVED_PREFIX, self::RESERVED_PREFIXES);
    }

    /**
     * Every code the package ships, as a case of an enum defining events, sits
     * under a reserved prefix.
     *
     * @return void
     */
    public function testEveryShippedCodeIsUnderAReservedPrefix(): void
    {
        self::assertSame([], self::codesOutsideTheReservedPrefixes(self::shippedCodes()), 'The package ships codes outside the reserved prefixes.');
    }

    /**
     * Every code the package ships is named in the documentation, in code type.
     *
     * @return void
     */
    public function testEveryShippedCodeIsDocumented(): void
    {
        $undocumented = array_values(array_filter(self::shippedCodes(), static fn (string $code): bool => !str_contains(self::documentation(), '`' . $code . '`')));

        self::assertSame([], $undocumented, 'The documentation does not name every shipped code.');
    }

    /**
     * The shipped-code check reads the case values of an enum defining events
     * and finds each one outside the reserved prefixes, so the check above is
     * not empty by construction.
     *
     * @return void
     */
    public function testTheShippedCodeCheckReadsEveryCaseOfADefiningEnum(): void
    {
        $codes = self::codesOf([InvoiceActivity::class, Outcome::class, self::class]);

        self::assertSame(['invoice.approved', 'invoice.refund_failed'], $codes);
        self::assertSame($codes, self::codesOutsideTheReservedPrefixes($codes));
        self::assertSame([], self::codesOutsideTheReservedPrefixes(['audit_log.pruned', 'session.created']));
        self::assertSame(['audit_logs.pruned', 'app.session.created'], self::codesOutsideTheReservedPrefixes(['audit_logs.pruned', 'app.session.created']));
    }

    /**
     * The documentation's examples record at least one code, and every code an
     * example records or declares is a valid event code under no reserved
     * prefix.
     *
     * @return void
     */
    public function testEveryExampleCodeIsValidAndNeutral(): void
    {
        $codes   = self::exampleCodesIn(self::codeBlocks());
        $invalid = [];

        foreach ($codes as $code) {
            try {
                EventCode::of($code);
            } catch (\InvalidArgumentException) {
                $invalid[] = $code;
            }
        }

        self::assertNotSame([], $codes, 'The documentation shows no example code.');
        self::assertSame([], $invalid, 'The documentation shows invalid event codes.');
        self::assertSame([], self::codesUnderTheReservedPrefixes($codes), 'The documentation shows codes under a reserved prefix.');
    }

    /**
     * The example scanner finds the first string-literal argument of every call
     * that names a code and the value of every enum case, and nothing else.
     *
     * @return void
     */
    public function testTheExampleScannerFindsEveryFormOfCode(): void
    {
        $example = <<<'PHP'
            AuditLog::record('invoice.approved', subject: $invoice);
            AuditLog::event("user.suspended")->on($user)->record();
            AuditLog::accessed( 'patient.record_viewed', subject: $record);
            AuditLog::bulk('invoice.exported', $invoices);
            EventDefinition::for('invoice.voided')->category('finance');
            EventDefinition::for($this)->retain('amount');
            Event::dispatch('not.a_code');
            $builder->recorded('not.a_code');
            case APPROVED = 'invoice.refunded';
            case Pending = 'not.a_case';
            // case DRAFT = 'invoice.drafted';
            PHP;

        $codes = ['invoice.approved', 'user.suspended', 'patient.record_viewed', 'invoice.exported', 'invoice.voided', 'invoice.refunded', 'invoice.drafted'];

        self::assertSame($codes, self::exampleCodesIn($example));
    }

    /**
     * The code blocks of the documentation name no other package of the suite:
     * no namespace of it, no Composer package of it, and no configuration but
     * the package's own and Laravel's.
     *
     * @return void
     */
    public function testNoExampleNamesAnotherSuitePackage(): void
    {
        self::assertSame([], self::foreignNamesIn(self::codeBlocks()), 'The documentation\'s examples name another package of the suite.');
    }

    /**
     * The neutrality scanner finds every form of another package's name, in
     * code and in strings, and none of the package's own or Laravel's.
     *
     * @return void
     */
    public function testTheNeutralityScannerFindsEveryForeignName(): void
    {
        $example = <<<'PHP'
            use SineMacula\Laravel\AuditLog\Facades\AuditLog;
            use SineMacula\Laravel\Other\Thing;
            $class = 'SineMacula\\Laravel\\Another\\Thing';
            $other = \SineMacula\Laravel\AuditLogger\Thing::class;
            composer require sinemacula/laravel-audit-log sinemacula/laravel-other
            $connection = config('audit-log.storage.connection');
            $driver = config("session.driver");
            $prefix = config('other.prefix');
            $value = Config::get('another.key');
            config(['third.key' => true]);
            PHP;

        self::assertSame([
            'SineMacula\Laravel\Other',
            'SineMacula\\\Laravel\\\Another',
            'SineMacula\Laravel\AuditLogger',
            'sinemacula/laravel-other',
            'config: other',
            'config: another',
            'config: third',
        ], self::foreignNamesIn($example));
    }

    /**
     * The dotted paths of the configuration's settings: every key whose value
     * is not a map of further settings, a list and an empty array included.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leafKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {

            $path = $prefix . $key;

            if (!is_array($value) || $value === [] || array_is_list($value)) {
                $keys[] = $path;

                continue;
            }

            array_push($keys, ...self::leafKeys($value, $path . '.'));
        }

        return $keys;
    }

    /**
     * The design notes in docs/design, by file name, the index excluded.
     *
     * @return list<string>
     */
    private static function noteFiles(): array
    {
        $files = array_map(static fn (string $file): string => basename($file), glob(self::root() . '/docs/design/*.md') ?: []);

        return array_values(array_filter($files, static fn (string $file): bool => $file !== 'README.md'));
    }

    /**
     * Whether a heading is in Title Case: every word starts with a capital
     * letter, but for the short words that stay lower case inside a title.
     *
     * @param  string  $title
     * @return bool
     */
    private static function isTitleCase(string $title): bool
    {
        $minor = ['a', 'an', 'and', 'as', 'at', 'by', 'for', 'in', 'of', 'on', 'or', 'the', 'to', 'with'];
        $words = preg_split('/[\s\/-]+/', $title) ?: [];

        foreach ($words as $position => $word) {
            if (preg_match('/\A\p{Lu}/u', $word) !== 1 && ($position === 0 || !in_array($word, $minor, true))) {
                return false;
            }
        }

        return $words !== [];
    }

    /**
     * The text of a `## ` section of a note, up to the next section.
     *
     * @param  string  $note
     * @param  string  $heading
     * @return string
     */
    private static function section(string $note, string $heading): string
    {
        $pattern = '/^## ' . preg_quote($heading, '/') . '\n(.*?)(?=^## |\z)/ms';

        return preg_match($pattern, $note, $matches) === 1 ? $matches[1] : '';
    }

    /**
     * The tests a section cites: each backticked test file, with the backticked
     * test methods that follow it. A method cited before any file is listed
     * under `?`, a file that can never exist.
     *
     * @param  string  $section
     * @return array<string, list<string>>
     */
    private static function citedTests(string $section): array
    {
        preg_match_all('/`([^`]+)`/', $section, $spans);

        $cited = [];
        $file  = null;

        foreach ($spans[1] as $span) {

            if (preg_match('/\Atests\/\S+Test\.php\z/', $span) === 1) {
                $file = $span;
                $cited[$file] ??= [];

                continue;
            }

            if (preg_match('/\Atest[A-Z]\w*\z/', $span) !== 1) {
                continue;
            }

            $cited[$file ?? '?'][] = $span;
        }

        return $cited;
    }

    /**
     * The event codes the package ships: the case values of every enum in
     * `src/` that defines events.
     *
     * @return list<string>
     */
    private static function shippedCodes(): array
    {
        $root    = self::root() . '/src/';
        $classes = [];
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $classes[] = self::PACKAGE_NAMESPACE . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -4));
        }

        sort($classes);

        return self::codesOf($classes);
    }

    /**
     * The case values of those classes that are enums defining events.
     *
     * @param  list<string>  $classes
     * @return list<string>
     */
    private static function codesOf(array $classes): array
    {
        $codes = [];

        foreach ($classes as $class) {

            if (!enum_exists($class) || !is_subclass_of($class, DefinesAuditEvents::class)) {
                continue;
            }

            foreach ($class::cases() as $case) {
                $codes[] = (string) $case->value;
            }
        }

        return $codes;
    }

    /**
     * The codes that sit under none of the reserved prefixes.
     *
     * @param  list<string>  $codes
     * @return list<string>
     */
    private static function codesOutsideTheReservedPrefixes(array $codes): array
    {
        return array_values(array_diff($codes, self::codesUnderTheReservedPrefixes($codes)));
    }

    /**
     * The codes that sit under one of the reserved prefixes.
     *
     * @param  list<string>  $codes
     * @return list<string>
     */
    private static function codesUnderTheReservedPrefixes(array $codes): array
    {
        return array_values(array_filter($codes, static function (string $code): bool {

            foreach (self::RESERVED_PREFIXES as $prefix) {
                if (str_starts_with($code, $prefix)) {
                    return true;
                }
            }

            return false;
        }));
    }

    /**
     * The codes examples record or declare: the first string-literal argument
     * of each `record(`, `event(`, `accessed(`, `bulk(` and `for(` call, and
     * the value of each upper-case enum case, in the order they appear.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function exampleCodesIn(string $code): array
    {
        $pattern = '/(?:(?<![\w$])(?:record|event|accessed|bulk|for)\(\s*|\bcase\s+[A-Z][A-Z0-9_]*\s*=\s*)' . self::LITERAL . '/';

        preg_match_all($pattern, $code, $matches, PREG_SET_ORDER);

        return array_map(static fn (array $match): string => self::literal($match), $matches);
    }

    /**
     * The names of other packages of the suite that code names: a namespace of
     * the suite other than the package's own, written with single or doubled
     * backslashes, a Composer package of the suite other than this one, and the
     * first segment of every configuration key read or written that is neither
     * the package's own nor one of Laravel's files.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function foreignNamesIn(string $code): array
    {
        preg_match_all('/SineMacula(\\\{1,2})Laravel\1(?!AuditLog\b)[A-Za-z_]\w*/', $code, $namespaces);
        preg_match_all('/sinemacula\/laravel-(?!audit-log\b)[a-z][a-z0-9-]*/i', $code, $packages);
        preg_match_all('/(?:\bconfig|\bConfig::\w+)\(\s*\[?\s*' . self::LITERAL . '/', $code, $reads, PREG_SET_ORDER);

        $configs = [];

        foreach ($reads as $read) {

            $file = explode('.', self::literal($read))[0];

            if ($file === self::CONFIG_KEY || in_array($file, self::LARAVEL_CONFIG, true)) {
                continue;
            }

            $configs[] = 'config: ' . $file;
        }

        return [...$namespaces[0], ...$packages[0], ...$configs];
    }

    /**
     * The text of a string literal `LITERAL` matched, whichever quotes it is
     * in.
     *
     * @param  array<int|string, string>  $match
     * @return string
     */
    private static function literal(array $match): string
    {
        return ($match[1] ?? '') !== '' ? $match[1] : ($match[2] ?? '');
    }

    /**
     * The contents of every fenced code block in the documentation, joined.
     *
     * @return string
     */
    private static function codeBlocks(): string
    {
        preg_match_all('/^ *(```|~~~)[^\n]*\n(.*?)^ *\1[ \t]*$/ms', self::documentation(), $matches);

        return implode("\n", $matches[2]);
    }

    /**
     * The Markdown without its fenced code blocks, so a `#` comment in a code
     * block is never read as a heading.
     *
     * @param  string  $markdown
     * @return string
     */
    private static function withoutCodeBlocks(string $markdown): string
    {
        return (string) preg_replace('/^ *(```|~~~)[^\n]*\n.*?^ *\1[ \t]*$/ms', '', $markdown);
    }

    /**
     * The text of the README, every guide and every design note.
     *
     * @return string
     */
    private static function documentation(): string
    {
        $root  = self::root();
        $files = [$root . '/README.md', ...(glob($root . '/docs/guides/*.md') ?: []), ...(glob($root . '/docs/design/*.md') ?: [])];

        return self::$documentation ??= implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }

    /**
     * The contents of a file of the repository.
     *
     * @param  string  $path
     * @return string
     */
    private static function read(string $path): string
    {
        $contents = file_get_contents(self::root() . $path);

        self::assertIsString($contents, sprintf('%s cannot be read.', $path));

        return $contents;
    }

    /**
     * The repository's root directory.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
