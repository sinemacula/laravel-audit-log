<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Stores\DocumentedSpillChannel;

/**
 * A drift guard for the README, the guides in docs/guides and the design notes
 * in docs/design: every outcome, origin, provenance, field handling, key owner,
 * IP mode, identifier mode, failure mode, delivery mode, failed operation and
 * envelope failure, every configuration key and every method of the recorder is
 * documented; every package event has a row in the events table and in the
 * events guide; every `AuditLog::` call shown exists or is planned; every
 * design note, the redaction note, the threat model and the delivery note among
 * them, exists, has the standard sections and is listed in the index, which
 * ends with the standard sentence; the notes state what they must, and the
 * threat model opens with the limits of key matching; the redaction note lists
 * every entry of the matcher and every IP mode, and never calls key matching
 * fail-closed; every redaction, failure and delivery setting's environment
 * variable is in the README; the outcomes table has exactly its rows, and no
 * document says a failed record is not true; the documented spill channel is
 * the one the tests use, and the spill and the outbox are called personal data;
 * every test a note cites and every file it anchors exists, and no document
 * cites a file kept out of the repository, a milestone or another package of
 * the suite, or describes a transition from a release that does not exist; the
 * vocabulary reserves every prefix and every shipped code sits under one; and
 * every example is valid and neutral, naming no other package of the suite.
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
    private const array ENUMS = [
        Outcome::class,
        Origin::class,
        Provenance::class,
        FieldHandling::class,
        KeyOwner::class,
        IpMode::class,
        IdentifierMode::class,
        FailureMode::class,
        DeliveryMode::class,
        FailedOperation::class,
        EnvelopeFailure::class,
    ];

    /** @var list<string> The sections of every design note, in order. */
    private const array SECTIONS = ['Purpose', 'Invariants', 'Success Path', 'Failure / Edge Cases', 'Implementation Anchors', 'Authoritative Tests', 'Change Triggers'];

    /** @var list<string> The design notes the package ships so far. */
    private const array NOTES = [
        'record-model.md',
        'event-definitions.md',
        'vocabulary.md',
        'storage.md',
        'integrity.md',
        'outcomes.md',
        'delivery.md',
        'event-model.md',
        'context-resolution.md',
        'redaction.md',
        'threat-model.md',
        'testing-helpers.md',
    ];

    /** @var string The sentence the threat model opens with. */
    private const string KEY_MATCHING_LIMITS = 'Key matching cannot find a secret in free text or under an innocuous key; '
        . 'event definitions, which allowlist fields, are the remedy.';

    /** @var string The sentence the threat model states the brute force limit with. */
    private const string BRUTE_FORCE_LIMIT = 'A guessable identifier falls to brute force once the key leaks.';

    /** @var string The redaction note. */
    private const string REDACTION_NOTE = '/docs/design/redaction.md';

    /** @var string The threat model. */
    private const string THREAT_MODEL = '/docs/design/threat-model.md';

    /** @var string The delivery note. */
    private const string DELIVERY_NOTE = '/docs/design/delivery.md';

    /** @var string The event model. */
    private const string EVENT_MODEL = '/docs/design/event-model.md';

    /** @var string The outcomes note. */
    private const string OUTCOMES_NOTE = '/docs/design/outcomes.md';

    /** @var string The events guide. */
    private const string EVENTS_GUIDE = '/docs/guides/events.md';

    /** @var string The sentence both the threat model and the delivery note state about the spill and the outbox. */
    private const string PERSONAL_DATA = 'The spill and the outbox hold personal data';

    /** @var list<string> The rows of the outcomes table, in order. */
    private const array OUTCOME_ROWS = [
        'after-commit-sync-report',
        'after-commit-sync-throw',
        'after-commit-none-open',
        'after-commit-outbox-same',
        'after-commit-outbox-same-throw',
        'after-commit-outbox-other',
        'immediately-sync-report',
        'immediately-sync-throw',
        'immediately-outbox',
        'transactional-sync',
        'transactional-outbox',
        'fail-closed-sync',
        'fail-closed-outbox',
        'fail-closed-transactional',
        'host-deadlock',
        'host-connection-lost',
        'aborted-postgres-host',
        'failed-finalise',
        'inside-a-store',
        'inside-a-store-strict',
        'drain-transient',
        'drain-final',
        'drain-undecryptable',
    ];

    /** @var list<string> The facade calls the documentation may show before they ship; this list empties as each arrives. */
    private const array PLANNED_CALLS = ['bulk', 'capture', 'map'];

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

    /** @var string The ways of calling something fail-closed, however the words are wrapped. */
    private const string FAIL_CLOSED = '/\bfail(?:s|ed|ing)?[\s-]+closed\b/i';

    /** @var string A citation of what is kept out of the repository: the requirements, the backlog or a build file. */
    private const string LOCAL_ONLY = '/FEATURES\.md|BACKLOG\.md|\bAUDIT-[A-Z]+\.\d|\bBL-\d|\.sinemacula\b|\bm\d+-design\b|§/';

    /** @var string A way of saying a failed record is not true, which it can be even when the business change rolls back, however the words are wrapped. */
    private const string NOT_TRUE = '/\b(?:the|a|its|that)\s+(?:failed\s+|spilled\s+)?record\s+(?:is|was)\s+(?:not|never)\s+true\b/i';

    /** @var string A citation of how the work was divided, which means nothing to a reader of the repository. */
    private const string MILESTONE = '/\bmilestones?\b|\bM[1-9]\b/';

    /** @var string Words describing a transition from a release, and none exists. */
    private const string TRANSITION = '/\bbreaking change|\bdeprecat|\bupgrade notes?\b|\bbackward[s]?[\s-]compat/i';

    /** @var string The name of another package of the suite, in prose as much as in code. */
    private const string SIBLING = '/\blaravel-(?:authentication|authorization|mfa|sso|iam)\b/i';

    /** @var ?string The README, the guides and the design notes, read once. */
    private static ?string $documentation = null;

    /**
     * Rows of `[enum value, enum]`: every outcome, origin, provenance, field
     * handling, key owner, IP mode and identifier mode.
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
     * Rows of `[event class]`: every event the package dispatches.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEvents(): iterable
    {
        foreach (glob(self::root() . '/src/Events/*.php') ?: [] as $file) {

            $class = self::PACKAGE_NAMESPACE . 'Events\\' . basename($file, '.php');

            if (!is_a($class, AuditLogEvent::class, true) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            yield basename($file, '.php') => [$class];
        }
    }

    /**
     * Every event the package dispatches has a row in the events table.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsTable(string $class): void
    {
        self::assertTrue(self::hasEventRow(self::documentation(), $class), sprintf('The events table has no row for %s.', $class));
    }

    /**
     * An event's row starts a table row with the event's whole class name, so
     * neither a mention in prose nor a row of a longer name counts.
     *
     * @return void
     */
    public function testTheEventRowMustNameTheWholeClass(): void
    {
        $class = AuditRecorded::class;

        self::assertTrue(self::hasEventRow("| Event |\n| `{$class}` | The store accepted it |\n", $class));
        self::assertFalse(self::hasEventRow("`{$class}` is dispatched.\n", $class));
        self::assertFalse(self::hasEventRow("| The store accepted it | `{$class}` |\n", $class));
        self::assertFalse(self::hasEventRow("| `{$class}Later` | Later |\n", $class));
    }

    /**
     * Rows of `[method]`: every public method the recorder declares.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRecorderMethods(): iterable
    {
        foreach (self::callsDeclaredOn(Recorder::class) as $method) {
            yield $method => [$method];
        }
    }

    /**
     * Every method the recorder declares is shown being called.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideRecorderMethods')]
    public function testEveryRecorderMethodIsDocumented(string $method): void
    {
        self::assertSame(1, preg_match('/(::|->|`)' . $method . '\(/', self::documentation()), sprintf('The documentation does not show %s().', $method));
    }

    /**
     * Every `AuditLog::name(` the documentation shows is a method the recorder
     * or the facade declares, or a call that is planned.
     *
     * @return void
     */
    public function testEveryAuditLogCallTheDocumentationShowsExists(): void
    {
        $unknown = array_values(array_diff(self::auditLogCallsIn(self::documentation()), self::knownAuditLogCalls()));

        self::assertSame([], $unknown, 'The documentation shows AuditLog calls that do not exist.');
    }

    /**
     * The call scanner finds every call on the facade, however it is qualified
     * or spaced, each once, and nothing else with that name in it.
     *
     * @return void
     */
    public function testTheCallScannerFindsEveryAuditLogCall(): void
    {
        $text = <<<'EOD'
            AuditLog::record('invoice.approved');
            Use `AuditLog::event()` to build one up.
            \SineMacula\Laravel\AuditLog\Facades\AuditLog::accessed('document.downloaded');
            $fake = AuditLog::fake ();
            AuditLog::
                contribute(OrganisationContributor::class);
            AuditLog::record('invoice.voided');
            $class = AuditLog::class;
            NotAuditLog::bulk();
            $AuditLog::map();
            AuditLog->capture();
            EOD;

        self::assertSame(['record', 'event', 'accessed', 'fake', 'contribute'], self::auditLogCallsIn($text));
    }

    /**
     * The calls allowed are those the recorder and the facade declare and the
     * planned ones, by their exact names: what the facade inherits from
     * Laravel, or forwards by magic, is not part of the package's surface, and
     * a call in the wrong case is not the call.
     *
     * @return void
     */
    public function testTheKnownCallsAreOnlyThePackagesOwn(): void
    {
        $known = self::knownAuditLogCalls();

        foreach (['record', 'event', 'accessed', 'define', 'contribute', 'fake', 'recorder', 'bulk', 'capture', 'map'] as $call) {
            self::assertContains($call, $known);
        }

        foreach (['__construct', '__callStatic', 'swap', 'spy', 'shouldReceive', 'getFacadeRoot', 'getFacadeAccessor', 'Record'] as $call) {
            self::assertNotContains($call, $known);
        }
    }

    /**
     * No planned call has shipped yet, so the list cannot outlive the methods
     * it stands in for: a planned call that ships fails here until it is taken
     * off the list.
     *
     * @return void
     */
    public function testNoPlannedCallHasShipped(): void
    {
        self::assertSame([], array_values(array_intersect(self::PLANNED_CALLS, self::callsDeclaredOn(Recorder::class))));
        self::assertSame([], array_values(array_intersect(self::PLANNED_CALLS, self::callsDeclaredOn(AuditLog::class))));
    }

    /**
     * The context note states what trusting a header depends on: `TrustProxies`
     * must be configured, only the immediate peer is checked, and the trusted
     * edge must overwrite or validate the headers.
     *
     * @return void
     */
    public function testTheContextNoteStatesTheProxyPrerequisite(): void
    {
        $note = self::prose('/docs/design/context-resolution.md');

        self::assertStringContainsString('`TrustProxies` must be configured', $note);
        self::assertStringContainsString('`isFromTrustedProxy()` checks only the immediate peer', $note);
        self::assertStringContainsString('the trusted edge must overwrite or validate these headers', $note);
    }

    /**
     * The context note states that what is carried into a job is readable in
     * the queue payload.
     *
     * @return void
     */
    public function testTheContextNoteStatesThatHiddenContextIsNotEncrypted(): void
    {
        self::assertStringContainsString('Hidden Context travels in the queue payload unencrypted', self::prose('/docs/design/context-resolution.md'));
    }

    /**
     * Rows of `[note, statement]`: what the notes must say, each a rule or a
     * caveat a reader would otherwise find out the hard way.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRequiredStatements(): iterable
    {
        $context     = '/docs/design/context-resolution.md';
        $testing     = '/docs/design/testing-helpers.md';
        $definitions = '/docs/design/event-definitions.md';
        $record      = '/docs/design/record-model.md';
        $storage     = '/docs/design/storage.md';
        $integrity   = '/docs/design/integrity.md';

        yield from [
            'the actor is never loaded'          => [$context, 'never through `user()`'],
            'guards with the trait only'         => [$context, '`GuardHelpers` trait'],
            'a foreign guard is asked one thing' => [$context, '`hasUser()` and nothing else'],
            'the guard goes with the actor'      => [$context, 'The guard goes with the ambient actor only'],
            'a record before the middleware'     => [$context, 'before the `auth` middleware'],
            'outside any frame'                  => [$context, 'Outside any frame the origin is `console`'],
            'a nested call without events'       => [$context, '`$this->call()` inside a command emits no command event'],
            'no claimed id'                      => [$context, 'No claimed id is kept'],
            'the snapshot is not authentication' => [$context, 'who started the work, not current authentication'],
            'only the package is reset'          => [$context, 'Only the package\'s own state is ever reset'],
            'a guard a job leaves signed in'     => [$context, 'still holding the identical object counts as holding nobody'],
            'a listener on the end of a job'     => [$context, 'still inside the frame'],
            'a record before trusting a proxy'   => [$context, 'in global middleware ahead of `TrustProxies`'],
            'the recorder is stateless'          => [$context, 'The recorder is stateless'],
            'registration at boot'               => [$context, 'not from a `booted()` callback'],
            'the fake is no engine'              => [$testing, 'no transaction engine'],
            'field rules apply at capture'       => [$testing, 'Field rules apply at capture'],
            'the failing fake'                   => [$testing, '`FakeAuditStore::failing(\Throwable)`'],
            'the first assertion'                => [$testing, '`assertAudited($code, ?Closure)`'],
            'the second assertion'               => [$testing, '`assertNotAudited($code, ?Closure)`'],
            'the third assertion'                => [$testing, '`assertNothingAudited()`'],
            'the fourth assertion'               => [$testing, '`assertAuditedTimes($code, $times)`'],
            'what the store received'            => [$testing, '`finalised()`, what the store received'],
            'faking every event'                 => [$testing, '`Event::fake([AuditRecorded::class])`'],
            'skipping the middleware'            => [$testing, '`withoutMiddleware()` means no HTTP frame'],
            'console events in a test'           => [$testing, '`WithConsoleEvents` is needed for command frames'],
            'a record after a request'           => [$testing, 'A record made after `$this->get()`'],
            'the test wrapper'                   => [$testing, '`transactional()` counts a `DatabaseTransactions` wrapper'],
            'registering in a test'              => [$testing, '`$app->booting()`'],
            'minimising in the pipeline'         => [$context, '`Privacy\RecordMinimiser` minimises it'],
            'a filled value is minimised'        => [$context, 'A filled value is minimised too'],
            'the walker reaches a nested rule'   => [$definitions, 'keeps `customer.email` and drops the rest of `customer`'],
            'the rules apply at capture'         => [$definitions, 'the rules apply at capture'],
            'what the metadata holds'            => [$record, 'it holds `note`, `identifier_hash` and `omitted`'],
            'an owned note is sealed'            => [$record, 'it is sealed through `Contracts\FieldEncrypter`'],
            'the record takes the minimised'     => [$record, '`AuditRecord::fromPending()` takes the minimised value'],
            'an exemption is an assumption'      => [self::REDACTION_NOTE, 'An exemption assumes non-secret metadata'],
            'an exempt container is kept'        => [self::REDACTION_NOTE, 'an exempt container\'s scalar values are kept'],
            'the remedy is a field rule'         => [self::REDACTION_NOTE, 'the remedy is an explicit field rule'],
            'policy before transform'            => [self::REDACTION_NOTE, 'selects the policy first and transforms the value after it'],
            'a long container is dropped'        => [self::REDACTION_NOTE, 'A container whose canonical JSON is longer than 1024 bytes is dropped and diagnosed'],
            'a 6to4 address keeps its /24'       => [self::REDACTION_NOTE, 'A `2002::/16` address truncates to its /40'],
            'an invalid address is no refusal'   => [self::REDACTION_NOTE, 'An invalid address is `null` in every mode and adds `$ip`'],
            'the minimum of the properties'      => [self::REDACTION_NOTE, 'at least 8192'],
            'the minimum of the context'         => [self::REDACTION_NOTE, 'at least 1024'],
            'what the count counts'              => [self::REDACTION_NOTE, '`count` counts removed branches'],
            'the note is not protected'          => [self::REDACTION_NOTE, 'A note is not protected'],
            'a mapped address is its IPv4'       => [self::REDACTION_NOTE, 'an IPv4-mapped address is its IPv4 address'],
            'the encrypter\'s failure is named'  => [self::REDACTION_NOTE, '`Privacy\FieldEncryptionFailedException`'],
            'no previous exception'              => [self::REDACTION_NOTE, 'has no previous exception'],
            'one report per capture'             => [self::REDACTION_NOTE, 'one report per capture'],
            'any other failure fails the write'  => [self::REDACTION_NOTE, 'Any other failure while minimising fails the write'],
            'words joined with no boundary'      => [self::THREAT_MODEL, '`mypassword`'],
            'only joined words are missed'       => [self::THREAT_MODEL, 'Only words joined with no boundary and not listed'],
            'the facade\'s frame'                => [self::THREAT_MODEL, 'which no attribute can mark'],
            'the setting that keeps arguments'   => [self::THREAT_MODEL, '`zend.exception_ignore_args`'],
            'minimising at capture'              => [self::THREAT_MODEL, 'nothing raw rests in a deferred callback, event or row'],
            'a secret is never un-redacted'      => [self::THREAT_MODEL, 'A built-in secret is never un-redacted'],
            'no key means no field'              => [self::THREAT_MODEL, 'An `ENCRYPT` field with no key is dropped'],
            'what a diagnostic never holds'      => [self::THREAT_MODEL, 'Diagnostics never hold a value or a dynamic key'],
            'the key falls with the application' => [self::THREAT_MODEL, 'A key from `app.key` falls with it'],
            'a dedicated key'                    => [self::THREAT_MODEL, 'A dedicated `redaction.key` allows independent operation'],
            'failed sign-ins correlate'          => [self::THREAT_MODEL, 'Failed sign-ins correlate with each other'],
            'a pseudonym is never another hash'  => [self::THREAT_MODEL, 'A pseudonym never equals an identifier hash or an IP hash'],
            'a value hashes alike in any field'  => [self::THREAT_MODEL, 'the same value does give the same hash in any field of any code'],
            'a field needing no linkage'         => [self::THREAT_MODEL, 'a field needing no linkage should use `drop` or `encrypt`'],
            'a key change is visible'            => [self::THREAT_MODEL, 'A key change is visible through the fingerprint'],
            'often shipped'                      => [self::THREAT_MODEL, 'often shipped off the server'],
            'what the encryption protects'       => [self::THREAT_MODEL, 'protects a database copy and not a compromised application holding the key'],
            'a spill is not encrypted'           => [self::THREAT_MODEL, 'A spill line is not encrypted'],
            'what a log\'s readers see'          => [self::THREAT_MODEL, 'no `MessageLogged` listener sees a spill line'],
            'other holders of a spill line'      => [self::THREAT_MODEL, 'a spill on the default channel can post a record to a chat room'],
            'what signing establishes'           => [self::THREAT_MODEL, 'What signing establishes'],
            'uncommitted is not evidence'        => [self::OUTCOMES_NOTE, 'A record for an uncommitted operation must not later become committed evidence.'],
            'a bound spill waits'                => [self::OUTCOMES_NOTE, 'A bound spill waits in memory'],
            'a spill waits for its connection'   => [self::OUTCOMES_NOTE, 'spill waits for any transaction still open on the connection it was written to'],
            'a spill written at once'            => [self::OUTCOMES_NOTE, 'spill is written at once'],
            'evidence of an attempt'             => [self::OUTCOMES_NOTE, 'evidence of an attempt, not of a committed change'],
            'the remaining gap'                  => [self::OUTCOMES_NOTE, 'The gap stays for `after-commit-outbox-other`'],
            'the sync gap'                       => [self::OUTCOMES_NOTE, 'a process that dies between a sync commit and its write loses it'],
            'the one decoder'                    => [self::DELIVERY_NOTE, '`Records\EnvelopeCodec` is the one decoder'],
            'failures move before the commit'    => [self::DELIVERY_NOTE, 'moves finalisation and insert failures before the commit'],
            'the guaranteed format'              => [self::DELIVERY_NOTE, 'Replay is guaranteed only for that format'],
            'at least once'                      => [self::DELIVERY_NOTE, 'at-least-once'],
            'no order'                           => [self::DELIVERY_NOTE, 'Delivery order is not guaranteed'],
            'calls within the lease'             => [self::DELIVERY_NOTE, 'a destination call must finish within `delivery.outbox.lease_seconds`'],
            'clocks within the lease'            => [self::DELIVERY_NOTE, 'worker clocks must agree to well within the lease'],
            'no drain inside a transaction'      => [self::DELIVERY_NOTE, 'the drain refuses to run inside a transaction'],
            'a stack and its capabilities'       => [self::DELIVERY_NOTE, 'joins a transaction only when every destination does'],
            'a host-fatal secondary failure'     => [self::DELIVERY_NOTE, 'a reporter or a listener on any connection with a transaction open propagates sanitised'],
            'nothing is scheduled'               => [self::DELIVERY_NOTE, 'The package does not schedule it'],
            'no job exists'                      => [self::DELIVERY_NOTE, 'because no job exists'],
            'why no job exists'                  => [self::DELIVERY_NOTE, 'Laravel stores exception text in `failed_jobs` separately from the payload'],
            'a call is no proof'                 => [self::DELIVERY_NOTE, 'a successful call to a remote destination is not proof that it ingested the record'],
            'receipts stay'                      => [self::DELIVERY_NOTE, 'Receipts are kept'],
            'old keys stay'                      => [self::DELIVERY_NOTE, 'Old keys must stay in `app.previous_keys`'],
            'a decrypt failure'                  => [self::DELIVERY_NOTE, 'A decrypt failure means a removed key or corruption, and the row is kept'],
            'never signed again'                 => [self::DELIVERY_NOTE, 'never re-signed'],
            'a removed key'                      => [self::DELIVERY_NOTE, 'restore the key or leave the record quarantined'],
            'where an unsigned record goes'      => [self::DELIVERY_NOTE, 'The importer, which has not shipped yet, is where an unsigned record goes, marked as asserted'],
            'a repeated log line'                => [self::DELIVERY_NOTE, 'a replay can repeat a log destination\'s line'],
            'a rewritten token'                  => [self::DELIVERY_NOTE, 'A `LineFormatter` substitutes `%context%`'],
            'a commit that is really a rollback' => [self::OUTCOMES_NOTE, 'A commit that is really a rollback writes nothing.'],
            'one record costs no other'          => [self::OUTCOMES_NOTE, 'One record\'s failure costs no other.'],
            'what a callback can still cost'     => [self::OUTCOMES_NOTE, 'An application callback can still cost the audit log its records.'],
            'what counts as fatal'               => [self::OUTCOMES_NOTE, 'What counts as fatal is read from the driver, not from the record.'],
            'a line is a projection'             => [self::DELIVERY_NOTE, 'The log store\'s line is a projection, not the integrity artefact'],
            'access to a spill file'             => [self::DELIVERY_NOTE, '**Access.**'],
            'rotating a spill file'              => [self::DELIVERY_NOTE, '**Rotation.**'],
            'keeping a spill file'               => [self::DELIVERY_NOTE, '**Retention.**'],
            'a percent sign is escaped'          => [self::DELIVERY_NOTE, 'every `%` is written as `\u0025`'],
            'the pinned OCSF version'            => [self::DELIVERY_NOTE, 'OCSF `1.9.0`'],
            'a mapping and its version'          => [self::DELIVERY_NOTE, 'A mapping applies only to records of its definition\'s version'],
            'the fallback'                       => [self::DELIVERY_NOTE, 'falls back to a Base Event'],
            'no invented classification'         => [self::DELIVERY_NOTE, 'A classification is never invented'],
            'the CEF header'                     => [self::DELIVERY_NOTE, 'CEF:0|Sine Macula|laravel-audit-log|<record_version>|<event>|<event>|<severity>|<extension>'],
            'the CEF extension'                  => [self::DELIVERY_NOTE, '`externalId`'],
            'a lost event'                       => [self::EVENT_MODEL, 'A crash between delete and dispatch loses an `AuditRecorded`'],
            'the event holds no value'           => [self::EVENT_MODEL, 'Neither holds a value of the record'],
            'the event contract'                 => [self::EVENT_MODEL, '`Contracts\AuditLogEvent`'],
            'what the guard leaves out'          => [self::EVENT_MODEL, 'The guard does not cover a contributor or an `AuditRecorded` listener'],
            'the failing fake by mode'           => [$testing, 'What the caller sees is the write path\'s, not the fake\'s'],
            'the fake says it can'               => [$testing, 'The fake says it is durable and that it joins a transaction on any connection'],
            'the fake in outbox mode'            => [$testing, 'In outbox mode a record reaches the fake when it is drained'],
            'the two tables'                     => [$storage, '`delivery.deliveries_table` (`audit_log_deliveries` by default) is always on the storage connection'],
            'the outbox\'s connection'           => [$storage, '`delivery.outbox.table` (`audit_log_outbox` by default) is on `delivery.outbox.connection`'],
            'the writer\'s other grants'         => [$storage, 'In outbox mode the writer also needs'],
            'a replay never signs'               => [$integrity, 'A replay verifies and never re-signs'],
            'rebuilding a record'                => [$record, '`AuditRecord::fromEnvelope()`'],
            'the codec in the record model'      => [$record, '`Records\EnvelopeCodec`, the one decoder'],
            'a queued listener'                  => [self::EVENTS_GUIDE, 'Use a queued listener'],
            'alerting on a failure'              => [self::EVENTS_GUIDE, 'Alert on a failed write'],
            'alerting on a record'               => [self::EVENTS_GUIDE, 'Alert on a stored record'],
            'what a listener may do'             => [self::EVENTS_GUIDE, 'What a listener may do'],
        ];
    }

    /**
     * Each of those notes states what it must, however the line is wrapped.
     *
     * @param  string  $note
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideRequiredStatements')]
    public function testEachNoteStatesWhatItMust(string $note, string $statement): void
    {
        self::assertStringContainsString($statement, self::prose($note));
    }

    /**
     * Rows of `[note, extra sections]`: the sections a note has beyond the
     * standard ones, in order.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideExtraSections(): iterable
    {
        yield from [
            'redaction'    => [self::REDACTION_NOTE, ['Key Matching', 'Field Rules', 'Budgets And Omission', 'IP Modes']],
            'threat model' => [self::THREAT_MODEL, ['Limits Of Key Matching', 'Keys And Brute Force', 'Spill And Outbox']],
            'delivery'     => [self::DELIVERY_NOTE, ['Spill Channel', 'Claims And Receipts', 'Replay', 'Stores And Capabilities', 'Formatters']],
        ];
    }

    /**
     * The redaction note, the threat model and the delivery note have their own
     * sections, in order, between the failure and edge cases and the
     * implementation anchors.
     *
     * @param  string  $note
     * @param  list<string>  $extra
     * @return void
     */
    #[DataProvider('provideExtraSections')]
    public function testEachNoteHasItsExtraSectionsInOrder(string $note, array $extra): void
    {
        preg_match_all('/^## (.+)$/m', self::withoutCodeBlocks(self::read($note)), $sections);

        self::assertSame([...array_slice(self::SECTIONS, 0, 4), ...$extra, ...array_slice(self::SECTIONS, 4)], $sections[1]);
    }

    /**
     * The threat model states the limits of key matching, in the sentence that
     * says what the remedy is, however the line is wrapped.
     *
     * @return void
     */
    public function testTheThreatModelStatesTheLimitsOfKeyMatching(): void
    {
        self::assertStringContainsString(self::KEY_MATCHING_LIMITS, self::prose(self::THREAT_MODEL));
    }

    /**
     * Those limits are the first thing the threat model says: the first
     * paragraph of its purpose starts with them.
     *
     * @return void
     */
    public function testTheThreatModelOpensWithThoseLimits(): void
    {
        $paragraphs = preg_split('/\n\s*\n/', trim(self::section(self::read(self::THREAT_MODEL), 'Purpose'))) ?: [];

        self::assertStringStartsWith(self::KEY_MATCHING_LIMITS, self::collapsed($paragraphs[0] ?? ''));
    }

    /**
     * The threat model states in its own section what a leaked key gives up,
     * however the line is wrapped.
     *
     * @return void
     */
    public function testTheThreatModelStatesTheBruteForceLimit(): void
    {
        self::assertStringContainsString(self::BRUTE_FORCE_LIMIT, self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Keys And Brute Force')));
    }

    /**
     * The threat model's section on key matching names the limits a reader
     * would otherwise assume were covered.
     *
     * @return void
     */
    public function testTheThreatModelNamesEachLimitOfKeyMatching(): void
    {
        $section = strtolower(self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Limits Of Key Matching')));

        foreach (['free text', 'innocuous keys', '`mypassword`', 'look-alikes', 'exempt containers', 'notes', '`auditlog::record()`', '`zend.exception_ignore_args`'] as $limit) {
            self::assertStringContainsString($limit, $section);
        }
    }

    /**
     * The redaction note calls key matching a heuristic and, however the words
     * are wrapped, never fail-closed; the threat model never does either.
     *
     * @return void
     */
    public function testTheRedactionNoteCallsKeyMatchingAHeuristic(): void
    {
        $section = self::section(self::read(self::REDACTION_NOTE), 'Key Matching');

        self::assertStringContainsString('heuristic', $section);
        self::assertSame(0, preg_match(self::FAIL_CLOSED, $section));
        self::assertSame(0, preg_match(self::FAIL_CLOSED, self::read(self::THREAT_MODEL)));
    }

    /**
     * The phrase key matching is never described with is found in each of its
     * forms, across a wrapped line, and not in a phrase that merely resembles
     * it.
     *
     * @return void
     */
    public function testTheFailClosedPatternFindsEachForm(): void
    {
        foreach (['fail-closed', 'Fails closed', "fails\n  closed", 'failing closed', 'failed-closed', 'fail closed'] as $phrase) {
            self::assertSame(1, preg_match(self::FAIL_CLOSED, $phrase), $phrase);
        }

        foreach (['a failure closed it', 'failsafe', 'the door is closed'] as $phrase) {
            self::assertSame(0, preg_match(self::FAIL_CLOSED, $phrase), $phrase);
        }
    }

    /**
     * Rows of `[entry]`: each survivor, exempt final token and sensitive unit
     * of the matcher, its tokens joined by `_`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMatcherEntries(): iterable
    {
        foreach ([...Redactor::SURVIVORS, ...array_map(static fn (string $token): array => [$token], Redactor::EXEMPT_FINAL_TOKENS), ...Redactor::SENSITIVE_UNITS] as $tokens) {

            $entry = implode('_', $tokens);

            yield $entry => [$entry];
        }
    }

    /**
     * Every entry of the matcher is named in the redaction note's section on
     * key matching, in code type.
     *
     * @param  string  $entry
     * @return void
     */
    #[DataProvider('provideMatcherEntries')]
    public function testTheRedactionNoteListsEveryMatcherEntry(string $entry): void
    {
        self::assertStringContainsString('`' . $entry . '`', self::section(self::read(self::REDACTION_NOTE), 'Key Matching'));
    }

    /**
     * Every IP mode has a row of its own in the redaction note's matrix.
     *
     * @return void
     */
    public function testTheRedactionNoteHasARowForEveryIpMode(): void
    {
        $section = self::section(self::read(self::REDACTION_NOTE), 'IP Modes');

        foreach (IpMode::cases() as $mode) {
            self::assertSame(1, preg_match('/^\| `' . $mode->value . '` +\|/m', $section), sprintf('The matrix has no row for `%s`.', $mode->value));
        }
    }

    /**
     * The redaction settings read from the environment are named in the README,
     * and there are as many as the settings that read one.
     *
     * @return void
     */
    public function testEveryRedactionLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_REDACTION_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(5, $variables[0], 'The configuration does not read the redaction environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
        }
    }

    /**
     * The failure and delivery settings read from the environment are named in
     * the README, and there are as many as the settings that read one.
     *
     * @return void
     */
    public function testEveryDeliveryLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_(?:FAILURE|DELIVERY)_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(9, $variables[0], 'The configuration does not read the failure and delivery environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
        }
    }

    /**
     * No document says a failed record is not true, because a failure or a
     * denial can be true even when the business change rolls back.
     *
     * @return void
     */
    public function testNoNoteSaysAFailedRecordIsNotTrue(): void
    {
        self::assertSame(0, preg_match(self::NOT_TRUE, self::documentation()), 'A document says a failed record is not true.');
    }

    /**
     * The phrase a failed record is never described with is found in each of
     * its forms, across a wrapped line, and not in a phrase that merely
     * resembles it.
     *
     * @return void
     */
    public function testTheNotTruePatternFindsEachForm(): void
    {
        foreach (['the record is not true', 'The record is not true', "the record\n  is not true", 'a failed record was never true', 'the spilled record is not true'] as $phrase) {
            self::assertSame(1, preg_match(self::NOT_TRUE, $phrase), $phrase);
        }

        foreach (['the record is true', 'A failure or a denial can be true', 'a record is not trusted'] as $phrase) {
            self::assertSame(0, preg_match(self::NOT_TRUE, $phrase), $phrase);
        }
    }

    /**
     * The guarantees of the outcomes note have exactly the rows they should, in
     * order, so a row added, removed or renamed is seen here as well as by its
     * test.
     *
     * @return void
     */
    public function testTheOutcomesTableHasEachRow(): void
    {
        preg_match_all('/^\| `([a-z-]+)` +\|/m', self::section(self::read(self::OUTCOMES_NOTE), 'Guarantees'), $rows);

        self::assertSame(self::OUTCOME_ROWS, $rows[1]);
    }

    /**
     * Each key of the channel the tests use, but its path, is in the delivery
     * note's code block with the same value, and the block has no key the tests
     * do not use, so the documented channel and the tested one cannot drift
     * apart.
     *
     * @return void
     */
    public function testTheDocumentedChannelIsTheTestedOne(): void
    {
        $block  = self::documentedChannel(self::section(self::read(self::DELIVERY_NOTE), 'Spill Channel'));
        $tested = DocumentedSpillChannel::config('');

        preg_match_all('/^ +\'(\w+)\' +=>/m', $block, $keys);

        self::assertSame(array_keys($tested), $keys[1], 'The documented channel does not have the keys of the tested one.');

        unset($tested['path']);

        foreach ($tested as $key => $value) {
            self::assertStringContainsString(self::channelEntry($key, $value), self::collapsed($block));
        }
    }

    /**
     * An entry of the channel is written as it is in configuration: a string in
     * quotes, a permission in octal, a class by its name, and a map with its
     * values written the same way, with a line feed in double quotes.
     *
     * @return void
     */
    public function testAChannelEntryIsWrittenAsItIsInConfiguration(): void
    {
        self::assertSame('\'level\' => \'critical\'', self::channelEntry('level', 'critical'));
        self::assertSame('\'permission\' => 0600', self::channelEntry('permission', 0600));
        self::assertSame('\'formatter\' => Tests\Unit\Documentation\DocumentationTest::class', self::channelEntry('formatter', self::class));
        self::assertSame('\'with\' => [\'format\' => "%message%\n", \'inline\' => false]', self::channelEntry('with', ['format' => "%message%\n", 'inline' => false]));
    }

    /**
     * The block is found by the channel's name, among others in its section,
     * and a section without it gives nothing.
     *
     * @return void
     */
    public function testTheChannelBlockIsFoundByItsName(): void
    {
        $section = "Text.\n\n```php\n\$other = 1;\n```\n\n```php\n'audit-spill' => [\n    'driver' => 'single',\n],\n```\n";

        self::assertSame("'audit-spill' => [\n    'driver' => 'single',\n],\n", self::documentedChannel($section));
        self::assertSame('', self::documentedChannel("```php\n\$other = 1;\n```\n"));
    }

    /**
     * The spill and the outbox are called personal data by the threat model, in
     * its own section, and by the delivery note, along with what the outbox's
     * encryption does not protect and who else can read a line.
     *
     * @return void
     */
    public function testTheSpillAndOutboxArePersonalData(): void
    {
        $section = self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Spill And Outbox'));

        self::assertStringContainsString(self::PERSONAL_DATA, $section);
        self::assertStringContainsString('often shipped off the server', $section);
        self::assertStringContainsString('not a compromised application holding the key', $section);
        self::assertStringContainsString('A spill line is not encrypted', $section);
        self::assertStringContainsString('no `MessageLogged` listener', $section);

        self::assertStringContainsString(self::PERSONAL_DATA, self::prose(self::DELIVERY_NOTE));
    }

    /**
     * Every event the package dispatches has a row in the events guide itself,
     * which is where a reader of the guide looks for it.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsGuide(string $class): void
    {
        self::assertTrue(self::hasEventRow(self::read(self::EVENTS_GUIDE), $class), sprintf('The events guide has no row for %s.', $class));
    }

    /**
     * No document cites a milestone, describes a transition from a release, or
     * names another package of the suite, in prose as much as in code.
     *
     * @return void
     */
    public function testNoDocumentCitesAMilestoneATransitionOrASibling(): void
    {
        self::assertSame(0, preg_match(self::MILESTONE, self::documentation()), 'The documentation cites a milestone.');
        self::assertSame(0, preg_match(self::TRANSITION, self::documentation()), 'The documentation describes a transition from a release.');
        self::assertSame(0, preg_match(self::SIBLING, self::documentation()), 'The documentation names another package of the suite.');
    }

    /**
     * Those patterns find each form, and neither the package's own name nor a
     * word that merely resembles one.
     *
     * @return void
     */
    public function testTheMilestoneTransitionAndSiblingPatternsFindEachForm(): void
    {
        foreach (['the milestone', 'in M5', 'M1 to M4'] as $citation) {
            self::assertSame(1, preg_match(self::MILESTONE, $citation), $citation);
        }

        foreach (['A breaking change', 'deprecated', 'Deprecation', 'upgrade notes', 'backward compatible', 'backwards-compatibility'] as $phrase) {
            self::assertSame(1, preg_match(self::TRANSITION, $phrase), $phrase);
        }

        foreach (['sinemacula/laravel-mfa', 'laravel-authentication', 'LARAVEL-IAM'] as $name) {
            self::assertSame(1, preg_match(self::SIBLING, $name), $name);
        }

        foreach (['M0', 'HMAC5', 'a line break', 'upgrade', 'sinemacula/laravel-audit-log'] as $text) {
            self::assertSame(0, preg_match(self::MILESTONE, $text), $text);
            self::assertSame(0, preg_match(self::TRANSITION, $text), $text);
            self::assertSame(0, preg_match(self::SIBLING, $text), $text);
        }
    }

    /**
     * Every file a note's implementation anchors name exists, and every note
     * names at least one.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideCitingNotes')]
    public function testEveryAnchoredFileExists(string $note): void
    {
        $anchored = self::anchoredFiles(self::section(self::read('/docs/design/' . $note), 'Implementation Anchors'));
        $missing  = array_values(array_filter($anchored, static fn (string $file): bool => !is_file(self::root() . '/' . $file)));

        self::assertNotSame([], $anchored, sprintf('%s anchors no file.', $note));
        self::assertSame([], $missing, sprintf('%s anchors files that do not exist.', $note));
    }

    /**
     * The anchor scanner finds each backticked file, and neither a method nor a
     * constant cited after it.
     *
     * @return void
     */
    public function testTheAnchorScannerFindsOnlyFiles(): void
    {
        $section = "- `src/Recorder.php`: `write()`; `config/audit-log.php`: `redaction`.\n- `database/migrations/one.php`, `MARKER`, `Privacy\\Redactor`.\n";

        self::assertSame(['src/Recorder.php', 'config/audit-log.php', 'database/migrations/one.php'], self::anchoredFiles($section));
    }

    /**
     * Nothing a reader of the repository can see cites what is kept out of it,
     * since such a citation would lead nowhere.
     *
     * @return void
     */
    public function testNoDocumentCitesAFileKeptOutOfTheRepository(): void
    {
        self::assertSame(0, preg_match(self::LOCAL_ONLY, self::documentation()), 'The documentation cites a file kept out of the repository.');
    }

    /**
     * The pattern for what is kept out of the repository finds each form of
     * citation, and neither a requirement-like word nor the package's own
     * environment variables.
     *
     * @return void
     */
    public function testTheLocalCitationPatternFindsEachForm(): void
    {
        foreach (['see FEATURES.md', 'BACKLOG.md', 'AUDIT-REDACT.8', 'BL-33', '.sinemacula/build', 'm4-design.md', 'section §9'] as $citation) {
            self::assertSame(1, preg_match(self::LOCAL_ONLY, $citation), $citation);
        }

        foreach (['AUDIT_LOG_REDACTION_KEY', 'audit-log:check', 'BL-', 'sinemacula/laravel-audit-log'] as $text) {
            self::assertSame(0, preg_match(self::LOCAL_ONLY, $text), $text);
        }
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
     * The files a section anchors: each backticked path into the package's own
     * source, configuration or database directories.
     *
     * @param  string  $section
     * @return list<string>
     */
    private static function anchoredFiles(string $section): array
    {
        preg_match_all('/`((?:src|config|database)\/[^`\s]+\.php)`/', $section, $files);

        return $files[1];
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
     * Whether the text has a table row starting with the event's class name.
     *
     * @param  string  $text
     * @param  string  $class
     * @return bool
     */
    private static function hasEventRow(string $text, string $class): bool
    {
        return preg_match('/^\| `' . preg_quote($class, '/') . '`/m', $text) === 1;
    }

    /**
     * The methods called on the `AuditLog` facade in the text, each once, in
     * the order they first appear.
     *
     * @param  string  $text
     * @return list<string>
     */
    private static function auditLogCallsIn(string $text): array
    {
        preg_match_all('/(?<![\w$])AuditLog\s*::\s*(\w+)\s*\(/', $text, $matches);

        return array_values(array_unique($matches[1]));
    }

    /**
     * The calls the documentation may show on the facade.
     *
     * @return list<string>
     */
    private static function knownAuditLogCalls(): array
    {
        return [...self::callsDeclaredOn(Recorder::class), ...self::callsDeclaredOn(AuditLog::class), ...self::PLANNED_CALLS];
    }

    /**
     * The public methods the class declares itself, which are not inherited,
     * but for its constructor and any magic method.
     *
     * @param  class-string  $class
     * @return list<string>
     */
    private static function callsDeclaredOn(string $class): array
    {
        $calls = [];

        foreach ((new \ReflectionClass($class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->getDeclaringClass()->getName() !== $class || str_starts_with($method->getName(), '__')) {
                continue;
            }

            $calls[] = $method->getName();
        }

        return $calls;
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
     * The fenced code block of a section that holds the documented channel,
     * found by its name, or nothing when none does.
     *
     * @param  string  $section
     * @return string
     */
    private static function documentedChannel(string $section): string
    {
        preg_match_all('/^ *```[^\n]*\n(.*?)^ *```[ \t]*$/ms', $section, $blocks);

        foreach ($blocks[1] as $block) {
            if (str_contains($block, '\'audit-spill\'')) {
                return $block;
            }
        }

        return '';
    }

    /**
     * An entry of the channel, written as it is in configuration.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return string
     */
    private static function channelEntry(string $key, mixed $value): string
    {
        return sprintf('\'%s\' => %s', $key, self::channelValue($value));
    }

    /**
     * A value of the channel, written as it is in configuration.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     */
    private static function channelValue(mixed $value): string
    {
        if (is_array($value)) {
            $entries = array_map(self::channelEntry(...), array_keys($value), array_values($value));

            return '[' . implode(', ', $entries) . ']';
        }

        return match (true) {
            is_bool($value)                                 => $value ? 'true' : 'false',
            is_int($value)                                  => sprintf('0%o', $value),
            is_string($value) && class_exists($value)       => $value . '::class',
            is_string($value) && str_contains($value, "\n") => '"' . addcslashes($value, "\n") . '"',
            default                                         => '\'' . (is_string($value) ? $value : get_debug_type($value)) . '\'',
        };
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
     * A file of the repository with every run of whitespace made one space, so
     * a sentence is found however its lines are wrapped.
     *
     * @param  string  $path
     * @return string
     */
    private static function prose(string $path): string
    {
        return self::collapsed(self::read($path));
    }

    /**
     * The text with every run of whitespace made one space.
     *
     * @param  string  $text
     * @return string
     */
    private static function collapsed(string $text): string
    {
        return (string) preg_replace('/\s+/', ' ', $text);
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
