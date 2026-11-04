<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Querying\Procedure\SubjectAccessPolicy;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * The reading guide's procedure for answering a subject access request: its
 * three blocks are in the guide as this test holds them, and run as written,
 * with nothing evaluated, they select the subject's entries as the actor and as
 * the subject, export and verify them, and give a copy holding no other
 * person's reference.
 *
 * The policy block's class is the fixture `SubjectAccessPolicy`, whose text
 * from its class declaration on is the block's. The selection and the review
 * blocks are the bodies of this test's `select()` and `review()`, their last
 * line, which hands back what the block left, aside, and each class a block
 * imports is imported here, the policy as the fixture. The investigator and the
 * subject are users under the morph alias `user`, as the seeded entries name
 * them: the subject is user 42, who acts on the seeded invoice, and another
 * person, user 99, acts on the subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessScope::class)]
#[CoversClass(AuditTrail::class)]
final class SubjectAccessProcedureTest extends TestCase
{
    use ReadsTheTrail;

    /** @var string The guide the procedure is in. */
    private const string GUIDE = '/docs/guides/reading.md';

    /** @var string The policy fixture, whose class is the procedure's. */
    private const string POLICY_FIXTURE = '/tests/Fixtures/Querying/Procedure/SubjectAccessPolicy.php';

    /** @var string The namespace the guide's policy is in. */
    private const string GUIDE_NAMESPACE = 'App\Audit\\';

    /** @var string The namespace the policy fixture is in. */
    private const string FIXTURE_NAMESPACE = 'Tests\Fixtures\Querying\Procedure\\';

    /** @var string The policy block, as the guide shows it. */
    private const string POLICY_BLOCK = <<<'MD'
        <!-- procedure:policy -->

        ```php
        <?php

        namespace App\Audit;

        use Illuminate\Contracts\Auth\Authenticatable;
        use SineMacula\Laravel\AuditLog\Access\AccessScope;
        use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
        use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
        use SineMacula\Laravel\AuditLog\Records\Reference;

        final readonly class SubjectAccessPolicy implements AuditAccessPolicy
        {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $investigator
             * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $subject
             */
            public function __construct(

                /** The person answering the request, as the application authenticated them. */
                #[\SensitiveParameter]
                private Authenticatable $investigator,

                /** The person the request is about. */
                private Reference $subject,
            ) {}

            /**
             * The subject's activity, as the actor or the subject of an entry, for the
             * investigator to read, count and export; the audit category, where the
             * export is journalled, for the investigator to verify the export; and
             * nothing for anyone else.
             *
             * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
             * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
             * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
             */
            #[\Override]
            public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
            {
                if ($viewer !== $this->investigator) {
                    return AccessScope::none();
                }

                return match ($purpose) {
                    ReadPurpose::VERIFY => AccessScope::all()->onlyCategories('audit'),
                    default             => AccessScope::all()->onlyAbout($this->subject),
                };
            }
        }
        ```
        MD;

    /** @var string The selection block, as the guide shows it. */
    private const string SELECT_BLOCK = <<<'MD'
        <!-- procedure:select -->

        ```php
        use App\Audit\SubjectAccessPolicy;
        use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
        use SineMacula\Laravel\AuditLog\Facades\AuditLog;
        use SineMacula\Laravel\AuditLog\Records\Reference;

        app()->instance(AuditAccessPolicy::class, new SubjectAccessPolicy($investigator, Reference::to($subject)));

        $trail   = AuditLog::trail()->visibleTo($investigator);
        $entries = [];
        $cursor  = null;

        do {
            $page    = $trail->cursorPaginate(100, $cursor);
            $entries = [...$entries, ...$page->entries];
            $cursor  = $page->nextCursor;
        } while ($cursor !== null);

        $export = $trail->export($path);

        if (!$trail->verifyExport($export->path)->isVerified()) {
            throw new \RuntimeException('The evidence export does not verify.');
        }
        ```
        MD;

    /** @var string The review block, as the guide shows it. */
    private const string REVIEW_BLOCK = <<<'MD'
        <!-- procedure:review -->

        ```php
        use SineMacula\Laravel\AuditLog\Querying\Describer;

        $describer = app(Describer::class);
        $you       = Reference::to($subject);
        $copy      = [];

        foreach ($entries as $entry) {
            $copy[] = [
                'when'      => $entry->toArray()['occurred_at'],
                'what'      => $describer->describe($entry)->title,
                'outcome'   => $entry->outcome->value,
                'by_you'    => (bool) $entry->actor?->equals($you),
                'about_you' => (bool) $entry->subject?->equals($you),
            ];
        }
        ```
        MD;

    /** @var string The morph alias the users are stored under, as the seeded entries name them. */
    private const string USER = 'user';

    /** @var string When the subject approved the seeded invoice. */
    private const string SUBJECT_ACTED_AT = '2026-11-01T12:00:00.000000Z';

    /** @var string When another person acted on the subject. */
    private const string ACTED_ON_AT = '2026-11-01T12:00:01.000000Z';

    /** @var string When another person acted on the seeded invoice. */
    private const string UNRELATED_AT = '2026-11-01T12:00:02.000000Z';

    /** @var string When another person acted with the subject as the principal. */
    private const string PRINCIPAL_AT = '2026-11-01T12:00:03.000000Z';

    /** @var list<string> The files the procedure exported, removed when the test ends. */
    private array $files = [];

    /**
     * Bind the read path, and store users under the alias the seeded entries
     * name them by.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();

        Relation::morphMap([self::USER => StubAuthUser::class]);
    }

    /**
     * Forget the alias and remove the files the procedure exported.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * Each block is in the guide exactly as this test holds it, and is what
     * this test runs: the policy fixture's class is the policy block's, the
     * bodies of `select()` and `review()` are the other blocks' code, and each
     * class a block imports is imported here.
     *
     * @return void
     */
    public function testTheBlocksAreInTheGuideAsHeldHere(): void
    {
        $guide  = self::read(self::GUIDE);
        $source = self::read('/tests/Feature/Querying/SubjectAccessProcedureTest.php');

        foreach ([self::POLICY_BLOCK, self::SELECT_BLOCK, self::REVIEW_BLOCK] as $block) {
            self::assertStringContainsString($block, $guide);
        }

        self::assertSame(self::classOf(self::codeOf(self::POLICY_BLOCK)), self::classOf(self::read(self::POLICY_FIXTURE)));

        foreach (['select' => self::SELECT_BLOCK, 'review' => self::REVIEW_BLOCK] as $method => $block) {
            [$imports, $code] = self::splitImports(self::codeOf($block));

            self::assertSame($code, self::bodyOf($method), sprintf('%s() is not the block\'s code.', $method));

            foreach ($imports as $import) {
                self::assertStringContainsString(str_replace(self::GUIDE_NAMESPACE, self::FIXTURE_NAMESPACE, $import), $source);
            }
        }
    }

    /**
     * The procedure, run as written, selects the subject's entries as the actor
     * and as the subject, newest first, and none other; exports exactly those
     * and verifies the export; and gives a copy that holds the subject's own
     * activity and no other person's reference.
     *
     * @return void
     */
    public function testTheDocumentedProcedureRuns(): void
    {
        [$actedOn, $acted] = $this->seedTheTrail();

        [$entries, $lines] = $this->select(self::user(7), self::user(42), $this->exportPath());

        self::assertSame([$actedOn, $acted], array_map(static fn (TrailEntry $entry): string => $entry->id, $entries));
        self::assertSame(2, $lines);

        $copy = $this->review(self::user(42), $entries);

        self::assertSame([
            ['when' => self::ACTED_ON_AT, 'what' => 'invoice.approved', 'outcome' => 'success', 'by_you' => false, 'about_you' => true],
            ['when' => self::SUBJECT_ACTED_AT, 'what' => 'invoice.approved', 'outcome' => 'success', 'by_you' => true, 'about_you' => false],
        ], $copy);

        self::assertStringNotContainsString('99', (string) json_encode($copy));
        self::assertStringNotContainsString(self::USER, (string) json_encode($copy));
    }

    /**
     * The canonical export the procedure keeps as evidence holds what the copy
     * leaves out, the other person who acted on the subject included, which is
     * why it is not a copy for the subject.
     *
     * @return void
     */
    public function testTheEvidenceExportHoldsWhatTheCopyLeavesOut(): void
    {
        $this->seedTheTrail();

        $path = $this->exportPath();

        $this->select(self::user(7), self::user(42), $path);

        $actors = [];

        foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $row = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($row);

            $actors[] = [$row['actor_type'] ?? null, $row['actor_id'] ?? null];
        }

        self::assertSame([[self::USER, '42'], [self::USER, '99']], $actors);
    }

    /**
     * An entry whose principal is the subject, though neither its actor nor its
     * subject is, is not selected: `onlyAbout()` matches the actor and the
     * subject alone, as the guide says.
     *
     * @return void
     */
    public function testPrincipalReferencesAreNotSelected(): void
    {
        [$actedOn, $acted] = $this->seedTheTrail();

        $principal = $this->seedEntry(['actor_id' => '99', 'principal_type' => self::USER, 'principal_id' => '42'], self::PRINCIPAL_AT);

        [$entries] = $this->select(self::user(7), self::user(42), $this->exportPath());

        $ids = array_map(static fn (TrailEntry $entry): string => $entry->id, $entries);

        self::assertSame([$actedOn, $acted], $ids);
        self::assertNotContains($principal, $ids);
    }

    /**
     * The policy lets no one but the investigator see anything: another user
     * the application authenticated reads an empty trail, and cannot find the
     * investigator's export to verify it.
     *
     * @return void
     */
    public function testNoOneButTheInvestigatorSeesAnything(): void
    {
        $this->seedTheTrail();

        $path = $this->exportPath();

        $this->select(self::user(7), self::user(42), $path);

        $other = AuditLog::trail()->visibleTo(self::user(99));

        self::assertSame([], $other->cursorPaginate()->entries);
        self::assertSame(0, $other->count());
        self::assertContains(ExportFinding::ENTRY_MISSING, $other->verifyExport($path)->findings);
    }

    /**
     * Each read the procedure makes is recorded under the investigator: one
     * page, the export, and its verification.
     *
     * @return void
     */
    public function testEachReadOfTheProcedureIsRecordedUnderTheInvestigator(): void
    {
        $this->seedTheTrail();

        $this->select(self::user(7), self::user(42), $this->exportPath());

        $records = array_map(static fn (array $record): array => [$record['event'] ?? null, $record['actor_type'] ?? null, $record['actor_id'] ?? null], $this->readRecords());

        self::assertSame([
            ['audit_log.trail_read', self::USER, '7'],
            ['audit_log.trail_exported', self::USER, '7'],
            ['audit_log.export_verified', self::USER, '7'],
        ], $records);
    }

    /**
     * The selection block, run as written for the investigator and the subject,
     * exporting to the path; the entries it selected and the lines it exported
     * are handed back.
     *
     * @param  \Tests\Unit\Stubs\StubAuthUser  $investigator
     * @param  \Tests\Unit\Stubs\StubAuthUser  $subject
     * @param  string  $path
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Querying\TrailEntry>, 1: int}
     *
     * @throws \RuntimeException
     */
    private function select(StubAuthUser $investigator, StubAuthUser $subject, string $path): array
    {
        app()->instance(AuditAccessPolicy::class, new SubjectAccessPolicy($investigator, Reference::to($subject)));

        $trail   = AuditLog::trail()->visibleTo($investigator);
        $entries = [];
        $cursor  = null;

        do {
            $page    = $trail->cursorPaginate(100, $cursor);
            $entries = [...$entries, ...$page->entries];
            $cursor  = $page->nextCursor;
        } while ($cursor !== null);

        $export = $trail->export($path);

        if (!$trail->verifyExport($export->path)->isVerified()) {
            throw new \RuntimeException('The evidence export does not verify.');
        }

        return [$entries, $export->lines];
    }

    /**
     * The review block, run as written for the subject over the entries
     * selected; the copy it made is handed back.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Tests\Unit\Stubs\StubAuthUser  $subject
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\TrailEntry>  $entries
     * @return list<array{when: array<array-key, mixed>|int|string|null, what: string, outcome: string, by_you: bool, about_you: bool}>
     */
    private function review(StubAuthUser $subject, array $entries): array
    {
        $describer = app(Describer::class);
        $you       = Reference::to($subject);
        $copy      = [];

        foreach ($entries as $entry) {
            $copy[] = [
                'when'      => $entry->toArray()['occurred_at'],
                'what'      => $describer->describe($entry)->title,
                'outcome'   => $entry->outcome->value,
                'by_you'    => (bool) $entry->actor?->equals($you),
                'about_you' => (bool) $entry->subject?->equals($you),
            ];
        }

        return $copy;
    }

    /**
     * Seed the subject approving the invoice, another person acting on the
     * subject, and that person approving the invoice, a microsecond's order
     * apart; the ids of the two entries about the subject are returned, the
     * newest first.
     *
     * @return array{0: string, 1: string}
     */
    private function seedTheTrail(): array
    {
        $acted   = $this->seedEntry(['actor_type' => self::USER, 'actor_id' => '42'], self::SUBJECT_ACTED_AT);
        $actedOn = $this->seedEntry(['actor_id' => '99', 'subject_type' => self::USER, 'subject_id' => '42'], self::ACTED_ON_AT);

        $this->seedEntry(['actor_id' => '99'], self::UNRELATED_AT);

        return [$actedOn, $acted];
    }

    /**
     * A path of the test's own for an export, removed with its bundle when the
     * test ends.
     *
     * @return string
     */
    private function exportPath(): string
    {
        $path = sys_get_temp_dir() . '/' . uniqid('audit-subject-access-', true) . '.ndjson';

        array_push($this->files, $path, $path . '.manifest.json');

        return $path;
    }

    /**
     * A saved-looking user of the id, never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
    }

    /**
     * The code of a block: what its fence holds, without the marker and the
     * fence.
     *
     * @param  string  $block
     * @return string
     */
    private static function codeOf(string $block): string
    {
        self::assertSame(1, preg_match('/^```php\n(.*?)^```$/ms', $block, $matches));

        return $matches[1];
    }

    /**
     * The `use` lines a block's code opens with, and the code after them and
     * the blank line that follows them.
     *
     * @param  string  $code
     * @return array{0: list<string>, 1: string}
     */
    private static function splitImports(string $code): array
    {
        self::assertSame(1, preg_match('/\A((?:use [^\n]+;\n)+)\n(.*)\z/s', $code, $matches));

        return [explode("\n", rtrim($matches[1])), $matches[2]];
    }

    /**
     * The body of a method of this test, without its braces and its last line,
     * which hands back what the block left, with the method's indentation
     * removed.
     *
     * @param  string  $method
     * @return string
     */
    private static function bodyOf(string $method): string
    {
        $reflection = new \ReflectionMethod(self::class, $method);
        $lines      = explode("\n", self::read('/tests/Feature/Querying/SubjectAccessProcedureTest.php'));
        $body       = array_slice($lines, (int) $reflection->getStartLine() + 1, (int) $reflection->getEndLine() - (int) $reflection->getStartLine() - 2);

        self::assertStringStartsWith('return ', trim((string) array_pop($body)), sprintf('%s() does not end handing back what its block left.', $method));
        self::assertSame('', array_pop($body), sprintf('%s() does not set its last line apart.', $method));

        return implode("\n", array_map(static fn (string $line): string => (string) preg_replace('/\A {8}/', '', $line), $body)) . "\n";
    }

    /**
     * The text of PHP source from its class declaration to its end, with its
     * trailing whitespace dropped.
     *
     * @param  string  $source
     * @return string
     */
    private static function classOf(string $source): string
    {
        self::assertSame(1, preg_match('/^final .*\z/ms', $source, $matches));

        return rtrim($matches[0]);
    }

    /**
     * The contents of a file of the repository.
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
