<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Querying\Procedure\SubjectAccessPolicy;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * The reading guide's subject access procedure, run as written: the bodies of
 * `select()`, `review()` and `erase()`, less their last line, are its blocks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessScope::class)]
#[CoversClass(AuditTrail::class)]
#[CoversClass(AuditLifecycle::class)]
final class SubjectAccessProcedureTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

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
             * @param  bool  $fragments
             */
            public function __construct(

                /** The person answering the request, as the application authenticated them. */
                #[\SensitiveParameter]
                private Authenticatable $investigator,

                /** The person the request is about. */
                private Reference $subject,

                /** Whether the investigator is finding the entries that hold the subject's fragments. */
                private bool $fragments = false,
            ) {}

            /**
             * For the investigator, the audit category, where an export is journalled,
             * to verify an export; otherwise, with the encrypted fields revealed, the
             * subject's activity, as the actor or the subject of an entry, or every
             * entry while finding the subject's fragments, which can be in an entry
             * about anyone. Nothing for anyone else.
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

                if ($purpose === ReadPurpose::VERIFY) {
                    return AccessScope::all()->onlyCategories('audit');
                }

                $scope = $this->fragments ? AccessScope::all() : AccessScope::all()->onlyAbout($this->subject);

                return $scope->revealingEncryptedFields();
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

        $you     = Reference::to($subject);
        $entries = [];
        $exports = [];

        foreach (['activity' => false, 'fragments' => true] as $selection => $fragments) {
            app()->instance(AuditAccessPolicy::class, new SubjectAccessPolicy($investigator, $you, $fragments));

            $trail  = AuditLog::trail()->visibleTo($investigator);
            $trail  = $fragments ? $trail->holdingDataOf($you) : $trail;
            $cursor = null;

            do {
                $page   = $trail->cursorPaginate(100, $cursor);
                $cursor = $page->nextCursor;

                foreach ($page->entries as $entry) {
                    $entries[$entry->id] ??= $entry;
                }
            } while ($cursor !== null);

            $exports[$selection] = $trail->export("{$directory}/{$selection}.ndjson");

            if (!$trail->verifyExport($exports[$selection]->path)->isVerified()) {
                throw new \RuntimeException('The evidence export does not verify.');
            }
        }
        ```
        MD;

    /** @var string The review block, as the guide shows it. */
    private const string REVIEW_BLOCK = <<<'MD'
        <!-- procedure:review -->

        ```php
        use SineMacula\Laravel\AuditLog\Querying\Describer;

        $describer = app(Describer::class);
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

    /** @var string The erasure block, as the guide shows it. */
    private const string ERASE_BLOCK = <<<'MD'
        <!-- procedure:erase -->

        ```php
        use SineMacula\Laravel\AuditLog\Lifecycle\Authority;

        $authority = new Authority(Reference::to($investigator), 'gdpr.article_17', $case);
        $erasure   = AuditLog::lifecycle()->erase($you, $authority);
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

    /** @var string When the subject's card was charged. */
    private const string CHARGED_AT = '2026-11-01T13:00:00.000000Z';

    /** @var string When another person logged the subject's call. */
    private const string CALLED_AT = '2026-11-01T13:00:01.000000Z';

    /** @var string The code a card charge is recorded under, its card sealed under the actor's key. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string The code a support call is recorded under, sealed for two owners. */
    private const string CALL = 'support.call_logged';

    /** @var string The subject's card, spaced so no digest or ciphertext holds it by chance. */
    private const string CARD = '4242 4242 4242 4242';

    /** @var string The subject's phone number, sealed under the subject's key in an entry about someone else. */
    private const string PHONE = '+44 20 7946 0018';

    /** @var string The agent's summary of the call, another owner's fragment in the same entry. */
    private const string SUMMARY = 'Refund agreed after a long call';

    /** @var string The request's reference in the investigator's own records. */
    private const string CASE = 'dpo:case-2026-118';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var ?string The directory the procedure exported to, removed when the test ends. */
    private ?string $directory = null;

    /**
     * Bind the privacy services and read path, alias users, define the events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();

        Relation::morphMap([self::USER => StubAuthUser::class]);

        self::define(
            EventDefinition::for(self::CHARGE)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR),
            EventDefinition::for(self::CALL)->category('support')->retain('caller')->encrypt('phone', 'caller')->encrypt('summary', KeyOwner::ACTOR),
        );
    }

    /**
     * Forget the alias, restore the clock and remove the exports.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);
        CarbonImmutable::setTestNow();

        if ($this->directory !== null) {
            foreach (glob($this->directory . '/*') ?: [] as $file) {
                unlink($file);
            }

            rmdir($this->directory);
        }

        parent::tearDown();
    }

    /**
     * Each block is in the guide exactly as this test holds and runs it.
     *
     * @return void
     */
    public function testTheBlocksAreInTheGuideAsHeldHere(): void
    {
        $guide  = self::read(self::GUIDE);
        $source = self::read('/tests/Feature/Querying/SubjectAccessProcedureTest.php');

        foreach ([self::POLICY_BLOCK, self::SELECT_BLOCK, self::REVIEW_BLOCK, self::ERASE_BLOCK] as $block) {
            self::assertStringContainsString($block, $guide);
        }

        self::assertSame(self::classOf(self::codeOf(self::POLICY_BLOCK)), self::classOf(self::read(self::POLICY_FIXTURE)));

        foreach (['select' => self::SELECT_BLOCK, 'review' => self::REVIEW_BLOCK, 'erase' => self::ERASE_BLOCK] as $method => $block) {
            [$imports, $code] = self::splitImports(self::codeOf($block));

            self::assertSame($code, self::bodyOf($method), sprintf('%s() is not the block\'s code.', $method));

            foreach ($imports as $import) {
                self::assertStringContainsString(str_replace(self::GUIDE_NAMESPACE, self::FIXTURE_NAMESPACE, $import), $source);
            }
        }
    }

    /**
     * The procedure, run as written, selects, exports, copies and erases.
     *
     * @return void
     */
    public function testTheDocumentedProcedureRuns(): void
    {
        [$actedOn, $acted]  = $this->seedTheTrail();
        [$charged, $called] = $this->seedTheFragments();

        [$entries, $exports] = $this->select(self::user(7), self::user(42), $this->directory());

        self::assertSame([$charged, $actedOn, $acted, $called], array_keys($entries));
        self::assertSame(['activity' => 3, 'fragments' => 2], array_map(static fn (ExportResult $export): int => $export->lines, $exports));

        $copy = $this->review(Reference::to(self::user(42)), $entries);

        self::assertSame([
            ['when' => self::CHARGED_AT, 'what' => self::CHARGE, 'outcome' => 'success', 'by_you' => true, 'about_you' => false],
            ['when' => self::ACTED_ON_AT, 'what' => 'invoice.approved', 'outcome' => 'success', 'by_you' => false, 'about_you' => true],
            ['when' => self::SUBJECT_ACTED_AT, 'what' => 'invoice.approved', 'outcome' => 'success', 'by_you' => true, 'about_you' => false],
            ['when' => self::CALLED_AT, 'what' => self::CALL, 'outcome' => 'success', 'by_you' => false, 'about_you' => false],
        ], $copy);

        foreach (['99', self::USER, self::CARD, self::PHONE, self::SUMMARY] as $withheld) {
            self::assertStringNotContainsString($withheld, (string) json_encode($copy));
        }

        [$erasure] = $this->erase(self::user(7), Reference::to(self::user(42)), self::CASE);

        self::assertSame([ErasureStatus::COMPLETE, 2, 0, 2, true], [$erasure->status, $erasure->keysDestroyed, $erasure->keysKept, $erasure->entriesAffected, $erasure->recorded]);
    }

    /**
     * Only `holdingDataOf()` finds the subject's fragment in another's entry.
     *
     * @return void
     */
    public function testOwnedFragmentsAreFoundWithHoldingDataOf(): void
    {
        [$actedOn, $acted]  = $this->seedTheTrail();
        [$charged, $called] = $this->seedTheFragments();

        [$entries, $exports] = $this->select(self::user(7), self::user(42), $this->directory());

        $you = Reference::to(self::user(42));

        self::assertFalse((bool) $entries[$called]->actor?->equals($you));
        self::assertFalse((bool) $entries[$called]->subject?->equals($you));
        self::assertSame([$acted, $actedOn, $charged], self::idsOf($exports['activity']->path));
        self::assertSame([$charged, $called], self::idsOf($exports['fragments']->path));
    }

    /**
     * The grant reveals every encrypted field selected, whoever owns it.
     *
     * @return void
     */
    public function testAnotherOwnersFragmentsAreRevealedForReview(): void
    {
        [$charged, $called] = $this->seedTheFragments();

        [$entries] = $this->select(self::user(7), self::user(42), $this->directory());

        self::assertSame(self::PHONE, $entries[$called]->properties['phone'] ?? null);
        self::assertSame(self::SUMMARY, $entries[$called]->properties['summary'] ?? null);
        self::assertSame(self::CARD, $entries[$charged]->properties['card'] ?? null);

        $copy = (string) json_encode($this->review(Reference::to(self::user(42)), $entries));

        self::assertStringNotContainsString(self::SUMMARY, $copy);
        self::assertStringNotContainsString(self::PHONE, $copy);
    }

    /**
     * After erasure the subject's fragments read erased; others stay revealed.
     *
     * @return void
     */
    public function testTheErasureStepLeavesTheSubjectsFragmentsErased(): void
    {
        [$charged, $called] = $this->seedTheFragments();

        $investigator = self::user(7);

        [, $exports] = $this->select($investigator, self::user(42), $this->directory());

        $this->erase($investigator, Reference::to(self::user(42)), self::CASE);

        $trail   = AuditLog::trail()->visibleTo($investigator);
        $entries = [];

        foreach ($trail->holdingDataOf(Reference::to(self::user(42)))->cursorPaginate(100)->entries as $entry) {
            $entries[$entry->id] = $entry;
        }

        self::assertSame([$called, $charged], array_keys($entries));
        self::assertSame([self::ERASED, self::SUMMARY], [$entries[$called]->properties['phone'] ?? null, $entries[$called]->properties['summary'] ?? null]);
        self::assertSame(self::ERASED, $entries[$charged]->properties['card'] ?? null);

        foreach ($exports as $export) {
            self::assertTrue($trail->verifyExport($export->path)->isVerified());
        }
    }

    /**
     * Running the erasure again is a no-op recorded as `already_erased`.
     *
     * @return void
     */
    public function testRunningTheErasureStepAgainChangesNothing(): void
    {
        $this->seedTheFragments();
        $this->select(self::user(7), self::user(42), $this->directory());

        [$first]  = $this->erase(self::user(7), Reference::to(self::user(42)), self::CASE);
        [$second] = $this->erase(self::user(7), Reference::to(self::user(42)), self::CASE);

        self::assertSame(ErasureStatus::COMPLETE, $first->status);
        self::assertSame([ErasureStatus::ALREADY_ERASED, null, 0, 0], [$second->status, $second->erasureId, $second->keysDestroyed, $second->entriesAffected]);
    }

    /**
     * The evidence export holds what the copy leaves out.
     *
     * @return void
     */
    public function testTheEvidenceExportHoldsWhatTheCopyLeavesOut(): void
    {
        $this->seedTheTrail();

        [, $exports] = $this->select(self::user(7), self::user(42), $this->directory());

        $actors = [];

        foreach (self::linesOf($exports['activity']->path) as $row) {
            $actors[] = [$row['actor_type'] ?? null, $row['actor_id'] ?? null];
        }

        self::assertSame([[self::USER, '42'], [self::USER, '99']], $actors);
        self::assertSame(0, $exports['fragments']->lines);
    }

    /**
     * The evidence exports keep the fragments sealed, whatever the grant.
     *
     * @return void
     */
    public function testTheEvidenceExportsKeepTheFragmentsSealed(): void
    {
        [, $called] = $this->seedTheFragments();

        [, $exports] = $this->select(self::user(7), self::user(42), $this->directory());

        foreach ($exports as $export) {
            $file = file_get_contents($export->path);

            self::assertIsString($file);

            foreach ([self::CARD, self::PHONE, self::SUMMARY] as $plaintext) {
                self::assertStringNotContainsString($plaintext, $file);
            }
        }

        $call = array_values(array_filter(self::linesOf($exports['fragments']->path), static fn (array $row): bool => ($row['id'] ?? null) === $called));

        self::assertCount(1, $call);
        self::assertSame(['c', 'k', 'v'], self::sortedKeys($call[0]['properties']['phone'] ?? null));
        self::assertSame(['c', 'k', 'v'], self::sortedKeys($call[0]['properties']['summary'] ?? null));
    }

    /**
     * An entry with the subject only as principal is not selected.
     *
     * @return void
     */
    public function testPrincipalReferencesAreNotSelected(): void
    {
        [$actedOn, $acted] = $this->seedTheTrail();

        $principal = $this->seedEntry(['actor_id' => '99', 'principal_type' => self::USER, 'principal_id' => '42'], self::PRINCIPAL_AT);

        [$entries] = $this->select(self::user(7), self::user(42), $this->directory());

        self::assertSame([$actedOn, $acted], array_keys($entries));
        self::assertArrayNotHasKey($principal, $entries);
    }

    /**
     * The policy lets no one but the investigator see anything.
     *
     * @return void
     */
    public function testNoOneButTheInvestigatorSeesAnything(): void
    {
        $this->seedTheTrail();
        $this->seedTheFragments();

        [, $exports] = $this->select(self::user(7), self::user(42), $this->directory());

        $other = AuditLog::trail()->visibleTo(self::user(99));

        self::assertSame([], $other->cursorPaginate()->entries);
        self::assertSame([], $other->holdingDataOf(Reference::to(self::user(42)))->cursorPaginate()->entries);
        self::assertSame(0, $other->count());

        foreach ($exports as $export) {
            self::assertContains(ExportFinding::ENTRY_MISSING, $other->verifyExport($export->path)->findings);
        }
    }

    /**
     * Each step of the procedure is recorded under the investigator.
     *
     * @return void
     */
    public function testEachStepOfTheProcedureIsRecordedUnderTheInvestigator(): void
    {
        $this->seedTheTrail();

        $this->select(self::user(7), self::user(42), $this->directory());

        [, $authority] = $this->erase(self::user(7), Reference::to(self::user(42)), self::CASE);

        $records = array_map(static fn (array $record): array => [$record['event'] ?? null, $record['actor_type'] ?? null, $record['actor_id'] ?? null], $this->readRecords());
        $reads   = array_map(static fn (array $record): bool => (self::propertiesOf($record)['reveal'] ?? null) === true, $this->readRecords('audit_log.trail_read'));

        self::assertSame([
            ['audit_log.trail_read', self::USER, '7'],
            ['audit_log.trail_exported', self::USER, '7'],
            ['audit_log.export_verified', self::USER, '7'],
            ['audit_log.trail_read', self::USER, '7'],
            ['audit_log.trail_exported', self::USER, '7'],
            ['audit_log.export_verified', self::USER, '7'],
            ['audit_log.subject_erased', self::USER, '7'],
        ], $records);
        self::assertSame([true, true], $reads);
        $erasures = array_map(static fn (array $record): mixed => self::propertiesOf($record)['authority_reason'] ?? null, $this->readRecords('audit_log.subject_erased'));

        self::assertSame([$authority->reason], $erasures);
    }

    /**
     * Another bound encrypter refuses the fragments selection, naming itself.
     *
     * @return void
     */
    public function testAnotherEncrypterRefusesTheFragmentsSelection(): void
    {
        $this->seedTheTrail();

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(RecordingFieldEncrypter::class);

        $this->select(self::user(7), self::user(42), $this->directory());
    }

    /**
     * The selection block, run as written; hands back its entries and exports.
     *
     * @param  \Tests\Unit\Stubs\StubAuthUser  $investigator
     * @param  \Tests\Unit\Stubs\StubAuthUser  $subject
     * @param  string  $directory
     * @return array{0: array<string, \SineMacula\Laravel\AuditLog\Querying\TrailEntry>, 1: array<string, \SineMacula\Laravel\AuditLog\Querying\ExportResult>}
     *
     * @throws \RuntimeException
     */
    private function select(StubAuthUser $investigator, StubAuthUser $subject, string $directory): array
    {
        $you     = Reference::to($subject);
        $entries = [];
        $exports = [];

        foreach (['activity' => false, 'fragments' => true] as $selection => $fragments) {
            app()->instance(AuditAccessPolicy::class, new SubjectAccessPolicy($investigator, $you, $fragments));

            $trail  = AuditLog::trail()->visibleTo($investigator);
            $trail  = $fragments ? $trail->holdingDataOf($you) : $trail;
            $cursor = null;

            do {
                $page   = $trail->cursorPaginate(100, $cursor);
                $cursor = $page->nextCursor;

                foreach ($page->entries as $entry) {
                    $entries[$entry->id] ??= $entry;
                }
            } while ($cursor !== null);

            $exports[$selection] = $trail->export("{$directory}/{$selection}.ndjson");

            if (!$trail->verifyExport($exports[$selection]->path)->isVerified()) {
                throw new \RuntimeException('The evidence export does not verify.');
            }
        }

        return [$entries, $exports];
    }

    /**
     * The review block, run as written; hands back the copy it made.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $you
     * @param  array<string, \SineMacula\Laravel\AuditLog\Querying\TrailEntry>  $entries
     * @return list<array{when: array<array-key, mixed>|int|string|null, what: string, outcome: string, by_you: bool, about_you: bool}>
     */
    private function review(Reference $you, array $entries): array
    {
        $describer = app(Describer::class);
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
     * The erasure block, run as written; hands back its result and authority.
     *
     * @param  \Tests\Unit\Stubs\StubAuthUser  $investigator
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $you
     * @param  string  $case
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult, 1: \SineMacula\Laravel\AuditLog\Lifecycle\Authority}
     *
     * @throws \Throwable
     */
    private function erase(StubAuthUser $investigator, Reference $you, string $case): array
    {
        $authority = new Authority(Reference::to($investigator), 'gdpr.article_17', $case);
        $erasure   = AuditLog::lifecycle()->erase($you, $authority);

        return [$erasure, $authority];
    }

    /**
     * Seed the trail; return the two entries about the subject, newest first.
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
     * Record the card charge and the support call, and return their ids.
     *
     * @return array{0: string, 1: string}
     */
    private function seedTheFragments(): array
    {
        $subject = Reference::of(self::USER, '42');

        CarbonImmutable::setTestNow(new CarbonImmutable(self::CHARGED_AT));

        $charged = AuditLog::event(self::CHARGE)->by($subject)->withProperties(['amount' => '12.00', 'card' => self::CARD])->record();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::CALLED_AT));

        $called = AuditLog::event(self::CALL)
            ->by(Reference::of(self::USER, '99'))
            ->on(Reference::of('ticket', 't_1001'))
            ->withProperties(['caller' => ['type' => self::USER, 'id' => '42'], 'phone' => self::PHONE, 'summary' => self::SUMMARY])
            ->record();

        CarbonImmutable::setTestNow();

        return [$charged->id, $called->id];
    }

    /**
     * A directory for the exports, removed with its contents after the test.
     *
     * @return string
     */
    private function directory(): string
    {
        $this->directory = sys_get_temp_dir() . '/' . uniqid('audit-subject-access-', true);

        self::assertTrue(mkdir($this->directory, 0700));

        return $this->directory;
    }

    /**
     * Make the definitions the only ones the recorder and container know.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  ...$definitions
     * @return void
     */
    private static function define(EventDefinition ...$definitions): void
    {
        $catalogue = new EventCatalogue;

        foreach ($definitions as $definition) {
            $catalogue->define($definition);
        }

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
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
     * Each line of an NDJSON export, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @return list<array<array-key, mixed>>
     */
    private static function linesOf(string $path): array
    {
        $rows = [];

        foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $row = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($row);

            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * The id of each line of an NDJSON export, in file order.
     *
     * @param  string  $path
     * @return list<?string>
     */
    private static function idsOf(string $path): array
    {
        return array_map(static fn (array $row): ?string => is_string($row['id'] ?? null) ? $row['id'] : null, self::linesOf($path));
    }

    /**
     * The keys of a map, sorted, or the test fails when the value is no map.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return list<array-key>
     */
    private static function sortedKeys(mixed $value): array
    {
        self::assertIsArray($value);

        $keys = array_keys($value);

        sort($keys);

        return $keys;
    }

    /**
     * The code a block's fence holds, without the marker and the fence.
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
     * The `use` lines a block's code opens with, and the code after them.
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
     * A method's body, less its braces and last line, unindented.
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
     * PHP source from its class declaration on, trailing whitespace dropped.
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
