<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsArtifacts;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:verify`: it prints a pinned line for each seal
 * as it is verified, then each finding of the run and the summary, in text or
 * one JSON object a line; the coverage is always printed, and a ranged run says
 * it is not the whole log; the journal's line follows the anchoring, its counts
 * in the JSON summary; a run of the whole log prints the key store's line and
 * holds its member, or says it skipped it for a custom encrypter; it fails
 * non-zero on a tampered, incomplete or unverifiable log, a journal or key
 * finding among them, and, with `--strict` and an anchor, on anything the
 * anchor does not confirm, except a seal awaiting its first anchoring; it
 * refuses a malformed option or range before verifying anything and alarms
 * nothing; and a failure or a stopped run dispatches the event and reports the
 * exception, none of which holds a value of an entry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifyCommand::class)]
final class VerifyCommandTest extends TestCase
{
    use MakesSubjectKeys, SealsEntries, SearchesForSecrets, SeedsArtifacts, WritesTheJournal;

    /** @var string When the log is sealed by the seal command. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When a run verifies, unless a test says otherwise: past the anchoring grace of every seal, and within the allowed age of every entry stored by default. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string When an entry is recorded that is overdue for sealing by the time a run verifies. */
    private const string OVERDUE_AT = '2026-10-30 12:00:00';

    /** @var string The id of a hold the journal places. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The id of the operation that prunes a seal. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The digest a disagreeing anchor holds instead of the local one. */
    private const string OTHER_DIGEST = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var string The summary lines of a valid log of two seals and no anchor, ending with the verdict. */
    private const string VALID_SUMMARY = "Checked seals 1 to 2 of head 2; no anchor is configured.\n"
        . "Integrity: 2 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n"
        . "Anchoring: 0 anchored, 2 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
        . "Journal: 0 rows to sequence none; the latest seal commits to none.\n"
        . "Keys: 0 verified, 0 erased, 0 findings.\n"
        . "Unsealed: 0 pending, 0 overdue.\n"
        . "Verification passed.\n";

    /** @var string What a ranged run says of the whole log. */
    private const string RANGED = 'This run checked a range; it does not establish the integrity of the whole log.';

    /** @var list<string> The integrity status values, in order. */
    private const array INTEGRITY = ['valid', 'pruned', 'incomplete', 'unverifiable', 'tampered'];

    /** @var list<string> The anchoring status values, in order. */
    private const array ANCHORING = ['anchored', 'unanchored', 'unavailable', 'contradicted'];

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The handler every report reaches. */
    private RecordingExceptionHandler $handler;

    /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> Every integrity event dispatched. */
    private \ArrayObject $alarms;

    /** @var string What the last verification printed. */
    private string $printed = '';

    /**
     * Register both commands with the console kernel, which keeps the test
     * independent of the provider, bind no anchor and nothing pruned, and
     * record every report and every integrity event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new SealCommand);
        $kernel->registerCommand(new VerifyCommand);

        $this->handler = new RecordingExceptionHandler;
        $this->alarms  = new \ArrayObject;

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->bindIf(KeyWrapper::class, LocalKeyWrapper::class);
        app()->instance(ExceptionHandler::class, $this->handler);

        $alarms = $this->alarms;

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event);
        });
    }

    /**
     * A valid log passes: each seal is printed in order, then the summary, and
     * nothing is dispatched or reported.
     *
     * @return void
     */
    public function testAValidLogPassesAndPrintsEachSeal(): void
    {
        $seals = $this->sealLog(2);

        self::assertSame(0, $this->verify());
        self::assertSame(
            sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $seals[0]['id'])
            . sprintf("seal 2 %s integrity=valid anchoring=unanchored members=2\n", $seals[1]['id'])
            . self::VALID_SUMMARY,
            $this->printed(),
        );
        self::assertCount(0, $this->alarms);
        self::assertSame([], $this->handler->reports());
    }

    /**
     * Every text line is pinned: a valid seal, a seal with its finding and the
     * first id it was found at, a finding of the run, and the summary.
     *
     * @return void
     */
    public function testTheTextLinesArePinned(): void
    {
        $seals    = $this->sealLog(2);
        $tampered = $this->membersOf((string) $seals[1]['id'])[0];
        $late     = $this->storeEntryAt(self::OVERDUE_AT);

        $this->editEntry($tampered);

        self::assertSame(1, $this->verify());
        self::assertSame(
            sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $seals[0]['id'])
            . sprintf("seal 2 %s integrity=tampered anchoring=unanchored members=2 finding=entry_hmac first=%s\n", $seals[1]['id'], $tampered)
            . sprintf("finding overdue_unsealed integrity=incomplete count=1 first=%s\n", $late)
            . "Checked seals 1 to 2 of head 2; no anchor is configured.\n"
            . "Integrity: 1 valid, 0 pruned, 0 incomplete, 0 unverifiable, 1 tampered.\n"
            . "Anchoring: 0 anchored, 2 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
            . "Journal: 0 rows to sequence none; the latest seal commits to none.\n"
            . "Keys: 0 verified, 0 erased, 0 findings.\n"
            . "Unsealed: 0 pending, 1 overdue.\n"
            . "Verification failed.\n",
            $this->printed(),
        );
    }

    /**
     * Every JSON line decodes to one object: each seal's, then each finding's,
     * and the summary last, each pinned whole.
     *
     * @return void
     */
    public function testTheJsonLinesArePinned(): void
    {
        $seals = $this->sealLog(1);
        $late  = $this->storeEntryAt(self::OVERDUE_AT);

        self::assertSame(1, $this->verify(['--json' => true]));

        $lines = $this->jsonLines();

        self::assertCount(3, $lines);
        self::assertSame([
            'type'            => 'segment',
            'sequence'        => 1,
            'seal_id'         => $seals[0]['id'],
            'integrity'       => 'valid',
            'anchoring'       => 'unanchored',
            'awaiting_anchor' => false,
            'members'         => 2,
            'finding'         => null,
            'first_bad_id'    => null,
        ], $lines[0]);
        self::assertSame(['type' => 'finding', 'finding' => 'overdue_unsealed', 'integrity' => 'incomplete', 'count' => 1, 'first_bad_id' => $late], $lines[1]);
        self::assertSame([
            'type'            => 'summary',
            'from'            => 1,
            'to'              => 1,
            'head'            => 1,
            'remote_head'     => null,
            'remote'          => null,
            'complete'        => true,
            'strict'          => false,
            'integrity'       => self::integrity(['valid' => 1]),
            'anchoring'       => self::anchoring(['unanchored' => 1]),
            'awaiting_anchor' => 0,
            'pending'         => 0,
            'overdue'         => 1,
            'journal'         => ['rows' => 0, 'head' => null, 'committed' => null],
            'keys'            => ['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => false, 'encrypter' => null],
            'first_finding'   => 'overdue_unsealed',
            'first_bad_id'    => $late,
            'passed'          => false,
        ], $lines[2]);
    }

    /**
     * The journal's line follows the anchoring: the rows read, the sequence of
     * the chain's head, and the sequence the latest seal commits to.
     *
     * @return void
     */
    public function testItPrintsTheJournalLine(): void
    {
        $this->journalHold(self::HOLD_ID);
        $this->sealLog(1);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString(
            "Anchoring: 0 anchored, 1 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
            . "Journal: 2 rows to sequence 2; the latest seal commits to 1.\n"
            . "Keys: 0 verified, 0 erased, 0 findings.\n"
            . "Unsealed: 0 pending, 0 overdue.\n",
            $this->printed(),
        );
    }

    /**
     * The JSON summary holds the journal's counts, and so does a ranged run's,
     * since every run verifies the whole journal.
     *
     * @return void
     */
    public function testTheJsonSummaryHoldsTheJournal(): void
    {
        $this->sealLog(1);
        $this->journalHold(self::HOLD_ID);
        $this->sealLog(1);

        foreach ([[], ['--from' => '1', '--to' => '1']] as $options) {
            self::assertSame(0, $this->verify(['--json' => true, ...$options]));

            $lines = $this->jsonLines();

            self::assertSame(['rows' => 1, 'head' => 1, 'committed' => 1], $lines[array_key_last($lines)]['journal'] ?? null);
        }
    }

    /**
     * A journal finding is printed as a finding of the run, fails the run
     * non-zero and alarms with it, a ranged run included.
     *
     * @return void
     */
    public function testAJournalFindingExitsNonZero(): void
    {
        $this->sealLog(1);

        $release = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        self::assertSame(1, $this->verify(['--from' => '1', '--to' => '1']));
        self::assertStringContainsString(sprintf("finding journal_transition integrity=tampered count=1 first=%s\n", $release->id), $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());
        $alarm = $this->singleAlarm();

        self::assertSame('journal_transition', $alarm->finding);
        self::assertSame($release->id, $alarm->firstBadId);
    }

    /**
     * A run of the whole log prints the key store's line after the journal's:
     * the keys verified, those erased and the key findings; a ranged run prints
     * none, and a custom encrypter's run says it skipped the key store, naming
     * the encrypter.
     *
     * @return void
     */
    public function testItPrintsTheKeysLine(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        $this->sealLog(1);
        $this->makeSubjectKey($owner);
        $this->makeSubjectKey(Reference::of('App\Models\User', '43'));
        $this->eraseByHand($owner);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString(
            "Journal: 1 rows to sequence 1; the latest seal commits to none.\n"
            . "Keys: 2 verified, 1 erased, 0 findings.\n"
            . "Unsealed: 0 pending, 0 overdue.\n",
            $this->printed(),
        );

        self::assertSame(0, $this->verify(['--from' => '1', '--to' => '1']));
        self::assertStringNotContainsString('Keys:', $this->printed());

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        self::assertSame(0, $this->verify());
        $skipped = sprintf("Keys: skipped; the bound field encrypter %s does not use the package's key store.\n", RecordingFieldEncrypter::class);

        self::assertStringContainsString($skipped, $this->printed());
    }

    /**
     * A key finding is printed as a finding of the run, counted on the key
     * store's line, fails the run non-zero and alarms with it.
     *
     * @return void
     */
    public function testAKeyFindingExitsNonZero(): void
    {
        $this->sealLog(1);

        [$key] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['wrapped_key' => null]);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf("finding key_destroyed_unjournalled integrity=tampered count=1 first=%s\n", $key->id), $this->printed());
        self::assertStringContainsString("Keys: 1 verified, 1 erased, 1 findings.\n", $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());

        $alarm = $this->singleAlarm();

        self::assertSame('key_destroyed_unjournalled', $alarm->finding);
        self::assertSame($key->id, $alarm->firstBadId);
    }

    /**
     * The JSON summary holds the key store's member: its counts on a run of the
     * whole log, `null` on a ranged run, and the encrypter it was skipped for
     * with a custom one.
     *
     * @return void
     */
    public function testTheJsonHasTheKeysMember(): void
    {
        $this->sealLog(1);
        $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        self::assertSame(0, $this->verify(['--json' => true]));
        self::assertSame(['keys' => 1, 'erased' => 0, 'findings' => 0, 'skipped' => false, 'encrypter' => null], $this->summaryLine()['keys'] ?? null);

        self::assertSame(0, $this->verify(['--json' => true, '--from' => '1']));
        self::assertArrayHasKey('keys', $this->summaryLine());
        self::assertNull($this->summaryLine()['keys']);

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        self::assertSame(0, $this->verify(['--json' => true]));
        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => RecordingFieldEncrypter::class], $this->summaryLine()['keys'] ?? null);
    }

    /**
     * A strict JSON run says so in its summary, with the anchor's head and how
     * it compared.
     *
     * @return void
     */
    public function testTheJsonSummaryOfAStrictRunCarriesTheAnchorsHead(): void
    {
        $this->bindAnchor(new RecordingAnchor);
        $this->sealLog(2);

        self::assertSame(0, $this->verify(['--json' => true, '--strict' => true]));

        $summary = $this->jsonLines()[2] ?? [];

        self::assertSame(['summary', 2, 'anchored'], [$summary['type'] ?? null, $summary['remote_head'] ?? null, $summary['remote'] ?? null]);
        self::assertSame([true, true], [$summary['strict'] ?? null, $summary['passed'] ?? null]);
        self::assertSame(self::anchoring(['anchored' => 2]), $summary['anchoring'] ?? null);
    }

    /**
     * A tampered log fails non-zero, naming the first altered entry in member
     * order, bytewise.
     *
     * @return void
     */
    public function testATamperedLogFailsNonZeroNamingTheFirstBadId(): void
    {
        $seals   = $this->sealLog(1, 3);
        $members = $this->membersOf((string) $seals[0]['id']);

        $this->editEntry($members[2]);
        $this->editEntry($members[1]);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf("integrity=tampered anchoring=unanchored members=3 finding=entry_hmac first=%s\n", $members[1]), $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());
        self::assertSame($members[1], $this->singleAlarm()->firstBadId);
    }

    /**
     * A log holding a bundle whose artifact was deleted after sealing exits
     * non-zero, its seal tampered with `manifest_missing` at the bundle's
     * entry, and alarms once.
     *
     * @return void
     */
    public function testATamperedArtifactExitsNonZero(): void
    {
        $this->storeEntries(1);

        $entryId = $this->seedBundle();

        $this->seal();
        $this->artifactsTable()->where('entry_id', $entryId)->delete();

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf("integrity=tampered anchoring=unanchored members=2 finding=manifest_missing first=%s\n", $entryId), $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());
        $alarm = $this->singleAlarm();

        self::assertSame(self::integrity(['tampered' => 1]), $alarm->integrity);
        self::assertSame('manifest_missing', $alarm->finding);
        self::assertSame($entryId, $alarm->firstBadId);
    }

    /**
     * A log holding two bundles whose artifacts were swapped between their
     * entries after sealing exits non-zero, its seal tampered with
     * `manifest_swapped` at the earlier of the two entries, and alarms once.
     *
     * @return void
     */
    public function testASwappedArtifactExitsNonZero(): void
    {
        $first  = $this->seedBundle();
        $second = $this->seedBundle();

        $this->seal();
        $this->swapArtifacts($first, $second);

        $earlier = min($first, $second);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf("integrity=tampered anchoring=unanchored members=2 finding=manifest_swapped first=%s\n", $earlier), $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());
        $alarm = $this->singleAlarm();

        self::assertSame(self::integrity(['tampered' => 1]), $alarm->integrity);
        self::assertSame('manifest_swapped', $alarm->finding);
        self::assertSame($earlier, $alarm->firstBadId);
    }

    /**
     * A log with an entry missing and no prune record fails as incomplete.
     *
     * @return void
     */
    public function testAnIncompleteLogFails(): void
    {
        $seals   = $this->sealLog(1);
        $members = $this->membersOf((string) $seals[0]['id']);

        $this->entries()->where('id', $members[0])->delete();

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf("integrity=incomplete anchoring=unanchored members=2 finding=missing_entry first=%s\n", $members[0]), $this->printed());
        self::assertStringContainsString("Integrity: 0 valid, 0 pruned, 1 incomplete, 0 unverifiable, 0 tampered.\n", $this->printed());
        self::assertSame(self::integrity(['incomplete' => 1]), $this->singleAlarm()->integrity);
    }

    /**
     * A log with a seal of a signer the package does not know fails as
     * unverifiable, naming the seal.
     *
     * @return void
     */
    public function testAnUnverifiableLogFails(): void
    {
        $seals = $this->sealLog(1);

        $this->checkpoints()->where('sequence', 1)->update(['signer' => 'other']);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf('seal 1 %s integrity=unverifiable anchoring=unanchored', $seals[0]['id']), $this->printed());
        self::assertStringContainsString('finding=seal_version', $this->printed());
        self::assertSame(self::integrity(['unverifiable' => 1]), $this->singleAlarm()->integrity);
    }

    /**
     * A segment whose entries a valid prune record of both its members accounts
     * for is pruned, and the run passes.
     *
     * @return void
     */
    public function testAPrunedSegmentPasses(): void
    {
        $seals = $this->sealLog(1);
        $seal  = $seals[0];

        $this->entries()->whereIn('id', $this->membersOf((string) $seal['id']))->delete();

        $ledger = new InMemoryPruneLedger;

        $digest = (string) $seal['seal_digest'];
        $record = app(SealSigner::class)->signPrune(
            (string) $seal['log_id'],
            (string) $seal['id'],
            $digest,
            2,
            PruneBitmap::encode([0, 1], 2),
            2,
            self::OPERATION_ID,
            '2027-11-01T00:00:00.000000Z',
        );

        $ledger->add($record);

        app()->instance(PruneLedger::class, $ledger);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString(sprintf("seal 1 %s integrity=pruned anchoring=unanchored members=2\n", $seal['id']), $this->printed());
        self::assertStringContainsString("Integrity: 0 valid, 1 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n", $this->printed());
        self::assertCount(0, $this->alarms);
    }

    /**
     * With the null anchor, unanchored is informational: a strict run passes
     * and says no anchor is configured.
     *
     * @return void
     */
    public function testUnanchoredIsInformationalWithTheNullAnchor(): void
    {
        $this->sealLog(2);

        self::assertSame(0, $this->verify(['--strict' => true]));
        self::assertStringEndsWith(self::VALID_SUMMARY, $this->printed());
        self::assertCount(0, $this->alarms);
    }

    /**
     * With an anchor configured, a seal past the grace that the anchor does not
     * hold is unanchored: a run passes, and a strict run fails, alarming with
     * the anchoring counts and no finding.
     *
     * @return void
     */
    public function testStrictFailsOnAnUnanchoredSegmentWhenAnAnchorIsConfigured(): void
    {
        $this->bindAnchor(new RecordingAnchor);
        $this->sealLog(1);
        $this->sealWithoutAnchoring('2026-11-01 13:40:00');

        self::assertSame(0, $this->verify());
        self::assertCount(0, $this->alarms);

        self::assertSame(1, $this->verify(['--strict' => true]));
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; the anchor's head is 1.\n", $this->printed());
        self::assertStringContainsString("Anchoring: 1 anchored, 1 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n", $this->printed());
        self::assertStringEndsWith("Verification failed.\n", $this->printed());

        $alarm = $this->singleAlarm();

        self::assertSame(self::anchoring(['anchored' => 1, 'unanchored' => 1]), $alarm->anchoring);
        self::assertNull($alarm->finding);
        self::assertSame(1, $alarm->remoteHead);
        self::assertReported('The audit log\'s integrity check failed (verify): 0 tampered, 0 incomplete, 0 unverifiable;'
            . ' 1 unanchored, 0 unavailable, 0 contradicted; first finding none at none; head 2.');
    }

    /**
     * An anchor setting that is malformed stops the run, never the command
     * before it: the run prints what stopped it by its class alone, alarms with
     * no finding, reports the stopped run and exits 1, strict or not.
     *
     * @return void
     */
    public function testAMalformedAnchorSettingAlarms(): void
    {
        $this->sealLog(1);

        app()->offsetUnset(CheckpointAnchor::class);
        app()->bind(CheckpointAnchor::class, static fn (): CheckpointAnchor => app(AnchorFactory::class)->make());
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.driver', 'foo');

        self::assertSame(1, $this->verify(['--strict' => true]));
        self::assertSame("Verification stopped with InvalidArgumentException.\n", $this->printed());

        $alarm = $this->singleAlarm();

        self::assertSame([null, false], [$alarm->finding, $alarm->complete]);
        self::assertReported('The audit log\'s verify run stopped with InvalidArgumentException; its integrity was not established.');
    }

    /**
     * A listener that fails is reported as it threw, and hides nothing: the
     * alarm is still reported after it and the run still exits 1.
     *
     * @return void
     */
    public function testAListenerThatFailsIsReported(): void
    {
        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (): void {
            throw new \RuntimeException('The listener failed.');
        });

        $seals = $this->sealLog(1);

        $this->editEntry($this->membersOf((string) $seals[0]['id'])[0]);

        self::assertSame(1, $this->verify());

        $reports = $this->handler->reports();

        self::assertCount(2, $reports);
        self::assertSame('The listener failed.', $reports[0]->getMessage());
        self::assertInstanceOf(IntegrityCheckFailedException::class, $reports[1]);
    }

    /**
     * With `--sweep-first`, an entry inserted late since the last sweep, older
     * than the allowed age, such as a replayed record, is sealed before the run
     * verifies, so it is never found overdue; without it, the same entry is
     * overdue.
     *
     * @return void
     */
    public function testSweepFirstSealsALateEntryBeforeVerifying(): void
    {
        $this->sealLog(1);
        $this->storeEntryAt(self::OVERDUE_AT);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString("Unsealed: 0 pending, 1 overdue.\n", $this->printed());

        $this->alarms->exchangeArray([]);

        self::assertSame(0, $this->verify(['--sweep-first' => true]));
        self::assertStringStartsWith("Sealed 1 entries in 1 seals (sequences 2 to 2).\nThe sweep is complete.\n", $this->printed());
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $this->printed());
        self::assertSame([], $this->alarms->getArrayCopy());
    }

    /**
     * With `--sweep-first` and `--json`, the sweep prints nothing, so every
     * line is still one JSON object, and a sweep that fails makes the run exit
     * 1 even when the log verifies.
     *
     * @return void
     */
    public function testSweepFirstKeepsJsonAndFailsWithTheSweep(): void
    {
        $this->sealLog(1);

        self::assertSame(0, $this->verify(['--sweep-first' => true, '--json' => true]));
        self::assertSame('summary', $this->jsonLines()[count($this->jsonLines()) - 1]['type']);

        $ids = $this->storeEntries(2, '2026-11-01 13:10:00');

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $ids[0])->update(['hmac' => str_repeat('z', 64)]);

        self::assertSame(1, $this->verify(['--sweep-first' => true]));
        self::assertStringContainsString("Skipped 1 entries that cannot be sealed (a malformed id, HMAC or time); they stay unsealed.\n", $this->printed());
        self::assertStringEndsWith("Verification passed.\n", $this->printed());
    }

    /**
     * An anchor that is unavailable makes a run say so and still pass, and a
     * strict run fail.
     *
     * @return void
     */
    public function testStrictFailsOnAnUnavailableAnchor(): void
    {
        $anchor = $this->bindAnchor(new RecordingAnchor);

        $this->sealLog(1);

        $anchor->failing();

        self::assertSame(0, $this->verify());
        self::assertStringContainsString("Checked seals 1 to 1 of head 1; the anchor is unavailable.\n", $this->printed());
        self::assertStringContainsString('anchoring=unavailable', $this->printed());

        self::assertSame(1, $this->verify(['--strict' => true]));
        self::assertSame(self::anchoring(['unavailable' => 1]), $this->singleAlarm()->anchoring);
    }

    /**
     * An anchor that cannot report its head cannot show a truncated tail, so a
     * strict run fails on it even when it confirms every seal, while a run that
     * is not strict passes.
     *
     * @return void
     */
    public function testStrictFailsOnAnAnchorThatCannotDiscover(): void
    {
        $this->bindAnchor(new RecordingAnchor(discovery: false));
        $this->sealLog(1);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString("Checked seals 1 to 1 of head 1; the anchor cannot report its head.\n", $this->printed());
        self::assertStringContainsString('anchoring=anchored', $this->printed());

        self::assertSame(1, $this->verify(['--strict' => true]));
        self::assertCount(1, $this->alarms);
    }

    /**
     * A strict run passes when the anchor confirms every seal and its head is
     * the local head.
     *
     * @return void
     */
    public function testStrictPassesWhenEverySegmentIsAnchored(): void
    {
        $this->bindAnchor(new RecordingAnchor);

        $seals = $this->sealLog(2);

        self::assertSame(0, $this->verify(['--strict' => true]));
        self::assertSame(
            sprintf("seal 1 %s integrity=valid anchoring=anchored members=2\n", $seals[0]['id'])
            . sprintf("seal 2 %s integrity=valid anchoring=anchored members=2\n", $seals[1]['id'])
            . "Checked seals 1 to 2 of head 2; the anchor's head is 2.\n"
            . "Integrity: 2 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n"
            . "Anchoring: 2 anchored, 0 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
            . "Journal: 0 rows to sequence none; the latest seal commits to none.\n"
            . "Keys: 0 verified, 0 erased, 0 findings.\n"
            . "Unsealed: 0 pending, 0 overdue.\n"
            . "Verification passed.\n",
            $this->printed(),
        );
        self::assertCount(0, $this->alarms);
    }

    /**
     * A seal committed a moment before the run, and not anchored yet, awaits
     * its first anchoring: it is printed and counted as such, and a strict run
     * beside it passes.
     *
     * @return void
     */
    public function testStrictPassesBesideASealNotYetAnchored(): void
    {
        $this->bindAnchor(new RecordingAnchor);
        $this->sealLog(1);

        $seal = $this->sealWithoutAnchoring('2026-11-01 13:59:00');

        self::assertSame(0, $this->verify(['--strict' => true]));
        self::assertStringContainsString(sprintf("seal 2 %s integrity=valid anchoring=unanchored members=2 awaiting-anchor\n", $seal['id']), $this->printed());
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; the anchor's head is 1.\n", $this->printed());
        self::assertStringContainsString("Anchoring: 1 anchored, 1 unanchored (1 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n", $this->printed());
        self::assertStringEndsWith("Verification passed.\n", $this->printed());
        self::assertCount(0, $this->alarms);
    }

    /**
     * A seal still unanchored once the grace has passed no longer awaits its
     * anchoring, and a strict run fails on it.
     *
     * @return void
     */
    public function testStrictFailsOnASealUnanchoredPastTheGrace(): void
    {
        $this->bindAnchor(new RecordingAnchor);
        $this->sealLog(1);

        $seal = $this->sealWithoutAnchoring('2026-11-01 13:59:00');

        self::assertSame(1, $this->verify(['--strict' => true], '2026-11-01 14:14:01'));
        self::assertStringContainsString(sprintf("seal 2 %s integrity=valid anchoring=unanchored members=2\n", $seal['id']), $this->printed());
        self::assertStringContainsString('(0 awaiting their first anchoring)', $this->printed());
        self::assertSame(self::anchoring(['anchored' => 1, 'unanchored' => 1]), $this->singleAlarm()->anchoring);
    }

    /**
     * The coverage line is printed on every run that verifies: of an empty log,
     * of the whole log, of a range, and of a run that fails.
     *
     * @return void
     */
    public function testTheCoverageIsAlwaysPrinted(): void
    {
        self::assertSame(0, $this->verify());
        self::assertSame(
            "Checked no seals: the log has none; no anchor is configured.\n"
            . "Integrity: 0 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n"
            . "Anchoring: 0 anchored, 0 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
            . "Journal: 0 rows to sequence none; the latest seal commits to none.\n"
            . "Keys: 0 verified, 0 erased, 0 findings.\n"
            . "Unsealed: 0 pending, 0 overdue.\n"
            . "Verification passed.\n",
            $this->printed(),
        );

        $this->sealLog(3);

        $this->verify();
        self::assertStringContainsString("Checked seals 1 to 3 of head 3; no anchor is configured.\n", $this->printed());

        $this->verify(['--from' => '2']);
        self::assertStringContainsString("Checked seals 2 to 3 of head 3; no anchor is configured.\n", $this->printed());

        $this->verify(['--to' => '2']);
        self::assertStringContainsString("Checked seals 1 to 2 of head 3; no anchor is configured.\n", $this->printed());

        $this->checkpoints()->where('sequence', 3)->update(['signature' => self::OTHER_DIGEST]);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString("Checked seals 1 to 3 of head 3; no anchor is configured.\n", $this->printed());
    }

    /**
     * A ranged run prints only its seals, says it does not establish the
     * integrity of the whole log, and has no unsealed entries to count; a run
     * of the whole log never says so.
     *
     * @return void
     */
    public function testARangedRunSaysItIsNotTheWholeLog(): void
    {
        $seals = $this->sealLog(3);

        self::assertSame(0, $this->verify(['--from' => '2', '--to' => '2']));
        self::assertSame(
            sprintf("seal 2 %s integrity=valid anchoring=unanchored members=2\n", $seals[1]['id'])
            . "Checked seals 2 to 2 of head 3; no anchor is configured.\n"
            . "Integrity: 1 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n"
            . "Anchoring: 0 anchored, 1 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n"
            . "Journal: 0 rows to sequence none; the latest seal commits to none.\n"
            . self::RANGED . "\n"
            . "Verification passed.\n",
            $this->printed(),
        );

        self::assertSame(0, $this->verify());
        self::assertStringNotContainsString(self::RANGED, $this->printed());
    }

    /**
     * A ranged run whose boundary seal fails prints that seal too, and fails.
     *
     * @return void
     */
    public function testARangedRunPrintsABoundaryThatFails(): void
    {
        $seals = $this->sealLog(3);

        $this->checkpoints()->where('sequence', 1)->update(['signature' => self::OTHER_DIGEST]);

        self::assertSame(1, $this->verify(['--from' => '2']));
        $line = sprintf("seal 1 %s integrity=tampered anchoring=unanchored members=0 finding=seal_signature first=%s\n", $seals[0]['id'], $seals[0]['id']);

        self::assertStringStartsWith($line, $this->printed());
        self::assertFalse($this->singleAlarm()->complete);
    }

    /**
     * Rows of `[option, value]`: values of each option that are not a sequence
     * from 1.
     *
     * @return iterable<string, array{0: 'from'|'to', 1: string}>
     */
    public static function provideMalformedOptions(): iterable
    {
        yield from [
            'from zero'        => ['from', '0'],
            'from negative'    => ['from', '-1'],
            'from a word'      => ['from', 'x'],
            'from a fraction'  => ['from', '1.5'],
            'from empty'       => ['from', ''],
            'from padded'      => ['from', '01'],
            'from signed'      => ['from', '+1'],
            'from an overflow' => ['from', '9223372036854775808'],
            'to zero'          => ['to', '0'],
            'to negative'      => ['to', '-1'],
            'to a word'        => ['to', 'x'],
            'to a fraction'    => ['to', '1.5'],
        ];
    }

    /**
     * An option that is not a sequence is refused with `INVALID`, naming the
     * option and its range, before any statement runs, alarming nothing.
     *
     * @param  'from'|'to'  $option
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideMalformedOptions')]
    public function testRefusesAMalformedOption(string $option, string $value): void
    {
        $this->sealLog(1);

        $statements = $this->countStatements();

        self::assertSame(2, $this->verify(['--' . $option => $value]));
        self::assertSame(sprintf("The --%s option must be an integer from 1 to %d.\n", $option, PHP_INT_MAX), $this->printed());
        self::assertCount(0, $statements);
        self::assertCount(0, $this->alarms);
        self::assertSame([], $this->handler->reports());
    }

    /**
     * A first seal after the last is refused with `INVALID`.
     *
     * @return void
     */
    public function testRefusesFromAfterTo(): void
    {
        $this->sealLog(3);

        self::assertSame(2, $this->verify(['--from' => '3', '--to' => '2']));
        self::assertSame("--from must not be after --to.\n", $this->printed());
    }

    /**
     * Rows of `[options, message]`: ranges with an end beyond a head of two
     * seals.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string}>
     */
    public static function provideRangesBeyondTheHead(): iterable
    {
        yield from [
            'the last seal'          => [['--to' => '3'], '--to is beyond the head of the log, seal 2.'],
            'the first seal'         => [['--from' => '3'], '--from is beyond the head of the log, seal 2.'],
            'both, the last checked' => [['--from' => '3', '--to' => '4'], '--to is beyond the head of the log, seal 2.'],
        ];
    }

    /**
     * An end beyond the head the run observed is refused with `INVALID`, naming
     * the option and the head, and nothing is verified.
     *
     * @param  array<string, string>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRangesBeyondTheHead')]
    public function testRefusesARangeBeyondTheHead(array $options, string $message): void
    {
        $this->sealLog(2);

        self::assertSame(2, $this->verify($options));
        self::assertSame($message . "\n", $this->printed());
    }

    /**
     * Any range of a log with no seal is refused with `INVALID`, while the
     * whole of it passes.
     *
     * @return void
     */
    public function testRefusesARangeOfAnEmptyLog(): void
    {
        self::assertSame(2, $this->verify(['--from' => '1']));
        self::assertSame("The log has no seal to verify in a range.\n", $this->printed());

        self::assertSame(0, $this->verify());
    }

    /**
     * A refused range of a log that would fail verifies nothing, prints only
     * why, and dispatches and reports nothing.
     *
     * @return void
     */
    public function testARefusedRangeAlarmsNothing(): void
    {
        $seals = $this->sealLog(2);

        $this->editEntry($this->membersOf((string) $seals[0]['id'])[0]);

        self::assertSame(2, $this->verify(['--to' => '3', '--strict' => true]));
        self::assertSame("--to is beyond the head of the log, seal 2.\n", $this->printed());
        self::assertSame(2, $this->verify(['--from' => '2', '--to' => '1', '--json' => true]));
        self::assertSame("--from must not be after --to.\n", $this->printed());
        self::assertCount(0, $this->alarms);
        self::assertSame([], $this->handler->reports());
    }

    /**
     * A run that stops prints what stopped it by its class alone after the
     * seals already verified, alarms with those counts, no finding and no head,
     * reports the stopped run and exits 1.
     *
     * @return void
     */
    public function testAStoppedRunAlarms(): void
    {
        $seals = $this->sealLog(2);

        $this->raiseOnMemberSelects(new \DomainException('The members cannot be read: ' . self::SECRET), 2);

        self::assertSame(1, $this->verify());
        self::assertSame(
            sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $seals[0]['id'])
            . "Verification stopped with DomainException.\n",
            $this->printed(),
        );

        $alarm = $this->singleAlarm();

        self::assertSame(['verify', self::integrity(['valid' => 1]), self::anchoring(['unanchored' => 1])], [$alarm->command, $alarm->integrity, $alarm->anchoring]);
        self::assertSame([null, null, null, null, false], [$alarm->finding, $alarm->firstBadId, $alarm->head, $alarm->remoteHead, $alarm->complete]);
        self::assertReported('The audit log\'s verify run stopped with DomainException; its integrity was not established.');
    }

    /**
     * A run that stops before any seal is verified alarms with every count at
     * zero, and a failure the configuration raises is a stopped run, never a
     * refused range.
     *
     * @return void
     */
    public function testAFailureBeforeAnySealIsAStoppedRun(): void
    {
        $this->sealLog(1);

        $this->raiseOnMemberSelects(new \InvalidArgumentException('A setting is malformed.'), 1);

        self::assertSame(1, $this->verify(['--from' => '1']));
        self::assertSame("Verification stopped with InvalidArgumentException.\n", $this->printed());

        $alarm = $this->singleAlarm();

        self::assertSame([self::integrity([]), self::anchoring([])], [$alarm->integrity, $alarm->anchoring]);
        self::assertReported('The audit log\'s verify run stopped with InvalidArgumentException; its integrity was not established.');
    }

    /**
     * A failure dispatches one event holding the counts, the first finding and
     * its id, the head and the coverage, and reports the exception built from
     * it, with no previous.
     *
     * @return void
     */
    public function testAFailureDispatchesTheEventAndReportsIt(): void
    {
        $seals    = $this->sealLog(1);
        $tampered = $this->membersOf((string) $seals[0]['id'])[0];

        $this->editEntry($tampered);

        self::assertSame(1, $this->verify());

        $alarm = $this->singleAlarm();

        self::assertSame(['verify', self::integrity(['tampered' => 1]), self::anchoring(['unanchored' => 1])], [$alarm->command, $alarm->integrity, $alarm->anchoring]);
        self::assertSame(['entry_hmac', $tampered, 1, null, true], [$alarm->finding, $alarm->firstBadId, $alarm->head, $alarm->remoteHead, $alarm->complete]);
        self::assertReported('The audit log\'s integrity check failed (verify): 1 tampered, 0 incomplete, 0 unverifiable;'
            . sprintf(' 1 unanchored, 0 unavailable, 0 contradicted; first finding entry_hmac at %s; head 1.', $tampered));
    }

    /**
     * A run that passes dispatches and reports nothing, strict or not.
     *
     * @return void
     */
    public function testThePassingRunDispatchesNothing(): void
    {
        $this->bindAnchor(new RecordingAnchor);
        $this->sealLog(2);

        self::assertSame(0, $this->verify());
        self::assertSame(0, $this->verify(['--strict' => true]));
        self::assertSame(0, $this->verify(['--json' => true, '--strict' => true]));
        self::assertCount(0, $this->alarms);
        self::assertSame([], $this->handler->reports());
    }

    /**
     * An anchor that holds another digest for a seal, found as it reports its
     * head, is a finding of the run: the log is tampered and the run fails.
     *
     * @return void
     */
    public function testAnAnchorInConflictFailsTheRun(): void
    {
        $anchor = $this->bindAnchor(new RecordingAnchor);

        $this->sealLog(1);

        $anchor->failing(AnchorConflictException::forSequence(1));

        self::assertSame(1, $this->verify());
        self::assertStringContainsString("finding anchor_conflict integrity=tampered count=1 first=none\n", $this->printed());
        self::assertStringContainsString("Checked seals 1 to 1 of head 1; the anchor holds another digest for a seal.\n", $this->printed());
        self::assertSame('anchor_conflict', $this->singleAlarm()->finding);
    }

    /**
     * An anchor whose head is beyond the local tail names that head, and the
     * missing tail fails the run.
     *
     * @return void
     */
    public function testAnAnchorsHeadBeyondTheTailIsNamed(): void
    {
        $anchor = $this->bindAnchor(new RecordingAnchor);

        $this->sealLog(1);

        $anchor->holdInstead(5, self::OTHER_DIGEST);

        self::assertSame(1, $this->verify());
        self::assertStringContainsString("finding missing_tail integrity=tampered count=1 first=none\n", $this->printed());
        self::assertStringContainsString("Checked seals 1 to 1 of head 1; the anchor's head is 5.\n", $this->printed());
        self::assertSame(5, $this->singleAlarm()->remoteHead);
    }

    /**
     * An anchor that holds nothing yet, beside a log sealed past the grace,
     * says so.
     *
     * @return void
     */
    public function testAnEmptyAnchorSaysItHoldsNoSeal(): void
    {
        $this->sealLog(1);
        $this->bindAnchor(new RecordingAnchor);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString("Checked seals 1 to 1 of head 1; the anchor holds no seal.\n", $this->printed());
        self::assertSame(1, $this->verify(['--strict' => true]));
    }

    /**
     * Nothing printed, dispatched or reported holds a value of an entry, in
     * text or JSON, across a tampered entry and a stopped run.
     *
     * @return void
     */
    public function testOutputHoldsNoValueOfAnEntry(): void
    {
        $id = $this->storeSecretEntry('2026-11-01 12:00:00');

        $this->storeSecretEntry('2026-11-01 12:00:01');
        $this->seal();

        self::assertTrue(self::holdsText($this->entries()->get()->all(), self::SECRET), 'The secret was not planted.');

        $this->editEntry($id);

        self::assertSame(1, $this->verify());

        $printed = $this->printed();

        self::assertSame(1, $this->verify(['--json' => true]));

        $printed .= $this->printed();

        $this->raiseOnMemberSelects(new \DomainException('Down: ' . self::SECRET), 1);

        self::assertSame(1, $this->verify());
        self::assertHoldsNoSecret($printed . $this->printed(), 'the output');
        self::assertHoldsNoSecret($this->alarms->getArrayCopy(), 'the events');
        self::assertHoldsNoSecret($this->handler->reports(), 'the reports');
        self::assertCount(3, $this->handler->reports());
    }

    /**
     * Each seal's line is written as its seal is verified, before the next
     * seal's members are read.
     *
     * @return void
     */
    public function testEachLineIsWrittenAsItsSegmentIsVerified(): void
    {
        $this->sealLog(3);

        $output = new BufferedOutput;

        /** @var \ArrayObject<int, string> $written */
        $written = new \ArrayObject;

        /** @var \ArrayObject<int, int> $seen */
        $seen = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($output, $written, $seen): void {
            if (!self::readsMembersOfASeal($query)) {
                return;
            }

            $written->append($output->fetch());
            $seen->append(substr_count(implode('', $written->getArrayCopy()), "\n"));
        });

        self::assertSame(0, $this->verify([], self::VERIFIED_AT, $output));
        self::assertSame([0, 1, 2], $seen->getArrayCopy());
    }

    /**
     * An id read from a table that was altered is printed with its control
     * characters stripped and nothing in it read as a style.
     *
     * @return void
     */
    public function testAnAlteredIdIsPrintedAsText(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() === 'pgsql') {
            self::markTestSkipped('PostgreSQL\'s uuid column cannot hold a malformed id.');
        }

        $this->sealLog(1);
        $this->checkpoints()->where('sequence', 1)->update(['id' => "\e[31m<fg=red>x</>"]);

        $shown = '[31m<fg=red>x</>';
        $line  = sprintf("seal 1 %s integrity=unverifiable anchoring=unanchored members=0 finding=seal_malformed first=%s\n", $shown, $shown);

        self::assertSame(1, $this->verify());
        self::assertStringStartsWith($line, $this->printed());

        self::assertSame(1, $this->verify(['--json' => true]));
        self::assertSame("\e[31m<fg=red>x</>", $this->jsonLines()[0]['seal_id'] ?? null);
    }

    /**
     * An id that is not UTF-8, as only SQLite stores, is repaired in a text
     * line and in a JSON line alike, so the run still says what it found.
     *
     * @return void
     */
    public function testAnIdThatIsNotUtf8IsRepaired(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores an id that is not UTF-8.');
        }

        $this->sealLog(1);
        $this->checkpoints()->where('sequence', 1)->update(['id' => "x\xFFy"]);

        self::assertSame(1, $this->verify());
        self::assertStringStartsWith("seal 1 x\u{FFFD}y integrity=unverifiable", $this->printed());

        self::assertSame(1, $this->verify(['--json' => true]));
        self::assertStringStartsWith('{"type":"segment","sequence":1,"seal_id":"x\ufffdy",', $this->printed());
        self::assertStringEndsWith("\"passed\":false}\n", $this->printed());
    }

    /**
     * The command is named `audit-log:verify` and takes `--from`, `--to`,
     * `--json`, `--strict` and `--sweep-first` alone.
     *
     * @return void
     */
    public function testTheSignatureIsPinned(): void
    {
        $command    = new VerifyCommand;
        $definition = $command->getDefinition();

        self::assertSame('audit-log:verify', $command->getName());
        self::assertSame(['from', 'to', 'json', 'strict', 'sweep-first'], array_keys($definition->getOptions()));
        self::assertTrue($definition->getOption('from')->acceptValue());
        self::assertTrue($definition->getOption('to')->acceptValue());
        self::assertFalse($definition->getOption('json')->acceptValue());
        self::assertFalse($definition->getOption('strict')->acceptValue());
        self::assertFalse($definition->getOption('sweep-first')->acceptValue());
        self::assertSame([], $definition->getArguments());
    }

    /**
     * Store and seal the number of seals, each of the number of entries,
     * recorded a minute apart, through the seal command at the time the log is
     * sealed, which anchors each seal when an anchor is bound, and return the
     * stored seals.
     *
     * @param  int  $seals
     * @param  int  $entries
     * @return list<array<string, scalar|null>>
     */
    private function sealLog(int $seals, int $entries = 2): array
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');

        for ($seal = 0; $seal < $seals; $seal++) {
            $this->storeEntries($entries, $first->addMinutes($seal)->format('Y-m-d H:i:s.u'));
            $this->seal();
        }

        return $this->seals();
    }

    /**
     * Store two entries and seal them at the time given without anchoring the
     * seal, as a seal run that has committed and not anchored yet leaves it,
     * and return the new seal.
     *
     * @param  string  $at
     * @return array<string, scalar|null>
     */
    private function sealWithoutAnchoring(string $at): array
    {
        $this->storeEntries(2, '2026-11-01 13:30:00.000000');
        $this->sealAt($at);
        $this->sealAll();

        $seals = $this->seals();

        return $seals[count($seals) - 1];
    }

    /**
     * Run the seal command at the time the log is sealed, and assert it
     * succeeded.
     *
     * @return void
     */
    private function seal(): void
    {
        app()->instance(Clock::class, FrozenClock::at(self::SEALED_AT));

        self::assertSame(0, $this->kernel()->call('audit-log:seal'), 'The log could not be sealed.');
    }

    /**
     * Run the verify command with the options given at the time given, into the
     * output given or the kernel's, and return its exit code.
     *
     * @param  array<string, bool|string>  $options
     * @param  string  $at
     * @param  ?\Symfony\Component\Console\Output\BufferedOutput  $output
     * @return int
     */
    private function verify(array $options = [], string $at = self::VERIFIED_AT, ?BufferedOutput $output = null): int
    {
        app()->instance(Clock::class, FrozenClock::at($at));

        $exit          = $this->kernel()->call('audit-log:verify', $options, $output);
        $this->printed = $output === null ? $this->kernel()->output() : '';

        return $exit;
    }

    /**
     * What the last verification printed, which the kernel gives only once.
     *
     * @return string
     */
    private function printed(): string
    {
        return $this->printed;
    }

    /**
     * Each line the last run printed, decoded from JSON.
     *
     * @return list<array<string, array<string, bool|int|string|null>|bool|int|string|null>>
     */
    private function jsonLines(): array
    {
        $lines = [];

        foreach (explode("\n", rtrim($this->printed(), "\n")) as $line) {
            /** @var array<string, array<string, bool|int|string|null>|bool|int|string|null> $decoded */
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
            $lines[] = $decoded;
        }

        return $lines;
    }

    /**
     * The summary line of the last JSON run, its last line.
     *
     * @return array<string, array<string, bool|int|string|null>|bool|int|string|null>
     */
    private function summaryLine(): array
    {
        $lines = $this->jsonLines();

        return $lines[array_key_last($lines)] ?? [];
    }

    /**
     * The console kernel.
     *
     * @return \Illuminate\Contracts\Console\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel;
    }

    /**
     * Bind the recording anchor every run anchors and verifies with, behind a
     * wrapper that gives it each stored receipt in the order it wrote it, since
     * MySQL's JSON column keeps an object's keys in an order of its own, and
     * return it.
     *
     * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $anchor
     * @return \Tests\Fixtures\Integrity\RecordingAnchor
     */
    private function bindAnchor(RecordingAnchor $anchor): RecordingAnchor
    {
        app()->instance(CheckpointAnchor::class, new class ($anchor) implements CheckpointAnchor {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $anchor
             */
            public function __construct(

                /** The anchor every call reaches. */
                private readonly RecordingAnchor $anchor,
            ) {}

            /**
             * The anchor's name.
             *
             * @return string
             */
            #[\Override]
            public function name(): string
            {
                return $this->anchor->name();
            }

            /**
             * Anchor the summary.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @return array<string, scalar|null>
             *
             * @throws \Throwable
             */
            #[\Override]
            public function anchor(SealSummary $seal): array
            {
                return $this->anchor->anchor($seal);
            }

            /**
             * Whether the anchor confirms the receipt, its sequence and digest
             * given in the order the anchor wrote them.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @param  array<string, scalar|null>  $receipt
             * @return bool
             *
             * @throws \Throwable
             */
            #[\Override]
            public function confirms(SealSummary $seal, array $receipt): bool
            {
                $ordered = array_merge(array_intersect_key(['sequence' => null, 'digest' => null], $receipt), $receipt);

                return $this->anchor->confirms($seal, $ordered);
            }

            /**
             * Whether the anchor can report its head.
             *
             * @return bool
             */
            #[\Override]
            public function supportsDiscovery(): bool
            {
                return $this->anchor->supportsDiscovery();
            }

            /**
             * The anchor's head.
             *
             * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
             *
             * @throws \Throwable
             */
            #[\Override]
            public function latest(): ?AnchoredHead
            {
                return $this->anchor->latest();
            }
        });

        return $anchor;
    }

    /**
     * Change the stored event of the entry, as someone who can write to the
     * database could, so it no longer matches its HMAC.
     *
     * @param  string  $id
     * @return void
     */
    private function editEntry(string $id): void
    {
        $this->entries()->where('id', $id)->update(['event' => 'invoice.voided']);
    }

    /**
     * Raise the failure from the selection of the members of the seal at the
     * position given, counted from one, and of every seal after it.
     *
     * @param  \Throwable  $failure
     * @param  int  $from
     * @return void
     */
    private function raiseOnMemberSelects(#[\SensitiveParameter] \Throwable $failure, int $from): void
    {
        $selects = 0;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($failure, $from, &$selects): void {
            if (!self::readsMembersOfASeal($query)) {
                return;
            }

            if (++$selects >= $from) {
                throw $failure;
            }
        });
    }

    /**
     * Record every statement the storage connection runs from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function countStatements(): \ArrayObject
    {
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($statements): void {
            $statements->append($query);
        });

        return $statements;
    }

    /**
     * Store a record whose properties hold the planted secret, recorded at the
     * time given, and return its id.
     *
     * @param  string  $recordedAt
     * @return string
     */
    private function storeSecretEntry(string $recordedAt): string
    {
        $instant   = (new CarbonImmutable($recordedAt, 'UTC'))->format('Y-m-d\TH:i:s.u\Z');
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured(['note' => self::SECRET], occurredAt: $instant));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }

    /**
     * The one event dispatched.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function singleAlarm(): IntegrityCheckFailed
    {
        self::assertCount(1, $this->alarms);

        $alarm = $this->alarms->getArrayCopy()[0] ?? null;

        self::assertInstanceOf(IntegrityCheckFailed::class, $alarm);

        $this->alarms->exchangeArray([]);

        return $alarm;
    }

    /**
     * Assert that exactly one exception was reported, an
     * `IntegrityCheckFailedException` with the message given and no previous.
     *
     * @param  string  $message
     * @return void
     */
    private function assertReported(string $message): void
    {
        $reports = $this->handler->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(IntegrityCheckFailedException::class, $reports[0]);
        self::assertSame($message, $reports[0]->getMessage());
        self::assertNull($reports[0]->getPrevious());
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * A query of the seals table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }

    /**
     * Whether the statement reads the members of one seal with their entries,
     * as verifying a segment does, and not the unsealed entries or the orphaned
     * members of the whole log.
     *
     * @param  string  $query
     * @return bool
     */
    private static function readsMembersOfASeal(string $query): bool
    {
        return str_starts_with(strtolower($query), 'select')
            && str_contains($query, IntegrityTables::membersTable())
            && str_contains($query, EntrySettings::table())
            && str_contains($query, 'checkpoint_id');
    }

    /**
     * The whole integrity map, the counts given and zero for the rest.
     *
     * @param  array<string, int>  $counts
     * @return array<string, int>
     */
    private static function integrity(array $counts): array
    {
        return array_merge(array_fill_keys(self::INTEGRITY, 0), $counts);
    }

    /**
     * The whole anchoring map, the counts given and zero for the rest.
     *
     * @param  array<string, int>  $counts
     * @return array<string, int>
     */
    private static function anchoring(array $counts): array
    {
        return array_merge(array_fill_keys(self::ANCHORING, 0), $counts);
    }
}
