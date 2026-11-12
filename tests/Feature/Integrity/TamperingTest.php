<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for what `audit-log:verify` finds once the log is altered below
 * the package through raw queries, and the limits it has.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifyCommand::class)]
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class TamperingTest extends TestCase
{
    use TampersWithTheLog;

    /** @var string When the log is sealed. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every command runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string A digest and a signature no seal, entry or member has. */
    private const string OTHER_DIGEST = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var string A seal id no stored seal has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var string The id of a seal inserted by hand. */
    private const string FORGED_SEAL_ID = '01932b4e-9000-7000-8000-00000000f0f0';

    /** @var string The id of an entry inserted by hand. */
    private const string FORGED_ENTRY_ID = '01932b4e-8a40-7000-8000-00000000f0f0';

    /** @var string The id of the operation that prunes a seal. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When a seal is pruned. */
    private const string PRUNED_AT = '2027-11-01T00:00:00.000000Z';

    /** @var string A secret of the first key of an explicit ring. */
    private const string SECRET_2025 = 'audit-log tampering test key 2025 0123456789';

    /** @var string A secret of the second key of an explicit ring. */
    private const string SECRET_2026 = 'audit-log tampering test key 2026 0123456789';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The handler every report reaches. */
    private RecordingExceptionHandler $handler;

    /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> Every integrity event dispatched. */
    private \ArrayObject $alarms;

    /** @var \Tests\Fixtures\Integrity\InMemoryPruneLedger The prune ledger every run reads, which holds no record until a test adds one. */
    private InMemoryPruneLedger $prunes;

    /**
     * Register both commands with no anchor, an empty prune ledger and a
     * stopped clock, and record every report and integrity event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->registerIntegrityCommands();

        $this->handler = new RecordingExceptionHandler;
        $this->alarms  = new \ArrayObject;
        $this->prunes  = new InMemoryPruneLedger;

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, $this->prunes);
        app()->instance(ExceptionHandler::class, $this->handler);
        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $this->sealAt(self::SEALED_AT);

        $alarms = $this->alarms;

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event);
        });
    }

    /**
     * An entry whose stored event is changed no longer matches its HMAC: its
     * seal is tampered, naming it, while the seal before stays valid.
     *
     * @return void
     */
    public function testAModifiedEntryIsTampered(): void
    {
        $seals = $this->sealLog(2);
        $entry = $this->membersOf((string) $seals[1]['id'])[0];

        $this->editEntry($entry, ['event' => 'invoice.voided']);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'valid', 2), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'tampered', 2, 'entry_hmac', $entry), $output);
        self::assertStringEndsWith("Verification failed.\n", $output);
    }

    /**
     * A value nested deep within an entry's properties, changed in the stored
     * JSON, no longer matches the entry's HMAC.
     *
     * @return void
     */
    public function testAModifiedNestedPropertyIsTampered(): void
    {
        $entry = $this->storeEntryWith(['invoice' => ['lines' => [['sku' => 'A-1', 'amount' => '1200.00'], ['sku' => 'B-2', 'amount' => '30.00']]]]);

        $this->sealAll();

        $stored = $this->entries()->where('id', $entry)->value('properties');

        self::assertIsString($stored);

        /** @var array{invoice: array{lines: list<array{sku: string, amount: string}>}} $properties */
        $properties = json_decode($stored, true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('30.00', $properties['invoice']['lines'][1]['amount'], 'The nested property was not stored as planted.');

        $properties['invoice']['lines'][1]['amount'] = '3.00';

        $this->editEntry($entry, ['properties' => json_encode($properties, JSON_THROW_ON_ERROR)]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, $this->sealIdAt(1), 'tampered', 1, 'entry_hmac', $entry), $output);
    }

    /**
     * Rows of `[column]`: the stored times of an entry, each covered by its
     * HMAC to the microsecond.
     *
     * @return iterable<string, array{0: 'occurred_at'|'recorded_at'}>
     */
    public static function provideEntryTimes(): iterable
    {
        yield from [
            'when it occurred' => ['occurred_at'],
            'when recorded'    => ['recorded_at'],
        ];
    }

    /**
     * Either stored time of an entry moved by one microsecond no longer matches
     * its HMAC.
     *
     * @param  'occurred_at'|'recorded_at'  $column
     * @return void
     */
    #[DataProvider('provideEntryTimes')]
    public function testAModifiedMicrosecondIsTampered(string $column): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->storedEntryRecordedAt('2026-11-01T12:00:00.000000Z');

        $this->editEntry($entry, [$column => '2026-11-01 12:00:00.000001']);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 2, 'entry_hmac', $entry), $output);
    }

    /**
     * A sealed entry deleted with no prune record leaves its seal incomplete,
     * naming it, and fails the run.
     *
     * @return void
     */
    public function testADeletedEntryIsIncomplete(): void
    {
        $seals = $this->sealLog(2);
        $entry = $this->membersOf((string) $seals[0]['id'])[1];

        $this->entries()->where('id', $entry)->delete();

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'incomplete', 2, 'missing_entry', $entry), $output);
        self::assertStringContainsString("Integrity: 1 valid, 0 pruned, 1 incomplete, 0 unverifiable, 0 tampered.\n", $output);
    }

    /**
     * A seal row deleted from the middle of the chain leaves a gap where the
     * walk expected it and its member rows orphaned, each tampering.
     *
     * @return void
     */
    public function testADeletedSealIsTampered(): void
    {
        $seals   = $this->sealLog(3);
        $members = $this->membersOf((string) $seals[1]['id']);

        $this->deleteSeal(2, false);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'valid', 2), $output);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'sequence_gap', (string) $seals[2]['id']), $output);
        self::assertStringContainsString(sprintf("finding orphan_member integrity=tampered count=2 first=%s\n", $members[0]), $output);
        self::assertStringContainsString("Checked seals 1 to 3 of head 3; no anchor is configured.\n", $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
    }

    /**
     * Rows of `[column, value, integrity, finding]`: an immutable seal column,
     * a value for it, and what verification finds once it is rewritten.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: 'tampered'|'unverifiable', 3: string}>
     */
    public static function provideRewrittenSealFields(): iterable
    {
        yield from [
            'its id'                => ['id', self::OTHER_ID, 'tampered', 'seal_digest'],
            'its sequence'          => ['sequence', 9, 'tampered', 'seal_digest'],
            'its log id'            => ['log_id', 'another-log', 'tampered', 'seal_digest'],
            'the previous id'       => ['previous_id', self::OTHER_ID, 'tampered', 'seal_digest'],
            'the previous digest'   => ['previous_digest', self::OTHER_DIGEST, 'tampered', 'seal_digest'],
            'its member count'      => ['member_count', 3, 'tampered', 'seal_digest'],
            'its members digest'    => ['members_digest', self::OTHER_DIGEST, 'tampered', 'seal_digest'],
            'its stored digest'     => ['seal_digest', self::OTHER_DIGEST, 'tampered', 'seal_digest'],
            'its first recording'   => ['first_recorded_at', '2026-11-01 11:00:00.000000', 'tampered', 'seal_digest'],
            'its last recording'    => ['last_recorded_at', '2026-11-01 12:30:00.000000', 'tampered', 'seal_digest'],
            'when it was sealed'    => ['sealed_at', '2026-11-01 13:30:00.000000', 'tampered', 'seal_digest'],
            'its key id'            => ['key_id', 'k-other', 'tampered', 'seal_digest'],
            'its signature'         => ['signature', self::OTHER_DIGEST, 'tampered', 'seal_signature'],
            'its signer'            => ['signer', 'ed25519', 'unverifiable', 'seal_version'],
            'its algorithm version' => ['algorithm_version', 2, 'unverifiable', 'seal_version'],
        ];
    }

    /**
     * Each immutable seal column rewritten without the key fails the run at
     * that seal, with the most severe finding the edit raises.
     *
     * @param  string  $column
     * @param  int|string  $value
     * @param  'tampered'|'unverifiable'  $integrity
     * @param  string  $finding
     * @return void
     */
    #[DataProvider('provideRewrittenSealFields')]
    public function testARewrittenSealFieldFails(string $column, int|string $value, string $integrity, string $finding): void
    {
        $seals = $this->sealLog(3);
        $id    = $column === 'id' ? (string) $value : (string) $seals[1]['id'];

        $this->editSeal(2, [$column => $value]);

        [$exit, $output] = $this->verify();

        $line = self::lineOf($output, $id);

        self::assertSame(1, $exit);
        self::assertStringContainsString(sprintf(' integrity=%s anchoring=unanchored ', $integrity), $line);
        self::assertStringEndsWith(sprintf(' finding=%s first=%s', $finding, $id), $line);
        self::assertStringEndsWith("Verification failed.\n", $output);

        if ($integrity !== 'unverifiable') {
            return;
        }

        self::assertStringContainsString(' members=0 ', $line, 'The segment did not stop at its seal.');
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'chain_broken', (string) $seals[2]['id']), $output);
    }

    /**
     * An entry's HMAC rewritten in its row no longer matches the HMAC its
     * member row recorded when it was sealed.
     *
     * @return void
     */
    public function testARewrittenMemberHmacIsTampered(): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->membersOf((string) $seals[0]['id'])[0];

        $this->editEntry($entry, ['hmac' => self::OTHER_DIGEST]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 2, 'member_hmac', $entry), $output);
    }

    /**
     * The HMAC a member row recorded, rewritten, no longer gives the members
     * digest the seal signed, which outranks the member's own mismatch.
     *
     * @return void
     */
    public function testARewrittenMemberRowBreaksTheMembersDigest(): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->membersOf((string) $seals[0]['id'])[0];

        DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->where('entry_id', $entry)->update(['hmac' => self::OTHER_DIGEST]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 2, 'members_digest', (string) $seals[0]['id']), $output);
    }

    /**
     * An entry deleted with its member row and the seal rewritten to match
     * still fails both seals' signatures without the key.
     *
     * @return void
     */
    public function testAJointSealAndMemberRewriteWithoutTheKeyIsTampered(): void
    {
        $seals  = $this->sealLog(3);
        $digest = $this->dropFromSeal(2, false);

        $this->rewriteSeal(3, ['previous_digest' => $digest]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'valid', 2), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'tampered', 1, 'seal_signature', (string) $seals[1]['id']), $output);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'seal_signature', (string) $seals[2]['id']), $output);
        self::assertSame(['seal_signature', (string) $seals[1]['id']], $this->verifyAlarmNames());
    }

    /**
     * The same rewrite made and signed with the key verifies on its own, and
     * breaks the link the next seal holds to the digest it replaced.
     *
     * @return void
     */
    public function testAJointRewriteWithTheKeyBreaksTheChainToTheNextSeal(): void
    {
        $seals = $this->sealLog(3);

        $this->dropFromSeal(2, true);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'valid', 1), $output);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'chain_broken', (string) $seals[2]['id']), $output);
        self::assertSame(['chain_broken', (string) $seals[2]['id']], $this->verifyAlarmNames());
    }

    /**
     * A chain forged with the key is caught by an anchor holding the seals:
     * their receipts no longer confirm and its head contradicts the forgery.
     *
     * @return void
     */
    public function testAForgedChainWithTheKeyIsCaughtByTheAnchor(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->forgeChainFrom(2);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'valid', 2, anchoring: 'anchored'), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'valid', 1), $output);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'anchor_contradiction', (string) $seals[2]['id'], 'contradicted'), $output);
        self::assertStringContainsString("Checked seals 1 to 3 of head 3; the anchor's head is 3.\n", $output);
        self::assertSame(['anchor_contradiction', (string) $seals[2]['id']], $this->verifyAlarmNames());
    }

    /**
     * A forged chain cannot be anchored over the one held: with every receipt
     * cleared, the next seal run finds a conflict, alarms and fails.
     *
     * @return void
     */
    public function testAForgedChainCannotBeAnchoredOverTheOneHeld(): void
    {
        $this->useDiskAnchor();
        $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->forgeChainFrom(2);
        $this->clearReceipts();

        [$exit, $output] = $this->runSeal();

        self::assertSame(1, $exit);
        self::assertStringContainsString('The anchor holds another digest for seal 2; the local log or the anchor has been altered.', $output);
        self::assertSame(['anchor_conflict', 1, 1], $this->sealAlarmCounts());
    }

    /**
     * The limit the threat model states, pinned: with no anchor, a chain forged
     * with the key, from a rewritten seal to the head, verifies.
     *
     * @return void
     */
    public function testAForgedChainWithTheKeyAndNoAnchorVerifies(): void
    {
        $seals = $this->sealLog(3);

        $this->forgeChainFrom(2);

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'valid', 1), $output);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'valid', 2), $output);
        self::assertStringContainsString("Integrity: 3 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n", $output);
        self::assertStringEndsWith("Verification passed.\n", $output);
    }

    /**
     * A member swapped with one of another seal keeps both counts and every
     * entry sealed once, and breaks both members digests.
     *
     * @return void
     */
    public function testMembersSwappedBetweenSealsAreTampered(): void
    {
        $seals = $this->sealLog(2);

        $this->swapMembers(1, 2);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);

        foreach ([0, 1] as $index) {
            $id = (string) $seals[$index]['id'];

            self::assertStringContainsString(self::line($index + 1, $id, 'tampered', 2, 'members_digest', $id), $output);
        }
    }

    /**
     * Two seals whose sequences are swapped each fail their digest, since the
     * sequence is part of the envelope.
     *
     * @return void
     */
    public function testSwappedSequencesAreTampered(): void
    {
        $seals = $this->sealLog(2);

        $this->editSeal(2, ['sequence' => 3]);
        $this->editSeal(1, ['sequence' => 2]);
        $this->editSeal(3, ['sequence' => 1]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[1]['id'], 'tampered', 2, 'seal_digest', (string) $seals[1]['id']), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[0]['id'], 'tampered', 2, 'seal_digest', (string) $seals[0]['id']), $output);
    }

    /**
     * An entry added to a seal's member rows, with its own HMAC, makes the seal
     * hold more members than it counts.
     *
     * @return void
     */
    public function testAMemberAddedToASealIsTampered(): void
    {
        $seals = $this->sealLog(1);
        $extra = $this->storeEntries(1, '2026-11-01 12:30:00.000000')[0];

        $this->addMember(1, $extra);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 3, 'member_count', (string) $seals[0]['id']), $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
    }

    /**
     * A member row naming a seal that does not exist, which would otherwise
     * pass its entry off as sealed, is a finding of the run.
     *
     * @return void
     */
    public function testAnOrphanedMemberIsTampered(): void
    {
        $this->sealLog(1);

        $entry = $this->storeEntries(1, '2026-11-01 12:30:00.000000')[0];

        $this->tamperedTable(IntegrityTables::membersTable())->insert(['checkpoint_id' => self::OTHER_ID, 'entry_id' => $entry, 'hmac' => self::OTHER_DIGEST]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(sprintf("finding orphan_member integrity=tampered count=1 first=%s\n", $entry), $output);
        self::assertSame(['orphan_member', $entry], $this->verifyAlarmNames());
    }

    /**
     * A receipt copied from another seal changes nothing, since the anchor's
     * head says which seals it holds, and a strict run passes.
     *
     * @return void
     */
    public function testAReplayedReceiptChangesNothing(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(2);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $receipt = $this->checkpoints()->where('sequence', 1)->value('anchor_receipt');

        $this->editSeal(2, ['anchor_receipt' => is_string($receipt) ? $receipt : null]);

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'valid', 2, anchoring: 'anchored'), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'valid', 2, anchoring: 'anchored'), $output);

        [$strict] = $this->verify(['--strict' => true]);

        self::assertSame(0, $strict);
    }

    /**
     * A tail truncated, with every local receipt cleared as well, is still
     * found: the anchor's head, asked for on its own, is beyond the local log.
     *
     * @return void
     */
    public function testTailTruncationWithLocalReceiptsClearedIsTampered(): void
    {
        $this->useDiskAnchor();
        $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->deleteSeal(3, true);
        $this->clearReceipts();

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString("finding missing_tail integrity=tampered count=1 first=none\n", $output);
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; the anchor's head is 3.\n", $output);

        $alarm = $this->verifyAlarm();

        self::assertSame(['missing_tail', 2, 3], [$alarm->finding, $alarm->head, $alarm->remoteHead]);
    }

    /**
     * A log emptied of every seal, member and entry, beside an anchor that
     * holds its head, is tampered.
     *
     * @return void
     */
    public function testAnEmptyLocalLogWithARemoteHeadIsTampered(): void
    {
        $this->useDiskAnchor();
        $this->sealLog(2);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->deleteSeal(2, true);
        $this->deleteSeal(1, true);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(0, $this->entries()->count());
        self::assertStringStartsWith("finding missing_tail integrity=tampered count=1 first=none\n", $output);
        self::assertStringContainsString("Checked no seals: the log has none; the anchor's head is 2.\n", $output);
    }

    /**
     * The head seal rewritten and signed with the key no longer has the digest
     * the anchor holds, so its anchoring is contradicted.
     *
     * @return void
     */
    public function testARewrittenDigestAtTheRemoteHeadIsContradicted(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(2);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->forgeSeal(2, ['sealed_at' => '2026-11-01 13:30:00.000000']);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'tampered', 2, 'anchor_contradiction', (string) $seals[1]['id'], 'contradicted'), $output);
        self::assertStringContainsString("Anchoring: 1 anchored, 0 unanchored (0 awaiting their first anchoring), 0 unavailable, 1 contradicted.\n", $output);
    }

    /**
     * The limit the threat model states, pinned: an entry deleted before any
     * seal holds it leaves no trace, and the run passes.
     *
     * @return void
     */
    public function testAPreSealDeletionIsUndetectable(): void
    {
        $this->sealLog(1);

        $ids = $this->storeEntries(2, '2026-11-01 12:30:00.000000');

        $this->entries()->where('id', $ids[0])->delete();
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertSame([$ids[1]], $this->membersOf($this->sealIdAt(2)));
        self::assertStringContainsString(self::line(2, $this->sealIdAt(2), 'valid', 1), $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
        self::assertStringEndsWith("Verification passed.\n", $output);
    }

    /**
     * A first seal that claims a predecessor is tampered, even signed with the
     * key, since nothing comes before the genesis.
     *
     * @return void
     */
    public function testAGenesisWithAPreviousDigestIsTampered(): void
    {
        $seals = $this->sealLog(2);

        $this->forgeSeal(1, ['previous_digest' => self::OTHER_DIGEST]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 2, 'genesis', (string) $seals[0]['id']), $output);
    }

    /**
     * Editing the anchor columns, which are no part of a seal, changes nothing,
     * since the anchor's head settles which seals it holds.
     *
     * @return void
     */
    public function testEditingTheAnchorColumnsChangesNothing(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $this->editSeal(1, ['anchor_receipt' => json_encode(['path' => self::ANCHOR_PATH . '/elsewhere.json', 'sha256' => self::OTHER_DIGEST], JSON_THROW_ON_ERROR)]);
        $this->editSeal(2, ['anchor' => 'disk:0000000000000000']);
        $this->editSeal(3, ['anchor' => null, 'anchor_receipt' => null, 'anchored_at' => null, 'anchor_error_class' => \RuntimeException::class]);

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);

        foreach ($seals as $index => $seal) {
            self::assertStringContainsString(self::line($index + 1, (string) $seal['id'], 'valid', 2, anchoring: 'anchored'), $output);
        }

        self::assertStringContainsString("Checked seals 1 to 3 of head 3; the anchor's head is 3.\n", $output);
        self::assertStringContainsString("Anchoring: 3 anchored, 0 unanchored (0 awaiting their first anchoring), 0 unavailable, 0 contradicted.\n", $output);

        [$strict] = $this->verify(['--strict' => true]);

        self::assertSame(0, $strict);
    }

    /**
     * A prune record of a seal whose entries are gone, with a signature that is
     * not the key's, is tampering, never pruning.
     *
     * @return void
     */
    public function testAForgedPruneRecordIsTampered(): void
    {
        $seals = $this->sealLog(1);
        $seal  = $seals[0];

        $this->pruneSeal($seal, forged: true);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seal['id'], 'tampered', 2, 'prune_record', (string) $seal['id']), $output);
    }

    /**
     * A seal whose entries are gone under a valid prune record of exactly that
     * seal is pruned, and the run passes.
     *
     * @return void
     */
    public function testAValidPruneRecordReportsPruned(): void
    {
        $seals = $this->sealLog(1);

        $this->pruneSeal($seals[0], forged: false);

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'pruned', 2), $output);
        self::assertStringContainsString("Integrity: 0 valid, 1 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n", $output);
    }

    /**
     * A pruned entry inserted again as it was is `resurrected`, which is
     * incomplete and fails the run.
     *
     * @return void
     */
    public function testAResurrectedPrunedRowIsIncomplete(): void
    {
        $seals   = $this->sealLog(2);
        $members = $this->membersOf((string) $seals[0]['id']);
        $kept    = (array) $this->entries()->where('id', $members[1])->first();

        $this->pruneSeal($seals[0], forged: false);
        $this->entries()->insert($kept);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'incomplete', 2, 'resurrected', $members[1]), $output);
        self::assertStringContainsString("Integrity: 1 valid, 0 pruned, 1 incomplete, 0 unverifiable, 0 tampered.\n", $output);
    }

    /**
     * A valid prune record never excuses a seal whose signature fails.
     *
     * @return void
     */
    public function testPruningNeverExcusesABadSignature(): void
    {
        $seals = $this->sealLog(1);

        $this->pruneSeal($seals[0], forged: false);
        $this->editSeal(1, ['signature' => self::OTHER_DIGEST]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 2, 'seal_signature', (string) $seals[0]['id']), $output);
    }

    /**
     * The first seal deleted with its member rows and entries leaves nothing to
     * link to, and is still found: the walk expects sequence 1 and finds 2.
     *
     * @return void
     */
    public function testADeletedGenesisSealIsTampered(): void
    {
        $seals = $this->sealLog(2);

        $this->deleteSeal(1, true);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringStartsWith(self::line(2, (string) $seals[1]['id'], 'tampered', 2, 'sequence_gap', (string) $seals[1]['id']), $output);
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; no anchor is configured.\n", $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
    }

    /**
     * The threat model's limit: with no anchor, the last seal deleted with its
     * members and entries leaves a shorter log that verifies.
     *
     * @return void
     */
    public function testTailTruncationWithoutAnAnchorIsUndetectable(): void
    {
        $this->sealLog(3);

        $this->deleteSeal(3, true);

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; no anchor is configured.\n", $output);
        self::assertStringContainsString("Integrity: 2 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n", $output);
        self::assertStringEndsWith("Verification passed.\n", $output);
    }

    /**
     * A seal inserted at the head without the key may be chained onto but is
     * never anchored, alarming each run, and verification reports it.
     *
     * @return void
     */
    public function testAForgedHeadWithoutTheKeyIsNeverAnchored(): void
    {
        $this->useDiskAnchor();
        $this->sealLog(1);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $forged = $this->insertForgedHead($this->storeEntries(1, '2026-11-01 12:30:00.000000')[0]);

        $this->storeEntries(1, '2026-11-01 12:31:00.000000');

        foreach ([1, 2] as $run) {
            [$exit, $output] = $this->runSeal();

            self::assertSame(1, $exit, "Seal run {$run} did not fail.");
            self::assertStringContainsString('Seal 2 does not verify (seal_signature), so it is not anchored; run audit-log:verify.', $output);
            self::assertSame(['seal_signature', 1, 0], $this->sealAlarmCounts(), "Seal run {$run} did not alarm.");
        }

        $seals = $this->seals();

        self::assertSame([$forged, $forged], [$seals[1]['id'], $seals[2]['previous_id']]);
        self::assertSame([1], $this->anchoredSequences());

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(2, $forged, 'tampered', 1, 'seal_signature', $forged), $output);
        self::assertSame(sprintf('seal 3 %s integrity=valid anchoring=unanchored members=1 awaiting-anchor', $seals[2]['id']), self::lineOf($output, (string) $seals[2]['id']));
        self::assertStringContainsString("Checked seals 1 to 3 of head 3; the anchor's head is 1.\n", $output);
    }

    /**
     * An entry whose member row is deleted is sealed again by the next sweep in
     * a valid seal, while the seal it was taken from is tampered.
     *
     * @return void
     */
    public function testADeletedMemberRowResealedElsewhereIsTampered(): void
    {
        $seals = $this->sealLog(2);
        $entry = $this->membersOf((string) $seals[0]['id'])[0];

        $this->deleteMember($entry);

        self::assertSame(1, $this->sealAll()->seals());
        self::assertSame([$entry], $this->membersOf($this->sealIdAt(3)));

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', 1, 'member_count', (string) $seals[0]['id']), $output);
        self::assertStringContainsString(self::line(3, $this->sealIdAt(3), 'valid', 1), $output);
    }

    /**
     * A row inserted with a made-up HMAC is sealed like any other, since
     * sealing never checks a row's HMAC, and verification reports it.
     *
     * @return void
     */
    public function testAnInsertedEntryWithoutTheKeyIsSealedThenTampered(): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->copyEntry($this->membersOf((string) $seals[0]['id'])[0], [
            'id'          => self::FORGED_ENTRY_ID,
            'event'       => 'invoice.refunded',
            'recorded_at' => '2026-11-01 12:30:00.000000',
            'hmac'        => self::OTHER_DIGEST,
        ]);

        self::assertSame(1, $this->sealAll()->seals());
        self::assertSame([$entry], $this->membersOf($this->sealIdAt(2)));

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(2, $this->sealIdAt(2), 'tampered', 1, 'entry_hmac', $entry), $output);
    }

    /**
     * A seal copied to sequence 0 to tie a fabricated entry to is found by a
     * whole-log run, its member row an orphan, and never anchored.
     *
     * @return void
     */
    public function testAPhantomSealAtSequenceZeroIsFound(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(2);

        [$anchored] = $this->runSeal();

        self::assertSame(0, $anchored, 'The log could not be anchored.');

        $entry   = $this->copyEntry($this->membersOf((string) $seals[0]['id'])[0], ['id' => self::FORGED_ENTRY_ID, 'event' => 'invoice.refunded', 'hmac' => self::OTHER_DIGEST]);
        $phantom = ['id' => self::OTHER_ID, 'sequence' => 0] + $this->checkpoints()->where('sequence', 1)->get()->map(static fn (object $row): array => (array) $row)->all()[0];

        $this->checkpoints()->insert($phantom);
        $this->tamperedTable(IntegrityTables::membersTable())->insert(['checkpoint_id' => self::OTHER_ID, 'entry_id' => $entry, 'hmac' => self::OTHER_DIGEST]);

        foreach ([[], ['--strict' => true]] as $options) {
            [$exit, $output] = $this->verify($options);

            self::assertSame(1, $exit);
            self::assertStringContainsString(sprintf("finding sequence_gap integrity=tampered count=1 first=%s\n", self::OTHER_ID), $output);
            self::assertStringContainsString(sprintf("finding orphan_member integrity=tampered count=1 first=%s\n", $entry), $output);
            self::assertStringContainsString('Checked seals 1 to 2 of head 2;', $output);
        }

        [$sealed, $printed] = $this->runSeal();

        self::assertSame(1, $sealed);
        self::assertStringContainsString('Seal 0 does not verify (seal_malformed), so it is not anchored; run audit-log:verify.', $printed);
    }

    /**
     * An entry recorded far ahead of the clock, which no seal takes, is a
     * finding of every run of the whole log, never pending for good.
     *
     * @return void
     */
    public function testAFarFutureEntryIsNeverPendingForGood(): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->copyEntry($this->membersOf((string) $seals[0]['id'])[0], [
            'id'          => self::FORGED_ENTRY_ID,
            'event'       => 'invoice.refunded',
            'recorded_at' => '2099-01-01 00:00:00.000000',
            'hmac'        => self::OTHER_DIGEST,
        ]);

        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(sprintf("finding future_unsealed integrity=incomplete count=1 first=%s\n", $entry), $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
        self::assertSame(['future_unsealed', $entry], $this->verifyAlarmNames());
    }

    /**
     * Deleting the last seals of a range is a gap of a ranged run, which
     * reports only the seals it read and fails.
     *
     * @return void
     */
    public function testADeletedSealAtTheEndOfARangeIsAGap(): void
    {
        $seals = $this->sealLog(5);

        $this->deleteSeal(3, true);

        [$exit, $output] = $this->verify(['--from' => '2', '--to' => '3']);

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'valid', 2), $output);
        self::assertStringContainsString("finding sequence_gap integrity=tampered count=1 first=none\n", $output);
        self::assertStringEndsWith("Verification failed.\n", $output);

        $this->deleteSeal(4, true);

        [$empty, $printed] = $this->verify(['--from' => '3', '--to' => '4']);

        self::assertSame(1, $empty);
        self::assertStringContainsString("finding sequence_gap integrity=tampered count=1 first=none\n", $printed);
    }

    /**
     * Marking a seal unreadable after deleting its segment still leaves it
     * tampered by the next link; at the anchor's head it is contradicted.
     *
     * @return void
     */
    public function testMarkingASealUnreadableNeverHidesItsDeletedSegment(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $id = (string) $seals[1]['id'];

        $this->tamperedTable(EntrySettings::table())->whereIn('id', $this->membersOf($id))->delete();
        $this->tamperedTable(IntegrityTables::membersTable())->where('checkpoint_id', $id)->delete();
        $this->editSeal(2, ['algorithm_version' => 2]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(3, (string) $seals[2]['id'], 'tampered', 2, 'chain_broken', (string) $seals[2]['id'], 'anchored'), $output);

        $this->editSeal(3, ['algorithm_version' => 2, 'seal_digest' => self::OTHER_DIGEST]);

        [$head, $printed] = $this->verify();

        self::assertSame(1, $head);
        self::assertStringContainsString(sprintf("finding anchor_contradiction integrity=tampered count=1 first=%s\n", (string) $seals[2]['id']), $printed);
    }

    /**
     * Seals made under keys rotated between them verify, each under the key it
     * names, while both keys stay in the ring.
     *
     * @return void
     */
    public function testKeyRotationBetweenSealsVerifies(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025], 'k2025');
        $this->storeEntries(2);
        $this->sealAll();
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');
        $this->storeEntries(2, '2026-11-01 12:30:00.000000');
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit);
        self::assertSame(['k2025', 'k2026'], array_column($this->seals(), 'key_id'));
        self::assertStringContainsString("Integrity: 2 valid, 0 pruned, 0 incomplete, 0 unverifiable, 0 tampered.\n", $output);
    }

    /**
     * A seal under a key removed from the ring is unverifiable and fails the
     * run, while the next seal verifies and links to it.
     *
     * @return void
     */
    public function testASealUnderARemovedKeyIsUnverifiable(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025], 'k2025');
        $this->storeEntries(2);
        $this->sealAll();
        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');
        $this->storeEntries(2, '2026-11-01 12:30:00.000000');
        $this->sealAll();

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, $this->sealIdAt(1), 'unverifiable', 2, 'seal_key', $this->sealIdAt(1)), $output);
        self::assertStringContainsString(self::line(2, $this->sealIdAt(2), 'valid', 2), $output);
    }

    /**
     * Rows of `[tamper]`: each alteration that fails a run of three seals of
     * two entries, returning the first finding and the id it names.
     *
     * @return iterable<string, array{0: \Closure(self): array{0: string, 1: ?string}}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'a modified entry' => [static function (self $test): array {
                $entry = $test->membersOf($test->sealIdAt(2))[1];

                $test->editEntry($entry, ['event' => 'invoice.voided']);

                return ['entry_hmac', $entry];
            }],
            'a deleted entry' => [static function (self $test): array {
                $entry = $test->membersOf($test->sealIdAt(3))[0];

                $test->entries()->where('id', $entry)->delete();

                return ['missing_entry', $entry];
            }],
            'a deleted seal' => [static function (self $test): array {
                $test->deleteSeal(2, false);

                return ['sequence_gap', $test->sealIdAt(3)];
            }],
            'a deleted genesis' => [static function (self $test): array {
                $test->deleteSeal(1, true);

                return ['sequence_gap', $test->sealIdAt(2)];
            }],
            'a rewritten seal field' => [static function (self $test): array {
                $test->editSeal(2, ['sealed_at' => '2026-11-01 13:30:00.000000']);

                return ['seal_digest', $test->sealIdAt(2)];
            }],
            'a rewritten signature' => [static function (self $test): array {
                $test->editSeal(3, ['signature' => self::OTHER_DIGEST]);

                return ['seal_signature', $test->sealIdAt(3)];
            }],
            'an unknown signer' => [static function (self $test): array {
                $test->editSeal(2, ['signer' => 'ed25519']);

                return ['chain_broken', $test->sealIdAt(3)];
            }],
            'a rewritten member hmac' => [static function (self $test): array {
                $entry = $test->membersOf($test->sealIdAt(1))[0];

                $test->editEntry($entry, ['hmac' => self::OTHER_DIGEST]);

                return ['member_hmac', $entry];
            }],
            'a joint rewrite without the key' => [static function (self $test): array {
                $test->dropFromSeal(2, false);

                return ['seal_signature', $test->sealIdAt(2)];
            }],
            'a joint rewrite with the key' => [static function (self $test): array {
                $test->dropFromSeal(2, true);

                return ['chain_broken', $test->sealIdAt(3)];
            }],
            'a genesis with a predecessor' => [static function (self $test): array {
                $test->forgeSeal(1, ['previous_id' => self::OTHER_ID]);

                return ['genesis', $test->sealIdAt(1)];
            }],
            'swapped members' => [static function (self $test): array {
                $test->swapMembers(2, 3);

                return ['members_digest', $test->sealIdAt(2)];
            }],
            'an added member' => [static function (self $test): array {
                $test->addMember(3, $test->storeEntries(1, '2026-11-01 12:30:00.000000')[0]);

                return ['member_count', $test->sealIdAt(3)];
            }],
            'a member moved out of its seal' => [static function (self $test): array {
                $entry = $test->membersOf($test->sealIdAt(1))[0];

                $test->tamperedTable(IntegrityTables::membersTable())->where('entry_id', $entry)->update(['checkpoint_id' => self::OTHER_ID]);

                return ['member_count', $test->sealIdAt(1)];
            }],
            'an orphaned member' => [static function (self $test): array {
                $entry = $test->storeEntries(1, '2026-11-01 12:30:00.000000')[0];

                $test->tamperedTable(IntegrityTables::membersTable())->insert(['checkpoint_id' => self::OTHER_ID, 'entry_id' => $entry, 'hmac' => self::OTHER_DIGEST]);

                return ['orphan_member', $entry];
            }],
            'a member resealed elsewhere' => [static function (self $test): array {
                $test->deleteMember($test->membersOf($test->sealIdAt(2))[1]);
                $test->sealAll();

                return ['member_count', $test->sealIdAt(2)];
            }],
            'an inserted entry' => [static function (self $test): array {
                $test->copyEntry($test->membersOf($test->sealIdAt(1))[0], ['id' => self::FORGED_ENTRY_ID, 'hmac' => self::OTHER_DIGEST]);
                $test->sealAll();

                return ['entry_hmac', self::FORGED_ENTRY_ID];
            }],
            'a forged prune record' => [static function (self $test): array {
                $test->pruneSeal($test->seals()[0], forged: true);

                return ['prune_record', $test->sealIdAt(1)];
            }],
            'a forged head'    => [static fn (self $test): array => ['seal_signature', $test->insertForgedHead($test->storeEntries(1, '2026-11-01 12:30:00.000000')[0])]],
            'a truncated tail' => [static function (self $test): array {
                $test->useDiskAnchor();
                $test->runSeal();
                $test->deleteSeal(3, true);
                $test->clearReceipts();

                return ['missing_tail', null];
            }],
        ];
    }

    /**
     * Every alteration that fails a run exits 1 and names its first finding and
     * bad id in the output, the event and the reported exception.
     *
     * @param  \Closure(self): array{0: string, 1: ?string}  $tamper
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testEveryFailureExitsNonZeroAndNamesTheFirstBadId(\Closure $tamper): void
    {
        $this->sealLog(3);

        [$finding, $id] = $tamper($this);

        $this->alarms->exchangeArray([]);

        [$exit, $output] = $this->verify();

        $reports = $this->handler->reports();
        $report  = $reports[count($reports) - 1] ?? null;

        self::assertSame(1, $exit);
        $named = sprintf('/( finding=%1$s first=%2$s|^finding %1$s integrity=tampered count=1 first=%2$s)$/m', $finding, $id ?? 'none');

        self::assertMatchesRegularExpression($named, $output);
        self::assertStringEndsWith("Verification failed.\n", $output);
        self::assertSame([$finding, $id], $this->verifyAlarmNames());
        self::assertInstanceOf(IntegrityCheckFailedException::class, $report);
        self::assertStringContainsString(sprintf('first finding %s at %s;', $finding, $id ?? 'none'), $report->getMessage());
    }

    /**
     * Delete the seal's first member with its entry and rewrite its count and
     * members digest, signed with the key when asked; return the digest.
     *
     * @param  int  $sequence
     * @param  bool  $withTheKey
     * @return string
     */
    private function dropFromSeal(int $sequence, bool $withTheKey): string
    {
        $entry = $this->membersOf($this->sealIdAt($sequence))[0];

        $this->entries()->where('id', $entry)->delete();
        $this->deleteMember($entry);

        $membership = $this->membershipOf($sequence);

        return $withTheKey ? $this->forgeSeal($sequence, $membership) : $this->rewriteSeal($sequence, $membership);
    }

    /**
     * Forge the chain with the key from the seal at the sequence to the head,
     * re-signing each seal.
     *
     * @param  int  $sequence
     * @return void
     */
    private function forgeChainFrom(int $sequence): void
    {
        $digest = $this->dropFromSeal($sequence, true);
        $head   = count($this->seals());

        for ($next = $sequence + 1; $next <= $head; $next++) {
            $digest = $this->forgeSeal($next, ['previous_digest' => $digest]);
        }
    }

    /**
     * Insert a seal of the entry after the head with a consistent digest and a
     * signature not the key's, with its member row; return its id.
     *
     * @param  string  $entryId
     * @return string
     */
    private function insertForgedHead(string $entryId): string
    {
        $seals = $this->seals();
        $head  = $seals[count($seals) - 1];
        /** @var array{recorded_at: string, hmac: string} $entry */
        $entry = (array) $this->entries()->where('id', $entryId)->first(['recorded_at', 'hmac']);
        $at    = StoredTime::fromStorage($entry['recorded_at']);
        $hmac  = $entry['hmac'];

        $envelope = new SealEnvelope(
            app(SealSettings::class)->logId(),
            self::FORGED_SEAL_ID,
            (int) $head['sequence'] + 1,
            (string) $head['id'],
            (string) $head['seal_digest'],
            1,
            SealEnvelope::membersDigest([[$entryId, $hmac]]),
            $at,
            $at,
            '2026-11-01T13:30:00.000000Z',
            app(SealSigner::class)->signingKeyId(),
        );

        $this->tamperedTable(IntegrityTables::checkpointsTable())->insert($envelope->toRow($envelope->digest(), self::OTHER_DIGEST));
        $this->tamperedTable(IntegrityTables::membersTable())->insert(['checkpoint_id' => self::FORGED_SEAL_ID, 'entry_id' => $entryId, 'hmac' => $hmac]);

        return self::FORGED_SEAL_ID;
    }

    /**
     * Delete every entry of the seal and keep their prune record in the ledger,
     * signed with the key or, when forged, without it.
     *
     * @param  array<string, scalar|null>  $seal
     * @param  bool  $forged
     * @return void
     */
    private function pruneSeal(array $seal, bool $forged): void
    {
        $this->entries()->whereIn('id', $this->membersOf((string) $seal['id']))->delete();

        $count  = (int) $seal['member_count'];
        $record = app(SealSigner::class)->signPrune(
            (string) $seal['log_id'],
            (string) $seal['id'],
            (string) $seal['seal_digest'],
            $count,
            PruneBitmap::encode(range(0, $count - 1), $count),
            $count,
            self::OPERATION_ID,
            self::PRUNED_AT,
        );

        if ($forged) {
            $record = PruneRecord::fromArray([...$record->toArray(), 'signature' => self::OTHER_DIGEST]);
        }

        $this->prunes->add($record);
    }

    /**
     * Store one finalised record with the properties given, recorded when the
     * first entries are, and return its id.
     *
     * @param  array<string, array<string, list<array<string, string>>>>  $properties
     * @return string
     */
    private function storeEntryWith(array $properties): string
    {
        $instant   = StoredTime::format(new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC'));
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured($properties, occurredAt: $instant));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }

    /**
     * The id of the stored entry recorded at the instant.
     *
     * @param  string  $instant
     * @return string
     */
    private function storedEntryRecordedAt(string $instant): string
    {
        $id = $this->entries()->where('recorded_at', StoredTime::toStorage($instant))->value('id');

        self::assertIsString($id, 'No entry is recorded at that instant.');

        return $id;
    }

    /**
     * The sequences the disk anchor holds an object for.
     *
     * @return list<int>
     */
    private function anchoredSequences(): array
    {
        $objects = Storage::disk(self::ANCHOR_DISK)->files(self::ANCHOR_PATH . '/' . app(SealSettings::class)->logId());

        return array_values(array_map(static fn (string $object): int => (int) substr(basename($object), 0, 20), $objects));
    }

    /**
     * The one event the verify command dispatched.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function verifyAlarm(): IntegrityCheckFailed
    {
        $alarms = array_values(array_filter($this->alarms->getArrayCopy(), static fn (IntegrityCheckFailed $alarm): bool => $alarm->command === 'verify'));

        self::assertCount(1, $alarms, 'The verify command did not dispatch exactly one event.');

        $this->alarms->exchangeArray([]);

        return $alarms[0];
    }

    /**
     * The first finding and first bad id of the one event the verify command
     * dispatched.
     *
     * @return array{0: ?string, 1: ?string}
     */
    private function verifyAlarmNames(): array
    {
        $alarm = $this->verifyAlarm();

        return [$alarm->finding, $alarm->firstBadId];
    }

    /**
     * The first finding, the tampered count and the contradicted count of the
     * one event the seal command dispatched.
     *
     * @return array{0: ?string, 1: ?int, 2: ?int}
     */
    private function sealAlarmCounts(): array
    {
        $alarms = array_values(array_filter($this->alarms->getArrayCopy(), static fn (IntegrityCheckFailed $alarm): bool => $alarm->command === 'seal'));

        self::assertCount(1, $alarms, 'The seal command did not dispatch exactly one event.');

        $this->alarms->exchangeArray([]);

        return [$alarms[0]->finding, $alarms[0]->integrity['tampered'] ?? null, $alarms[0]->anchoring['contradicted'] ?? null];
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
     * The line the verify command prints for a seal, with its finding and first
     * id when it has one.
     *
     * @param  int  $sequence
     * @param  string  $id
     * @param  string  $integrity
     * @param  int  $members
     * @param  ?string  $finding
     * @param  ?string  $first
     * @param  string  $anchoring
     * @return non-empty-string
     */
    private static function line(
        int $sequence,
        string $id,
        string $integrity,
        int $members,
        ?string $finding = null,
        ?string $first = null,
        string $anchoring = 'unanchored',
    ): string {
        $line = sprintf('seal %d %s integrity=%s anchoring=%s members=%d', $sequence, $id, $integrity, $anchoring, $members);

        return ($finding === null ? $line : sprintf('%s finding=%s first=%s', $line, $finding, $first)) . "\n";
    }

    /**
     * The one line of the output that reports the seal with the id, without its
     * line break.
     *
     * @param  string  $output
     * @param  string  $id
     * @return string
     */
    private static function lineOf(string $output, string $id): string
    {
        $lines = preg_grep('/\Aseal \d+ ' . preg_quote($id, '/') . ' /', explode("\n", $output)) ?: [];

        self::assertCount(1, $lines, sprintf('The output does not report seal %s once.', $id));

        return (string) array_values($lines)[0];
    }
}
