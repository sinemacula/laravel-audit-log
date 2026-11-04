<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for erasing an owner, on whichever engine the suite runs
 * against, end to end through captures under the package's encrypter and reads
 * under the package's reader: only the owner's keys are destroyed, so another
 * owner's fragment of the same record still reads; a hold of the verified chain
 * or a preservation blocking any unit refuses the whole erasure unless it goes
 * ahead in part, which destroys the rest and reports the kept keys; an outbox
 * older than the erasure refuses it unless accepted, and a record still in the
 * outbox is erased with its key however it is held; the journal row lists each
 * destroyed key before and after and each kept key's reasons, the keys are
 * tombstoned with its id and the owner marked; an owner already erased is a
 * no-op; a custom encrypter, a key that fails its signature, too many keys, a
 * broken journal and another installation are refused, writing nothing; a
 * tombstone that changes fewer keys than it names rolls the whole erasure back;
 * and the owner's lock is free once the erasure has ended, after retries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Eraser::class)]
final class EraserTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string When every capture and erasure runs, unless a test moves the clock. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The operation every erasure runs under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The operation every hold is placed under. */
    private const string HOLD_OPERATION = '01932b4e-9000-7000-8000-0000000000b1';

    /** @var string The code a card charge is captured under. */
    private const string CARD = 'billing.card_charged';

    /** @var string The code a support ticket is captured under. */
    private const string TICKET = 'support.ticket_opened';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var string The connection a test points the maintenance connection at when it must reach another database. */
    private const string OTHER = 'audit_other';

    /** @var string How MySQL reports a deadlock, which a lifecycle transaction retries. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /**
     * Freeze the clock, bind the package's key wrapper, encrypter and reader as
     * the provider will, and define the codes every test captures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();

        $card = EventDefinition::for(self::CARD)
            ->category('billing')
            ->retain('amount')
            ->encrypt('card', KeyOwner::ACTOR)
            ->encrypt('expiry', KeyOwner::ACTOR)
            ->encrypt('iban', KeyOwner::SUBJECT);

        self::define($card, EventDefinition::for(self::TICKET)->category('support')->retain('topic')->encrypt('details', KeyOwner::ACTOR));
    }

    /**
     * Roll back any transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An owner who never had a key is still marked and journalled: an `erasure`
     * row destroying nothing at floor 0, and an `erased` marker under its id,
     * so no key is ever created for the owner.
     *
     * @return void
     */
    public function testAnOwnerWithNoKeysIsMarkedAndJournalled(): void
    {
        $result = $this->erase(self::owner());
        $marker = app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner());
        $row    = $this->lastJournalRow();

        self::assertSame(ErasureStatus::COMPLETE, $result->status);
        self::assertSame([0, 0, 0], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame(JournalKind::ERASURE, $row->kind);
        self::assertSame($row->id, $result->erasureId);
        self::assertNotNull($marker);
        self::assertSame([$row->id, MarkerTransition::ERASED, 0, $row->sequence], [$marker->id, $marker->transition, $marker->generationFloor, $marker->journalSequence]);
        self::assertNull($this->keyCreator()->create(new KeyUnit(self::owner(), null, 'billing')));
    }

    /**
     * A record holding fragments of two owners keeps the other owner's: the
     * erased owner's card reads `[ERASED]`, the other owner's IBAN still reads,
     * and only the erased owner's key is destroyed.
     *
     * @return void
     */
    public function testATwoOwnerRecordErasesOnlyOneOwnersFragments(): void
    {
        $other  = Reference::of('App\Models\Account', '9');
        $record = $this->chargeCard(self::owner(), $other);

        $this->revealEverything();

        self::assertSameProperties(['amount' => '12.00', 'card' => '4242', 'expiry' => '12/30', 'iban' => 'GB00TEST'], $this->propertiesOf($record->id, 'billing'));

        $result = $this->erase(self::owner());

        self::assertSame([1, 1], [$result->keysDestroyed, $result->entriesAffected]);
        self::assertSameProperties(['amount' => '12.00', 'card' => self::ERASED, 'expiry' => self::ERASED, 'iban' => 'GB00TEST'], $this->propertiesOf($record->id, 'billing'));
        self::assertSame([KeyState::ERASED], $this->statesOf(self::owner()));
        self::assertSame([KeyState::LIVE], $this->statesOf($other));
    }

    /**
     * A hold of the verified chain matching one unit's entry refuses the whole
     * erasure, naming the hold, and nothing is written: every key stays live
     * and no row or marker is added.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHeldUnitRefusesTheWholeErasure(): void
    {
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $hold    = $this->hold(HoldScope::all()->categories('support'));
        $written = $this->written();
        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::BLOCKED, $refused->refusal());
        self::assertSame(['held:' . $hold->id], $refused->reasons());
        self::assertSame(app(OwnerFingerprint::class)->of(self::owner()), [$refused->fingerprintKey(), $refused->fingerprint()]);
        self::assertSame($written, $this->written());
        self::assertSame([KeyState::LIVE, KeyState::LIVE], $this->statesOf(self::owner()));
    }

    /**
     * A unit whose entry is still within its category's preservation refuses
     * the whole erasure, `preserved:<category>`, and nothing is written; once
     * the entry is past it, the erasure goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreservedUnitRefusesTheWholeErasure(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', ['support' => 30]);

        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $written = $this->written();
        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::BLOCKED, $refused->refusal());
        self::assertSame(['preserved:support'], $refused->reasons());
        self::assertSame($written, $this->written());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-12-05 00:00:00', 'UTC'));

        self::assertSame(2, $this->erase(self::owner())->keysDestroyed);
    }

    /**
     * A category preserved forever blocks every entry of its units, however
     * old.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForeverPreservationBlocksEveryEntry(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', ['billing' => 0]);

        CarbonImmutable::setTestNow(new CarbonImmutable('2001-01-01 00:00:00', 'UTC'));

        $this->chargeCard(self::owner());

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        self::assertSame(['preserved:billing'], $this->refusalOf(self::owner())->reasons());
    }

    /**
     * Going ahead in part destroys the units nothing blocks and keeps the rest,
     * reporting each kept key's reasons: the result is `partial`, the owner is
     * marked erased, the kept unit's live key goes on encrypting, and no key is
     * created for the destroyed unit.
     *
     * @return void
     */
    public function testPartialDestroysTheUnblockedUnitsAndReportsTheRest(): void
    {
        $card   = $this->chargeCard(self::owner());
        $ticket = $this->openTicket(self::owner());
        $hold   = $this->hold(HoldScope::all()->categories('support'));
        $kept   = $this->keyOf(self::owner(), 'support');
        $result = $this->erase(self::owner(), true);

        self::assertSame(ErasureStatus::PARTIAL, $result->status);
        self::assertSame([1, 1, 1], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame(['held:' . $hold->id], $result->blocked);
        self::assertSame(KeyState::LIVE, $this->keyOf(self::owner(), 'support')->state);
        self::assertSame(KeyState::ERASED, $this->keyOf(self::owner(), 'billing')->state);
        self::assertSame(MarkerTransition::ERASED, app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner())?->transition);
        self::assertSame([['generation' => 1, 'key_id' => $kept->id, 'reasons' => ['held:' . $hold->id], 'unit' => $kept->unit]], $this->lastPayload()['kept']);
        self::assertTrue($this->lastPayload()['partial']);

        $this->revealEverything();

        $next = $this->openTicket(self::owner());

        self::assertSame(self::ERASED, $this->propertiesOf($card->id, 'billing')['card']);
        self::assertSame('Card declined.', $this->propertiesOf($ticket->id, 'support')['details']);
        self::assertSame('Card declined.', $this->propertiesOf($next->id, 'support')['details']);
        self::assertNull($this->keyCreator()->create(new KeyUnit(self::owner(), null, 'billing')));
    }

    /**
     * A hold of one category leaves the owner's unit of another category
     * erasable: the units are what let unrelated data go.
     *
     * @return void
     */
    public function testAHoldOnOneCategoryLeavesAnotherUnitErasable(): void
    {
        $this->chargeCard(self::owner());
        $this->openTicket(Reference::of('App\Models\User', '43'));
        $this->hold(HoldScope::all()->categories('support'));

        $result = $this->erase(self::owner());

        self::assertSame(ErasureStatus::COMPLETE, $result->status);
        self::assertSame(1, $result->keysDestroyed);
        self::assertSame([], $result->blocked);
    }

    /**
     * The blocks are decided from the holds of the verified chain, never from
     * the projection: a hold whose projection row was deleted still refuses the
     * erasure, and a projection row of a hold the chain released holds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBlocksAreDecidedFromTheReplayedChainNotTheProjection(): void
    {
        $this->chargeCard(self::owner());

        $hold       = $this->hold(HoldScope::all());
        $projection = $this->keyConnection()->table(LifecycleTables::holdsTable())->where('hold_id', $hold->id);
        $row        = (array) $projection->first();

        $projection->delete();

        self::assertSame(['held:' . $hold->id], $this->refusalOf(self::owner())->reasons());

        app(HoldKeeper::class)->release(self::HOLD_OPERATION, $hold->id, self::authority());

        $this->keyConnection()->table(LifecycleTables::holdsTable())->insert($row);

        self::assertSame(1, $this->erase(self::owner())->keysDestroyed);
    }

    /**
     * A hold committed after the erasure was asked for, but before its lock, is
     * seen: the erasure reads the holds after its lock, and is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldPlacedBeforeTheLockIsSeen(): void
    {
        $this->chargeCard(self::owner());

        /** @var \ArrayObject<string, string> $placed */
        $placed = new \ArrayObject;
        $state  = IntegrityTables::stateTable();

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(function (string $query) use ($placed, $state): void {
            if ($placed->count() > 0 || !str_contains($query, $state)) {
                return;
            }

            // The hold's own statements reach this hook too, so the guard is
            // set before it is placed
            $placed['hold'] = '';
            $placed['hold'] = $this->hold(HoldScope::all())->id;
        });

        $refused = $this->refusalOf(self::owner());

        self::assertSame(['held:' . $placed['hold']], $refused->reasons());
    }

    /**
     * An outbox row created before the erasure started refuses it, failed or
     * not, since the key's destruction erases whatever it holds; nothing is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOutboxRowOlderThanTheErasureRefusesIt(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $this->chargeCard(self::owner());

        $written = $this->written();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:01', 'UTC'));

        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::PENDING_DELIVERY, $refused->refusal());
        self::assertSame([], $refused->reasons());
        self::assertSame($written, $this->written());
    }

    /**
     * An erasure that accepts the outbox goes ahead and says so; the record
     * still in the outbox is delivered afterwards, its envelope under the
     * destroyed key, so it reads `[ERASED]` once stored.
     *
     * @return void
     */
    public function testPendingAcceptsItAndTheDeliveredRecordIsErased(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $record = $this->chargeCard(self::owner());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:01', 'UTC'));

        $result = $this->erase(self::owner(), false, true);

        self::assertTrue($result->pendingAccepted);
        self::assertSame([1, 0], [$result->keysDestroyed, $result->entriesAffected]);
        self::assertSame([true, 1], [$this->lastPayload()['pending_accepted'], $this->lastPayload()['pending_rows']]);

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());

        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::SYNC->value);

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->propertiesOf($record->id, 'billing')['card']);
    }

    /**
     * An erasure that accepts an empty outbox accepted nothing.
     *
     * @return void
     */
    public function testPendingOverAnEmptyOutboxAcceptsNothing(): void
    {
        $this->chargeCard(self::owner());

        $result = $this->erase(self::owner(), false, true);

        self::assertFalse($result->pendingAccepted);
        self::assertSame([false, 0], [$this->lastPayload()['pending_accepted'], $this->lastPayload()['pending_rows']]);
    }

    /**
     * A hold protects a record only once it is stored: a record still in the
     * outbox has no key use, so a hold that matches it blocks nothing, and it
     * is erased with its key; the same hold over a stored record refuses.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldProtectsARecordOnlyOnceStored(): void
    {
        $other = Reference::of('App\Models\User', '43');

        $this->chargeCard($other);

        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $pending = $this->chargeCard(self::owner());

        $this->hold(HoldScope::all()->categories('billing'));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:01', 'UTC'));

        self::assertSame(1, $this->erase(self::owner(), false, true)->keysDestroyed);
        self::assertSame(ErasureRefusal::BLOCKED, $this->refusalOf($other, false, true)->refusal());

        app(OutboxDrainer::class)->drain(100, false);
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::SYNC->value);

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->propertiesOf($pending->id, 'billing')['card']);
    }

    /**
     * The journal row names the operation and the authority, and lists, by key
     * id, every destroyed key with its unit, generation, state, HMAC, wrapped
     * key digest and wrapping key before and its state after, the owner's
     * fingerprint, the floor, the outbox accepted and the entries affected.
     *
     * @return void
     */
    public function testTheJournalRowListsEveryDestroyedKeyWithItsBeforeAndAfter(): void
    {
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $billing = $this->keyOf(self::owner(), 'billing');
        $support = $this->keyOf(self::owner(), 'support');

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $support->id)->update(['state' => KeyState::SUPERSEDED->value]);

        $support = $this->keyOf(self::owner(), 'support');
        $result  = $this->erase(self::owner());
        $row     = $this->lastJournalRow();

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        $destroyed = array_map(static fn (SubjectKeyRow $key): array => [
            'key_id'     => $key->id,
            'unit'       => $key->unit,
            'generation' => $key->generation,
            'before'     => ['state' => $key->state->value, 'hmac' => $key->hmac, 'wrapped_digest' => hash('sha256', (string) $key->wrappedKey), 'wrap_key_id' => $key->wrapKeyId],
            'after'      => ['state' => 'erased'],
        ], [$billing, $support]);

        usort($destroyed, static fn (array $a, array $b): int => strcmp($a['key_id'], $b['key_id']));

        self::assertSame(self::OPERATION, $row->operationId);
        self::assertSame(['App\Models\User', '7', 'case.review', 'app:ticket-123'], [$row->authorityType, $row->authorityId, $row->reason, $row->externalReference]);
        self::assertSame(CanonicalEncoder::encode([
            'owner_fingerprint' => $fingerprint,
            'fingerprint_key'   => $fingerprintKey,
            'generation_floor'  => 1,
            'partial'           => false,
            'pending_accepted'  => false,
            'pending_rows'      => 0,
            'destroyed'         => $destroyed,
            'kept'              => [],
            'entries_affected'  => 2,
        ]), $row->payload);
        self::assertSame([$fingerprint, $fingerprintKey], [$result->fingerprint, $result->fingerprintKey]);
    }

    /**
     * Every destroyed key, live or superseded, is tombstoned with the erasure
     * row's id, erased with no wrapped key, its wrapping key and signed fields
     * kept; the marker shares the row's id, sequence and time, at the floor; a
     * key erased before is left as it was.
     *
     * @return void
     */
    public function testTheKeysAreTombstonedWithTheErasureRowsId(): void
    {
        $this->chargeCard(self::owner());

        $first = $this->eraseByHand(self::owner());

        $this->reinstateByHand(self::owner());
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $support = $this->keyOf(self::owner(), 'support');

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $support->id)->update(['state' => KeyState::SUPERSEDED->value]);

        $before = $this->storedSubjectKeys();
        $result = $this->erase(self::owner());
        $row    = $this->lastJournalRow();
        $marker = app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner());

        self::assertSame($row->id, $result->erasureId);

        foreach ($this->storedSubjectKeys() as $id => $key) {
            $erasure = $before[$id]->state === KeyState::ERASED ? $first->id : $row->id;

            self::assertSame([KeyState::ERASED, null, $erasure], [$key->state, $key->wrappedKey, $key->erasureId], $id);
            self::assertSame([$before[$id]->wrapKeyId, $before[$id]->hmac, $before[$id]->generation], [$key->wrapKeyId, $key->hmac, $key->generation], $id);
        }

        self::assertNotNull($marker);
        self::assertSame([$row->id, $row->sequence, $row->occurredAt, 2], [$marker->id, $marker->journalSequence, $marker->createdAt, $marker->generationFloor]);
        self::assertSame(2, $result->keysDestroyed);
    }

    /**
     * The entries affected are distinct entries: an entry holding two fields
     * under one key counts once, and the entries of each destroyed key are
     * summed.
     *
     * @return void
     */
    public function testTheEntriesAffectedAreDistinctEntries(): void
    {
        $this->chargeCard(self::owner());
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());
        $this->chargeCard(Reference::of('App\Models\User', '43'));

        $result = $this->erase(self::owner());

        self::assertSame(3, $result->entriesAffected);
        self::assertSame(3, $this->lastPayload()['entries_affected']);
        self::assertSame(4, $this->keyConnection()->table(KeyTables::keyUsesTable())->count());
    }

    /**
     * An erased owner gets no new key in any unit: a later capture drops the
     * owner's fields, and the key creator makes none.
     *
     * @return void
     */
    public function testAnErasedOwnerGetsNoNewKey(): void
    {
        $this->chargeCard(self::owner());
        $this->erase(self::owner());

        $keys  = count($this->storedSubjectKeys());
        $later = $this->openTicket(self::owner());

        self::assertArrayNotHasKey('details', $later->properties ?? []);
        self::assertCount($keys, $this->storedSubjectKeys());
        self::assertNull($this->keyCreator()->create(new KeyUnit(self::owner(), null, 'support')));
        self::assertNull($this->keyCreator()->create(new KeyUnit(self::owner(), null, 'billing')));
    }

    /**
     * An owner already erased who holds no key is a no-op: the result is
     * `already_erased`, names no row, and nothing is written.
     *
     * @return void
     */
    public function testAnAlreadyErasedOwnerIsANoOp(): void
    {
        $this->chargeCard(self::owner());
        $this->erase(self::owner());

        $written = $this->written();
        $result  = $this->erase(self::owner());

        self::assertSame(ErasureStatus::ALREADY_ERASED, $result->status);
        self::assertNull($result->erasureId);
        self::assertSame([0, 0, 0], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame(app(OwnerFingerprint::class)->of(self::owner()), [$result->fingerprintKey, $result->fingerprint]);
        self::assertSame($written, $this->written());
    }

    /**
     * An owner erased in part keeps its blocked keys, so it is not already
     * erased: once the hold is released, erasing it again destroys them.
     *
     * @return void
     */
    public function testAKeptKeyIsDestroyedOnceItsHoldIsReleased(): void
    {
        $this->openTicket(self::owner());

        $hold = $this->hold(HoldScope::all());

        self::assertSame(0, $this->erase(self::owner(), true)->keysDestroyed);

        app(HoldKeeper::class)->release(self::HOLD_OPERATION, $hold->id, self::authority());

        $result = $this->erase(self::owner());

        self::assertSame(ErasureStatus::COMPLETE, $result->status);
        self::assertSame(1, $result->keysDestroyed);
        self::assertSame([KeyState::ERASED], $this->statesOf(self::owner()));
    }

    /**
     * A custom encrypter is refused `unsupported_encrypter`, naming its class,
     * before the installation is confirmed or the lock taken; the package's
     * encrypter that never encrypts is supported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACustomEncrypterIsRefused(): void
    {
        $this->chargeCard(self::owner());

        app()->bind(FieldEncrypter::class, RecordingFieldEncrypter::class);

        $lock    = $this->lockRow();
        $written = $this->written();
        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::UNSUPPORTED_ENCRYPTER, $refused->refusal());
        self::assertSame([RecordingFieldEncrypter::class], $refused->reasons());
        self::assertSame($lock, $this->lockRow());
        self::assertSame($written, $this->written());

        app()->bind(FieldEncrypter::class, NoFieldEncrypter::class);

        self::assertSame(1, $this->erase(self::owner())->keysDestroyed);
    }

    /**
     * Rows of `[how a key of the owner is made unverifiable]`: its signed
     * fields changed, or signed under a key the ring does not hold.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideUnverifiableKeys(): iterable
    {
        yield from [
            'a changed creation time' => [['created_at' => '2026-11-04 09:00:00.000000']],
            'a forged signature'      => [['hmac' => str_repeat('0', 64)]],
            'an unknown signing key'  => [['key_id' => 'retired-key']],
        ];
    }

    /**
     * A key of the owner that fails its signature, in any state, refuses the
     * whole erasure `key_unverifiable`, naming the key, and nothing is written.
     *
     * @param  array<string, string>  $columns
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnverifiableKeys')]
    public function testAKeyThatFailsItsSignatureRefusesTheErasure(array $columns): void
    {
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $key = $this->keyOf(self::owner(), 'support');

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($columns);

        $written = $this->written();
        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::KEY_UNVERIFIABLE, $refused->refusal());
        self::assertSame([$key->id], $refused->reasons());
        self::assertSame($written, $this->written());
    }

    /**
     * A key of the owner too malformed to read refuses the erasure
     * `key_unverifiable`, naming no key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedKeyRefusesTheErasure(): void
    {
        $this->chargeCard(self::owner());

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->update(['category' => 'Not A Category']);

        $refused = $this->refusalOf(self::owner());

        self::assertSame(ErasureRefusal::KEY_UNVERIFIABLE, $refused->refusal());
        self::assertSame([], $refused->reasons());
    }

    /**
     * More than 10,000 live or superseded keys are refused `too_many_keys`
     * before any key is read or any key use; 10,000 are not refused for their
     * number.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMoreThanTenThousandKeysAreRefused(): void
    {
        $this->insertForgedKeys(Eraser::MAX_KEYS);

        self::assertSame(ErasureRefusal::KEY_UNVERIFIABLE, $this->refusalOf(self::owner())->refusal());

        $this->insertForgedKeys(1, Eraser::MAX_KEYS + 1);

        $reads = $this->readsOf([KeyTables::keyUsesTable(), KeyTables::subjectKeysTable()]);

        self::assertSame(ErasureRefusal::TOO_MANY_KEYS, $this->refusalOf(self::owner())->refusal());
        self::assertSame([KeyTables::subjectKeysTable() => 1], array_count_values($reads->getArrayCopy()));
    }

    /**
     * A journal that fails verification refuses the erasure before anything is
     * decided, naming the finding, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABrokenJournalRefusesTheErasure(): void
    {
        $this->chargeCard(self::owner());

        $hold = $this->hold(HoldScope::all()->categories('support'));

        $this->tamperJournal($hold->journalSequence, ['reason' => 'other.reason']);

        $written = $this->written();

        try {
            $this->erase(self::owner());

            self::fail('Expected the erasure to be refused.');
        } catch (JournalBrokenException $exception) {
            self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        }

        self::assertSame($written, $this->written());
    }

    /**
     * Erasing changes no signed column: every entry still verifies under its
     * HMAC, every key under its signature, and the journal with its erasure row
     * verifies whole.
     *
     * @return void
     */
    public function testHmacsStillVerifyAfterTheErasure(): void
    {
        $this->chargeCard(self::owner(), Reference::of('App\Models\Account', '9'));
        $this->openTicket(self::owner());
        $this->erase(self::owner());

        $codec   = new RowCodec;
        $entries = $this->keyConnection()->table(EntrySettings::table())->get()->all();

        self::assertCount(2, $entries);

        foreach ($entries as $entry) {
            self::assertTrue(app(RecordSigner::class)->verifies($codec->decode((array) $entry)));
        }

        foreach ($this->storedSubjectKeys() as $key) {
            self::assertTrue(app(SubjectKeySigner::class)->verifies($key), $key->id);
        }

        $replay = JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId())->verify($this->keyConnection());

        self::assertSame($this->lastJournalRow()->sequence, $replay->head()[0] ?? null);
    }

    /**
     * An erasure lost to a concurrent operation is made again, its work run
     * afresh after the owner's lock, and commits once; the owner's lock is free
     * once it has ended, every attempt's released.
     *
     * @return void
     */
    public function testTheOwnerIsReleasedAfterRetries(): void
    {
        $this->chargeCard(self::owner());

        $lost   = new \ArrayObject;
        $locks  = new \ArrayObject;
        $marker = KeyTables::ownerErasuresTable();

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(static function (string $query) use ($lost, $marker): void {
            if ($lost->count() >= 2 || !str_starts_with($query, 'select') || !str_contains($query, $marker)) {
                return;
            }

            $lost->append(true);

            throw new QueryException(StorageConnection::forMaintenance(), $query, [], new \PDOException(self::DEADLOCK));
        });

        DB::listen(static function (QueryExecuted $query) use ($locks): void {
            if (!str_contains($query->sql, LifecycleTables::lockTable())) {
                return;
            }

            $locks->append($query->sql);
        });

        $result = $this->erase(self::owner());

        self::assertSame(1, $result->keysDestroyed);
        self::assertCount(2, $lost);
        self::assertCount(3, $locks);
        self::assertCount(1, array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === JournalKind::ERASURE->value));
        self::assertTrue($this->isOwnerLockFree(self::owner()));
    }

    /**
     * The installation is confirmed before the lock is taken: a maintenance
     * connection that reaches another database is refused, and neither the
     * lock, the journal, the keys nor the markers are touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInstallationMismatchRefusesBeforeTheLock(): void
    {
        $this->chargeCard(self::owner());
        $this->otherDatabase();

        $lock    = $this->lockRow();
        $written = $this->written();

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        try {
            $this->erase(self::owner());

            self::fail('Expected the erasure to be refused.');
        } catch (InstallationMismatchException) {
            // The refusal under test
        }

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', null);

        self::assertSame($lock, $this->lockRow());
        self::assertSame($written, $this->written());
    }

    /**
     * A tombstone that changes fewer keys than it names, a key erased behind
     * the erasure's back, rolls the whole erasure back: the journal row, the
     * marker and every other key's tombstone with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATombstoneCountMismatchRollsEverythingBack(): void
    {
        $this->chargeCard(self::owner());
        $this->openTicket(self::owner());

        $victim  = $this->keyOf(self::owner(), 'support');
        $written = $this->written();
        $keys    = KeyTables::subjectKeysTable();
        $fired   = new \ArrayObject;

        $tamper = static function (string $query, array $bindings, Connection $connection) use ($fired, $keys, $victim): void {
            if ($fired->count() > 0 || !str_starts_with($query, 'update') || !str_contains($query, $keys)) {
                return;
            }

            $fired->append(true);

            $connection->table($keys)->where('id', $victim->id)->update(['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => self::OPERATION]);
        };

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting($tamper);

        try {
            $this->erase(self::owner());

            self::fail('Expected the erasure to roll back.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A subject key changed while its owner was erased; the erasure is rolled back.', $exception->getMessage());
        }

        self::assertCount(1, $fired);
        self::assertSame($written, $this->written());
        self::assertSame([KeyState::LIVE, KeyState::LIVE], $this->statesOf(self::owner()));
    }

    /**
     * Going ahead in part when every key is blocked destroys nothing and still
     * marks and journals the owner: the result is `partial`, every key kept
     * with its reasons, and no new key is made for the owner.
     *
     * @return void
     */
    public function testAPartialErasureBlockedEverywhereStillMarksAndJournals(): void
    {
        $this->chargeCard(self::owner());

        $hold   = $this->hold(HoldScope::all());
        $key    = $this->keyOf(self::owner(), 'billing');
        $result = $this->erase(self::owner(), true);
        $row    = $this->lastJournalRow();

        self::assertSame(ErasureStatus::PARTIAL, $result->status);
        self::assertSame([0, 1, 0], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame(['held:' . $hold->id], $result->blocked);
        self::assertSame($row->id, $result->erasureId);
        self::assertSame([], $this->lastPayload()['destroyed']);
        self::assertSame([['generation' => 1, 'key_id' => $key->id, 'reasons' => ['held:' . $hold->id], 'unit' => $key->unit]], $this->lastPayload()['kept']);
        self::assertSame([KeyState::LIVE], $this->statesOf(self::owner()));
        self::assertSame($row->id, app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner())?->id);
        self::assertNull($this->keyCreator()->create(new KeyUnit(self::owner(), null, 'support')));
    }

    /**
     * Erase the owner with the eraser the container builds, under the test's
     * operation and authority.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  bool  $partial
     * @param  bool  $pending
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \UnexpectedValueException
     */
    private function erase(Reference $owner, bool $partial = false, bool $pending = false): ErasureResult
    {
        return app(Eraser::class)->erase(self::OPERATION, $owner, self::authority(), $partial, $pending);
    }

    /**
     * The refusal an erasure of the owner throws; the test fails when it is not
     * refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  bool  $partial
     * @param  bool  $pending
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     */
    private function refusalOf(Reference $owner, bool $partial = false, bool $pending = false): ErasureRefusedException
    {
        try {
            $this->erase($owner, $partial, $pending);
        } catch (ErasureRefusedException $exception) {
            return $exception;
        }

        self::fail('Expected the erasure to be refused.');
    }

    /**
     * Capture a charge of a card, with its expiry, the actor owns, encrypted
     * under the actor's key, and, given a subject, an IBAN encrypted under the
     * subject's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function chargeCard(Reference $actor, ?Reference $subject = null): AuditRecord
    {
        $properties = ['amount' => '12.00', 'card' => '4242', 'expiry' => '12/30'];
        $pending    = AuditLog::event(self::CARD)->by($actor);

        if ($subject !== null) {
            $pending->on($subject);

            $properties['iban'] = 'GB00TEST';
        }

        return $pending->withProperties($properties)->record();
    }

    /**
     * Capture a support ticket the actor opened, its details encrypted under
     * the actor's key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function openTicket(Reference $actor): AuditRecord
    {
        return AuditLog::event(self::TICKET)->by($actor)->withProperties(['topic' => 'refund', 'details' => 'Card declined.'])->record();
    }

    /**
     * Place a hold over the scope through the hold keeper, and return it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private function hold(HoldScope $scope): Hold
    {
        return app(HoldKeeper::class)->place(self::HOLD_OPERATION, $scope, self::authority(), HoldBasis::LEGAL_CLAIM, null);
    }

    /**
     * The properties of the entry with the id, as a page of the category shows
     * them to the viewer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  string  $category
     * @return array<array-key, mixed>
     */
    private function propertiesOf(string $id, string $category): array
    {
        $entries = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory($category)->cursorPaginate(50)->entries;

        foreach ($entries as $entry) {
            if ($entry->id === $id) {
                return $entry->properties;
            }
        }

        self::fail("The page does not show {$id}.");
    }

    /**
     * The owner's key in the category, with no tenant, as stored.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $category
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function keyOf(Reference $owner, string $category): SubjectKeyRow
    {
        $unit = (new KeyUnit($owner, null, $category))->digest();
        $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit && $key->state !== KeyState::ERASED));

        if ($keys === []) {
            $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit));
        }

        self::assertNotSame([], $keys, "The owner has no key in {$category}.");

        return $keys[count($keys) - 1];
    }

    /**
     * The state of every key of the owner, in id order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState>
     */
    private function statesOf(Reference $owner): array
    {
        $keys = array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->ownerType === $owner->type && $key->ownerId === $owner->id);

        return array_values(array_map(static fn (SubjectKeyRow $key): KeyState => $key->state, $keys));
    }

    /**
     * What an erasure writes: the journal's rows, the owner markers and the key
     * rows, so a refusal can be shown to have written none of it.
     *
     * @return array{0: list<array<string, scalar|null>>, 1: list<array<string, scalar|null>>, 2: list<array<string, scalar|null>>}
     */
    private function written(): array
    {
        $rows = static fn (string $table, string $order): array => array_values(array_map(
            static fn (object $row): array => (array) $row,
            DB::connection(StorageConnection::name())->table($table)->orderBy($order)->get()->all(),
        ));

        /** @var array{0: list<array<string, scalar|null>>, 1: list<array<string, scalar|null>>, 2: list<array<string, scalar|null>>} */
        return [$this->journalRows(), $rows(KeyTables::ownerErasuresTable(), 'id'), $rows(KeyTables::subjectKeysTable(), 'id')];
    }

    /**
     * The journal's last row, with its payload.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function lastJournalRow(): JournalRow
    {
        $rows = $this->journalRows();

        return JournalRow::fromRow($rows[count($rows) - 1], true);
    }

    /**
     * The payload of the journal's last row, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     */
    private function lastPayload(): array
    {
        return $this->lastJournalRow()->payloadMap() ?? [];
    }

    /**
     * The lifecycle lock's row, as stored.
     *
     * @return array<string, scalar|null>
     */
    private function lockRow(): array
    {
        /** @var array<string, scalar|null> */
        return (array) DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->first();
    }

    /**
     * Insert keys of the owner that sign nothing, each live in one unit at its
     * own generation from the one given, at most 500 to a statement.
     *
     * @param  int  $count
     * @param  int  $from
     * @return void
     */
    private function insertForgedKeys(int $count, int $from = 1): void
    {
        $unit = (new KeyUnit(self::owner(), null, 'billing'))->digest();
        $rows = array_map(static fn (int $generation): array => [
            'id'          => sprintf('01932b4e-f000-7000-8000-%012d', $generation),
            'owner_type'  => self::owner()->type,
            'owner_id'    => self::owner()->id,
            'tenant_type' => null,
            'tenant_id'   => null,
            'category'    => 'billing',
            'unit'        => $unit,
            'generation'  => $generation,
            'state'       => KeyState::LIVE->value,
            'wrapped_key' => 'forged',
            'wrap_key_id' => 'd-0000000000000000',
            'created_at'  => '2026-11-04 09:00:00.000000',
            'erasure_id'  => null,
            'key_id'      => 'retired-key',
            'hmac'        => str_repeat('0', 64),
        ], range($from, $from + $count - 1));

        foreach (array_chunk($rows, 500) as $chunk) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->insert($chunk);
        }
    }

    /**
     * Record, from now, the table each read of any of the tables reads.
     *
     * @param  list<string>  $tables
     * @return \ArrayObject<int, string>
     */
    private function readsOf(array $tables): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $reads */
        $reads = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($reads, $tables): void {
            if (!str_starts_with($query->sql, 'select')) {
                return;
            }

            foreach ($tables as $table) {
                if (preg_match('/from [`"]?' . preg_quote($table, '/') . '[`"]?(\s|$)/', $query->sql) !== 1) {
                    continue;
                }

                $reads->append($table);
            }
        });

        return $reads;
    }

    /**
     * Whether the maintenance session holds the owner's lock no more: MySQL's
     * named lock not held by this session, whoever else may hold one of the
     * same name, and no advisory lock held by this session on PostgreSQL;
     * SQLite takes none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return bool
     */
    private function isOwnerLockFree(Reference $owner): bool
    {
        $connection = DB::connection(StorageConnection::forMaintenance());
        $held       = match ($connection->getDriverName()) {
            'mysql' => $connection->selectOne('select coalesce(is_used_lock(?) = connection_id(), 0) as held', [OwnerLock::name($owner)]),
            'pgsql' => $connection->selectOne('select count(*) as held from pg_locks where locktype = \'advisory\' and pid = pg_backend_pid()'),
            default => (object) ['held' => 0],
        };

        self::assertIsObject($held);

        return (int) ($held->held ?? 1) === 0;
    }

    /**
     * Configure `OTHER`, a connection to another database whose integrity state
     * table holds no installation id.
     *
     * @return void
     */
    private function otherDatabase(): void
    {
        $config = app(ConfigRepository::class);

        DB::purge(self::OTHER);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        $schema = DB::connection(self::OTHER)->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        $this->beforeApplicationDestroyed(static fn () => DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable()));
    }

    /**
     * The owner every test erases.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', '42');
    }

    /**
     * The authority every erasure and hold is made with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * Make the definitions the only ones the facade's recorder and the
     * container know, as an application registers them while it boots.
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
}
