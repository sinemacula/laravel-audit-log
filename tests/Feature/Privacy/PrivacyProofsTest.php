<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * End-to-end proofs of owners' keys and erasure on the provider's own bindings,
 * through the facade and the commands, with nothing of the package bound by
 * hand but the access policy: a field is sealed under its owner's key and
 * revealed only through the grant; erasing one owner of a record leaves the
 * other's fragment revealed, and the log still verifies; a hold and a
 * preservation refuse the whole erasure, and a partial one lets the owner's
 * unrelated unit go; a pending outbox refuses it until accepted, and the record
 * delivered after it reads erased; a reinstated owner is sealed for again in a
 * new generation; rewrap and rotation keep every field readable; binding
 * `NoFieldEncrypter` stops encryption and leaves erasure working; and
 * `holdingDataOf()` finds an owner's entries, refused under an encrypter of the
 * application's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class PrivacyProofsTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, SearchesForSecrets;

    /** @var string The code a card charge is captured under, sealing the card for the actor and the account for the subject. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string The code a support call is captured under, sealing its summary for the actor. */
    private const string CALL = 'support.call_noted';

    /** @var string The code whose sealed members minimisation leaves in a container of another shape. */
    private const string LISTED = 'billing.items_listed';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var string The card every charge is made with unless a test names another: the planted secret, which no hex, base64url or UUID holds by chance. */
    private const string CARD = self::SECRET . '-4242';

    /** @var string What a fragment shows under a scope that does not reveal it. */
    private const string ENCRYPTED = '[ENCRYPTED]';

    /** @var string The account number every charge carries. */
    private const string IBAN = 'GB29NWBK60161331926819';

    /** @var array<string, string> The options of the authority every command is run on. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'gdpr.article_17'];

    /** @var string A wrapping secret of 32 bytes. */
    private const string FIRST_SECRET = 'first-wrapping-secret-of-32-byte';

    /** @var string Another wrapping secret of 32 bytes. */
    private const string SECOND_SECRET = 'second-wrapping-secret-of-32-byt';

    /**
     * Freeze the clock, report to a recording handler, and define the charge
     * and the call on a recorder of the test's own, behind the facade.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CHARGE)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR)->encrypt('iban', KeyOwner::SUBJECT));
        $catalogue->define(EventDefinition::for(self::CALL)->category('support')->encrypt('summary', KeyOwner::ACTOR));
        $catalogue->define(EventDefinition::for(self::LISTED)->category('billing')->encrypt('0', KeyOwner::ACTOR)->encrypt('items.0', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * On the provider's bindings alone a charge's card and account are sealed
     * under their owners' keys, stored nowhere in plaintext, shown as
     * `[ENCRYPTED]` to a scope without the grant, and revealed through it.
     *
     * @return void
     */
    public function testTheDefaultsSealAndRevealOnlyThroughTheGrant(): void
    {
        self::assertInstanceOf(SubjectKeyEncrypter::class, app(FieldEncrypter::class));
        self::assertInstanceOf(SubjectKeyFieldReader::class, app(FieldReader::class));
        self::assertInstanceOf(LocalKeyWrapper::class, app(KeyWrapper::class));

        $id = $this->charge(self::customer('42'));

        self::assertHoldsNoSecret((array) $this->keyConnection()->table(EntrySettings::table())->where('id', $id)->first(), 'the stored row');

        $this->allowEverything();

        self::assertSame([self::ENCRYPTED, self::ENCRYPTED], self::fragmentsOf($this->shown($id)));

        $this->revealEverything();

        self::assertSame([self::CARD, self::IBAN], self::fragmentsOf($this->shown($id)));
    }

    /**
     * A member sealed in a map that minimisation leaves stored as a list, and
     * in a list of properties the metadata turns into a map, opens where it is
     * stored: both sides name it by its key, not by its container's shape.
     *
     * @return void
     */
    public function testAMemberOpensWhicheverShapeItsContainerIsStoredIn(): void
    {
        $owner  = self::customer('42');
        $nested = AuditLog::event(self::LISTED)->by($owner)->withProperties(['items' => [0 => self::CARD, 'discard' => 'x']])->record()->id;

        $this->later();

        $top = AuditLog::event(self::LISTED)->by($owner)->withProperties([0 => self::CARD, 'gone' => 'x'])->record()->id;

        $this->later();
        $this->revealEverything();

        $items = $this->shown($nested)->properties['items'] ?? null;

        self::assertSame([self::CARD], $items);
        self::assertSame(self::CARD, $this->shown($top)->properties[0] ?? null);
        self::assertArrayHasKey('_audit', $this->shown($top)->properties);
    }

    /**
     * Erasing the actor of a record about two owners, through the command,
     * turns the actor's fragment to `[ERASED]` and leaves the subject's
     * revealed; the erasure is recorded, and the log, sealed before and after
     * it, verifies with its keys.
     *
     * @return void
     */
    public function testErasingOneOwnerOfARecordLeavesTheOther(): void
    {
        $id = $this->charge(self::customer('42'));

        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]));

        self::assertSame(0, Artisan::call('audit-log:erase', ['type' => 'App\Models\Customer', 'id' => '42', ...self::AUTHORITY]));
        self::assertStringContainsString(': complete.', Artisan::output());
        self::assertCount(1, $this->readRecords('audit_log.subject_erased'));

        $this->revealEverything();

        self::assertSame([self::ERASED, self::IBAN], self::fragmentsOf($this->shown($id)));

        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]));

        $exit    = Artisan::call('audit-log:verify');
        $printed = Artisan::output();

        self::assertSame(0, $exit, $printed);
        self::assertMatchesRegularExpression('/^Keys: 2 verified, 1 erased, 0 findings\.$/m', $printed);
        self::assertStringContainsString('Verification passed.', $printed);
    }

    /**
     * A hold over the owner's charges refuses the whole erasure, writing
     * nothing; a partial erasure destroys the owner's support unit, which
     * nothing holds, and keeps the held billing unit, whose fragment stays
     * revealed while the call's reads `[ERASED]`.
     *
     * @return void
     */
    public function testAHoldRefusesTheErasureAndAPartialOneLetsTheUnrelatedUnitGo(): void
    {
        $owner  = self::customer('42');
        $charge = $this->charge($owner);
        $call   = AuditLog::event(self::CALL)->by($owner)->withProperties(['summary' => 'Asked about a refund.'])->record()->id;
        $hold   = AuditLog::lifecycle()->hold(HoldScope::all()->categories('billing'), self::authority(), HoldBasis::LEGAL_CLAIM)->hold;

        $this->later();

        $refused = self::refusalOf(static fn () => AuditLog::lifecycle()->erase($owner, self::authority()));

        self::assertSame([ErasureRefusal::BLOCKED, ['held:' . $hold->id]], [$refused->refusal(), $refused->reasons()]);
        $states = array_map(static fn (SubjectKeyRow $key): string => $key->state->value, $this->storedSubjectKeys());

        self::assertSame([KeyState::LIVE->value], array_values(array_unique($states)));
        self::assertSame('denied', $this->readRecords('audit_log.subject_erased')[0]['outcome'] ?? null);

        $partial = AuditLog::lifecycle()->erase($owner, self::authority(), partial: true);

        self::assertSame([ErasureStatus::PARTIAL, 1, 1], [$partial->status, $partial->keysDestroyed, $partial->keysKept]);

        $this->revealEverything();

        self::assertSame(self::CARD, $this->shown($charge)->properties['card'] ?? null);
        self::assertSame(self::ERASED, $this->shown($call)->properties['summary'] ?? null);
    }

    /**
     * A category preserved forever refuses an erasure of any key that sealed
     * one of its entries, naming the category.
     *
     * @return void
     */
    public function testAPreservedOwnerIsRefused(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', ['billing' => 0]);

        $this->charge(self::customer('42'));
        $this->later();

        $refused = self::refusalOf(static fn () => AuditLog::lifecycle()->erase(self::customer('42'), self::authority()));

        self::assertSame([ErasureRefusal::BLOCKED, ['preserved:billing']], [$refused->refusal(), $refused->reasons()]);
    }

    /**
     * A record still in the outbox refuses the erasure until it is accepted as
     * pending; once accepted, the record the drain delivers afterwards reads
     * `[ERASED]` for the erased owner and revealed for the other.
     *
     * @return void
     */
    public function testAPendingOutboxRefusesUntilAcceptedAndTheDeliveredRecordIsErased(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $id = $this->charge(self::customer('42'));

        $this->later();

        $refused = self::refusalOf(static fn () => AuditLog::lifecycle()->erase(self::customer('42'), self::authority()));

        self::assertSame(ErasureRefusal::PENDING_DELIVERY, $refused->refusal());

        $accepted = AuditLog::lifecycle()->erase(self::customer('42'), self::authority(), pending: true);

        self::assertSame([ErasureStatus::COMPLETE, true], [$accepted->status, $accepted->pendingAccepted]);

        self::assertSame(0, Artisan::call('audit-log:drain', ['--until-empty' => true]));
        $this->revealEverything();

        self::assertSame([self::ERASED, self::IBAN], self::fragmentsOf($this->shown($id)));
    }

    /**
     * An erased owner's new card is dropped, with no key made for it; once the
     * owner is reinstated through the command, the next card is sealed under a
     * new generation above the erased one and revealed, while the erased
     * fragment never comes back.
     *
     * @return void
     */
    public function testAReinstatedOwnerIsSealedForAgainInANewGeneration(): void
    {
        $owner = self::customer('42');
        $first = $this->charge($owner);

        AuditLog::lifecycle()->erase($owner, self::authority());

        $dropped = AuditLog::event(self::CHARGE)->by($owner)->on(self::account())->withProperties(['amount' => '9.00', 'card' => '5555'])->record();

        self::assertSame(['card'], $dropped->properties['_audit']['omitted']['paths'] ?? null);

        self::assertSame(0, Artisan::call('audit-log:reinstate', ['type' => 'App\Models\Customer', 'id' => '42', ...self::AUTHORITY, '--reason' => 'consent.renewed']));

        $second = $this->charge($owner, '6666');
        $keys   = $this->keysOf(new KeyUnit($owner, null, 'billing'));

        self::assertSame([[1, KeyState::ERASED], [2, KeyState::LIVE]], array_map(static fn (SubjectKeyRow $key): array => [$key->generation, $key->state], $keys));

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->shown($first)->properties['card'] ?? null);
        self::assertSame('6666', $this->shown($second)->properties['card'] ?? null);
    }

    /**
     * Rewrapping onto a new wrapping key, through the command, moves every key
     * onto it, so the old key can leave the ring and every field still reads;
     * rotating supersedes the live keys, the next charge opens the unit's next
     * generation, and both charges still read.
     *
     * @return void
     */
    public function testRewrapAndRotationKeepEveryFieldReadable(): void
    {
        $this->useRing(['w1' => self::FIRST_SECRET], 'w1');

        $owner = self::customer('42');
        $first = $this->charge($owner);

        $this->useRing(['w1' => self::FIRST_SECRET, 'w2' => self::SECOND_SECRET], 'w2');

        self::assertSame(0, Artisan::call('audit-log:rewrap', [...self::AUTHORITY, '--reason' => 'keys.rotated']));

        $this->useRing(['w2' => self::SECOND_SECRET], 'w2');

        self::assertSame(['w2'], array_values(array_unique(array_map(static fn (SubjectKeyRow $key): ?string => $key->wrapKeyId, $this->storedSubjectKeys()))));

        self::assertSame(0, Artisan::call('audit-log:rewrap', [...self::AUTHORITY, '--reason' => 'keys.rotated', '--rotate' => true]));

        $second = $this->charge($owner, '6666');
        $keys   = $this->keysOf(new KeyUnit($owner, null, 'billing'));

        self::assertSame([[1, KeyState::SUPERSEDED], [2, KeyState::LIVE]], array_map(static fn (SubjectKeyRow $key): array => [$key->generation, $key->state], $keys));

        $this->revealEverything();

        self::assertSame(self::CARD, $this->shown($first)->properties['card'] ?? null);
        self::assertSame('6666', $this->shown($second)->properties['card'] ?? null);
    }

    /**
     * Binding `NoFieldEncrypter` is the choice never to encrypt: a charge's
     * card and account are dropped and diagnosed, never stored, and an erasure
     * still destroys the keys made before the choice.
     *
     * @return void
     */
    public function testNoFieldEncrypterStopsEncryptionAndLeavesErasureWorking(): void
    {
        $owner = self::customer('42');

        $this->charge($owner);

        app()->bind(FieldEncrypter::class, NoFieldEncrypter::class);

        $dropped = AuditLog::event(self::CHARGE)->by($owner)->on(self::account())->withProperties(['amount' => '9.00', 'card' => '5555', 'iban' => self::IBAN])->record();

        self::assertSame(['card', 'iban'], $dropped->properties['_audit']['omitted']['paths'] ?? null);
        self::assertCount(2, $this->storedSubjectKeys());

        $erased = AuditLog::lifecycle()->erase($owner, self::authority());

        self::assertSame([ErasureStatus::COMPLETE, 1], [$erased->status, $erased->keysDestroyed]);
    }

    /**
     * `holdingDataOf()` finds the entries holding a fragment sealed under the
     * owner's keys, and no other owner's; under a field encrypter of the
     * application's own it is refused, naming the binding.
     *
     * @return void
     */
    public function testHoldingDataOfFindsTheOwnersEntriesUnderThePackagesEncrypter(): void
    {
        $mine = $this->charge(self::customer('42'));

        $this->charge(self::customer('43'));
        $this->revealEverything();

        $found = AuditLog::trail()->visibleTo($this->viewer())->holdingDataOf(self::customer('42'))->cursorPaginate(100)->entries;

        self::assertSame([$mine], array_map(static fn (TrailEntry $entry): string => $entry->id, $found));

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(RecordingFieldEncrypter::class);

        AuditLog::trail()->holdingDataOf(self::customer('42'));
    }

    /**
     * Capture a charge of the card given, by the customer, on the account, and
     * return its id; the clock moves on a second after it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $customer
     * @param  string  $card
     * @return string
     */
    private function charge(Reference $customer, string $card = self::CARD): string
    {
        $id = AuditLog::event(self::CHARGE)->by($customer)->on(self::account())->withProperties(['amount' => '12.00', 'card' => $card, 'iban' => self::IBAN])->record()->id;

        $this->later();

        return $id;
    }

    /**
     * The entry with the id, as a page of the trail shows it to the viewer,
     * which the test fails without.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private function shown(string $id): TrailEntry
    {
        foreach (AuditLog::trail()->visibleTo($this->viewer())->cursorPaginate(100)->entries as $entry) {
            if ($entry->id === $id) {
                return $entry;
            }
        }

        self::fail("The page does not show {$id}.");
    }

    /**
     * The stored keys of the unit, by generation.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     */
    private function keysOf(KeyUnit $unit): array
    {
        $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit->digest()));

        usort($keys, static fn (SubjectKeyRow $one, SubjectKeyRow $other): int => $one->generation <=> $other->generation);

        return $keys;
    }

    /**
     * Make the wrapping ring the keys given, with the current one named.
     *
     * @param  array<string, string>  $keys
     * @param  string  $current
     * @return void
     */
    private function useRing(array $keys, string $current): void
    {
        app(ConfigRepository::class)->set(['audit-log.privacy.keys' => $keys, 'audit-log.privacy.current' => $current]);
    }

    /**
     * Move the frozen clock on a second.
     *
     * @return void
     */
    private function later(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());
    }

    /**
     * The card and the account number a charge shows, in that order, each a
     * string, which the test fails without.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailEntry  $entry
     * @return array{0: string, 1: string}
     */
    private static function fragmentsOf(TrailEntry $entry): array
    {
        $card = $entry->properties['card'] ?? null;
        $iban = $entry->properties['iban'] ?? null;

        self::assertIsString($card);
        self::assertIsString($iban);

        return [$card, $iban];
    }

    /**
     * The refusal the erasure throws, which the test fails without.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $erase
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     */
    private static function refusalOf(\Closure $erase): ErasureRefusedException
    {
        try {
            $erase();
        } catch (ErasureRefusedException $refused) {
            return $refused;
        }

        self::fail('The erasure was not refused.');
    }

    /**
     * A customer, an owner of cards.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function customer(string $id): Reference
    {
        return Reference::of('App\Models\Customer', $id);
    }

    /**
     * The account every charge is on, the owner of its account number.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function account(): Reference
    {
        return Reference::of('App\Models\Account', '7');
    }

    /**
     * The authority every operation of the API is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'gdpr.article_17', 'app:case-118');
    }
}
