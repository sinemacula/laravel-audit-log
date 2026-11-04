<?php

declare(strict_types = 1);

namespace Tests\Integration\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Integration tests for erasure on the engine the suite runs against, on the
 * provider's own bindings: a record about two owners keeps the other owner's
 * fragment revealed once one owner is erased, with the erased key tombstoned
 * under its journal row, the owner marked at its floor and the entries counted;
 * an erased owner's new field is dropped and no key is made for it; and the
 * log, sealed before and after the erasure, verifies with its key store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Eraser::class)]
#[CoversClass(AuditLifecycle::class)]
final class PrivacyEnginesTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, SearchesForSecrets;

    /** @var string The code a card charge is captured under, sealing the card for the actor and the account for the subject. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var string The account number every charge carries. */
    private const string IBAN = 'GB29NWBK60161331926819';

    /**
     * Freeze the clock, report to a recording handler, and define the charge on
     * a recorder of the test's own, behind the facade.
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
     * Erasing the actor of a record about two owners destroys the actor's key
     * alone: the key is erased, unwrapped and tombstoned under the erasure's
     * journal row, the owner is marked erased at its floor, one entry is
     * counted, and a revealing read shows the actor's card `[ERASED]` and the
     * account's number, in that record and in one about the account alone.
     *
     * @return void
     */
    public function testATwoOwnerErasureOnEachEngine(): void
    {
        $both    = $this->charge(self::customer());
        $account = AuditLog::event(self::CHARGE)->on(self::account())->withProperties(['amount' => '3.00', 'iban' => self::IBAN])->record()->id;

        $this->later();

        $result = AuditLog::lifecycle()->erase(self::customer(), self::authority());

        self::assertSame([ErasureStatus::COMPLETE, 1, 0, 1], [$result->status, $result->keysDestroyed, $result->keysKept, $result->entriesAffected]);

        $keys = $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('owner_type', 'App\Models\Customer')->get(['state', 'wrapped_key', 'erasure_id'])->all();

        self::assertCount(1, $keys);
        self::assertSame(['erased', null, $result->erasureId], array_values((array) $keys[0]));

        $marker = (array) $this->keyConnection()->table(KeyTables::ownerErasuresTable())->where('owner_type', 'App\Models\Customer')->where('owner_id', '42')->first();

        self::assertSame(['erased', 1, $result->erasureId], [$marker['transition'] ?? null, (int) ($marker['generation_floor'] ?? 0), $marker['id'] ?? null]);
        self::assertSame(1, $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('state', 'live')->count());

        $this->revealEverything();

        $shown = $this->shown([$both, $account]);

        self::assertSame([self::ERASED, self::IBAN], [$shown[$both]->properties['card'] ?? null, $shown[$both]->properties['iban'] ?? null]);
        self::assertSame(self::IBAN, $shown[$account]->properties['iban'] ?? null);
    }

    /**
     * Once the owner is erased a new card of theirs is dropped and counted, no
     * key is made for the owner, and the account's number is still sealed
     * beside it.
     *
     * @return void
     */
    public function testAnErasedOwnersNewFieldIsDroppedOnEachEngine(): void
    {
        $this->charge(self::customer());

        AuditLog::lifecycle()->erase(self::customer(), self::authority());

        $charged = ['amount' => '9.00', 'card' => self::SECRET . '-5555', 'iban' => self::IBAN];
        $record  = AuditLog::event(self::CHARGE)->by(self::customer())->on(self::account())->withProperties($charged)->record();

        self::assertSame(['card'], $record->properties['_audit']['omitted']['paths'] ?? null);
        self::assertIsArray($record->properties['iban'] ?? null);
        self::assertSame(1, $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('owner_type', 'App\Models\Customer')->count());
        self::assertHoldsNoSecret($record->properties, 'the record\'s properties');
    }

    /**
     * A log sealed before an erasure and after it verifies, its key store
     * included: both owners' keys verified, the erased one counted, and no
     * finding.
     *
     * @return void
     */
    public function testVerifyAfterErasureOnEachEngine(): void
    {
        $this->charge(self::customer());

        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]));

        AuditLog::lifecycle()->erase(self::customer(), self::authority());

        $this->later();
        $this->charge(Reference::of('App\Models\Customer', '43'));

        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]));

        $exit    = Artisan::call('audit-log:verify');
        $printed = Artisan::output();

        self::assertSame(0, $exit, $printed);
        self::assertMatchesRegularExpression('/^Keys: 3 verified, 1 erased, 0 findings\.$/m', $printed);
        self::assertStringContainsString('Verification passed.', $printed);
    }

    /**
     * Capture a charge of a card by the customer on the account, and return its
     * id; the clock moves on a second after it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $customer
     * @return string
     */
    private function charge(Reference $customer): string
    {
        $id = AuditLog::event(self::CHARGE)->by($customer)->on(self::account())->withProperties(['amount' => '12.00', 'card' => '4242', 'iban' => self::IBAN])->record()->id;

        $this->later();

        return $id;
    }

    /**
     * The entries with the ids, as one page of the trail shows them to the
     * viewer, by id; the test fails without any of them.
     *
     * @param  list<string>  $ids
     * @return array<string, \SineMacula\Laravel\AuditLog\Querying\TrailEntry>
     */
    private function shown(array $ids): array
    {
        $shown = [];

        foreach (AuditLog::trail()->visibleTo($this->viewer())->cursorPaginate(100)->entries as $entry) {
            $shown[$entry->id] = $entry;
        }

        foreach ($ids as $id) {
            self::assertInstanceOf(TrailEntry::class, $shown[$id] ?? null, "The page does not show {$id}.");
        }

        return $shown;
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
     * The customer every test erases.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function customer(): Reference
    {
        return Reference::of('App\Models\Customer', '42');
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
     * The authority every erasure is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'gdpr.article_17', 'app:case-118');
    }
}
