<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Proofs, end to end through a capture under the package's encrypter, that a
 * value encrypted for its owner is stored nowhere in plaintext: every form an
 * owner takes (the actor, the subject, a property path, a note's owner and the
 * actor of an encrypted address) is sealed under that owner's key, at its own
 * path, with a key use for each key; the outbox and a spill line hold only the
 * envelope; a field whose owner is absent or erased is dropped and counted,
 * with no reason, the two alike; and a write that fails leaves the plaintext in
 * no spill line, log line or report.
 *
 * It claims no coverage: it pins what a capture leaves behind, across the
 * pipeline, the sealer, the encrypter, the delivery and the store, each of
 * which its own test pins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EncryptionProofsTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, MakesSubjectKeys, SearchesForSecrets;

    /** @var string The code every record here is captured under. */
    private const string CODE = 'billing.card_charged';

    /** @var string The category of the code's definition. */
    private const string CATEGORY = 'billing';

    /** @var string The address every record here is captured from. */
    private const string ADDRESS = '203.0.113.7';

    /**
     * Bind the package's key wrapper and its encrypter, as the provider will,
     * fresh on every resolution, keep reports from the framework and log to
     * nowhere.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app(ConfigRepository::class)->set('logging.default', 'null');
    }

    /**
     * Each form an owner takes is encrypted under that owner's key in the
     * record's tenant and category: the actor's card, the subject's account, a
     * payee's name keyed on the payee property, a customer's note and the
     * actor's address, each sealed at its own path, opening there to its typed
     * plaintext; the stored row holds no plaintext, and each distinct key has
     * its one key use.
     *
     * @return void
     */
    public function testEachOwnerFormIsEncrypted(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.ip', 'encrypt');

        $actor    = Reference::of('App\Models\User', '7');
        $subject  = Reference::of('App\Models\Account', '42');
        $payee    = Reference::of('App\Models\Payee', '5');
        $customer = Reference::of('App\Models\Customer', '9');
        $tenant   = Reference::of('App\Models\Team', '3');

        self::define(
            EventDefinition::for(self::CODE)
                ->category(self::CATEGORY)
                ->retain('amount', 'payee')
                ->encrypt('card', KeyOwner::ACTOR)
                ->encrypt('iban', KeyOwner::SUBJECT)
                ->encrypt('payee_name', 'payee'),
        );

        $pending = AuditLog::event(self::CODE)->by($actor)->on($subject)->forTenant($tenant)->withNote(self::SECRET . '-note', $customer)->withProperties([
            'amount'     => '12.00',
            'card'       => self::SECRET . '-card',
            'iban'       => self::SECRET . '-iban',
            'payee'      => ['type' => $payee->type, 'id' => $payee->id],
            'payee_name' => self::SECRET . '-payee',
        ]);

        $pending->fillClient(self::ADDRESS, null);

        $record = $pending->record();
        $stored = $this->storedEntry($record->id);

        self::assertHoldsNoSecret($stored, 'the stored row');

        $properties = json_decode((string) $stored['properties'], true, 64, JSON_THROW_ON_ERROR);
        $ip         = json_decode((string) $stored['ip'], true, 2, JSON_THROW_ON_ERROR);

        self::assertIsArray($properties);
        self::assertIsArray($ip);

        $sealed = [
            [$properties['card'] ?? null, $actor, ['properties', 'card'], self::SECRET . '-card'],
            [$properties['iban'] ?? null, $subject, ['properties', 'iban'], self::SECRET . '-iban'],
            [$properties['payee_name'] ?? null, $payee, ['properties', 'payee_name'], self::SECRET . '-payee'],
            [$properties['_audit']['note'] ?? null, $customer, ['properties', '_audit', 'note'], self::SECRET . '-note'],
            [$ip, $actor, ['ip'], self::ADDRESS],
        ];

        foreach ($sealed as [$envelope, $owner, $path, $value]) {
            $key = $this->keyOf(new KeyUnit($owner, $tenant, self::CATEGORY));

            self::assertIsArray($envelope, implode('.', $path));
            self::assertSame($key->id, $envelope['k'] ?? null, implode('.', $path));
            self::assertSame(json_encode($value), $this->open($envelope, $key, $record->id, $path), implode('.', $path));
        }

        $reference = $properties['payee'] ?? null;

        self::assertIsArray($reference);

        // A JSON column on MySQL gives its keys back sorted, so the order is
        // not what the record held
        ksort($reference);

        self::assertSame(['id' => '5', 'type' => 'App\Models\Payee'], $reference);
        self::assertSame($this->expectedKeyUses($record->id, $tenant, [$actor, $subject, $payee, $customer]), $this->keyUsesOf($record->id));
    }

    /**
     * A record whose write fails is spilled holding its envelopes and none of
     * the plaintext: the store's failure to write the record's key uses rolls
     * its entry back, and the spill line it leaves carries the envelope.
     *
     * @return void
     */
    public function testASpillLineHoldsOnlyTheEnvelope(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
        app(ConfigRepository::class)->set('audit-log.privacy.key_uses_table', 'audit_missing_key_uses');

        $this->captureLogLines();

        $record = $this->chargeCard(Reference::of('App\Models\User', '7'));
        $lines  = $this->spillLines();

        self::assertCount(1, $lines);
        self::assertHoldsNoSecret($lines, 'the spill line');
        self::assertTrue(self::holdsText($lines, self::envelopeOf($record)['c']), 'The spill line does not hold the envelope.');
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Under the outbox, a record is encrypted at capture: its outbox row, as
     * stored and once its payload is decrypted, holds the envelope and none of
     * the plaintext.
     *
     * @return void
     */
    public function testTheOutboxHoldsOnlyTheEnvelope(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $record = $this->chargeCard(Reference::of('App\Models\User', '7'));
        $row    = $this->outboxRow($record->id);

        self::assertNotNull($row);
        self::assertHoldsNoSecret($row, 'the outbox row');

        $payload = app(StringEncrypter::class)->decryptString((string) $row['payload']);

        self::assertHoldsNoSecret($payload, 'the outbox payload');
        self::assertStringContainsString(self::envelopeOf($record)['c'], $payload);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A field whose owner the record lacks, and one whose owner is erased, are
     * dropped alike: neither is stored in plaintext, each is counted as one
     * omission at its path, and neither record says why, so the two cannot be
     * told apart and no later record about the owner discloses the erasure.
     *
     * @return void
     */
    public function testNoPlaintextIsStoredForAnAbsentOrErasedOwner(): void
    {
        $holder = Reference::of('App\Models\Customer', '9');

        $this->makeSubjectKey($holder, null, self::CATEGORY);
        $this->eraseByHand($holder);

        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->retain('amount', 'holder')->encrypt('card', 'holder'));

        $card   = ['amount' => '12.00', 'card' => self::SECRET . '-card'];
        $absent = AuditLog::event(self::CODE)->withProperties($card)->record();
        $erased = AuditLog::event(self::CODE)->withProperties([...$card, 'holder' => ['type' => $holder->type, 'id' => $holder->id]])->record();

        $omitted = ['omitted' => ['count' => 1, 'paths' => ['card']]];

        self::assertSame(['amount', '_audit'], array_keys($absent->properties ?? []));
        self::assertSame(['amount', 'holder', '_audit'], array_keys($erased->properties ?? []));
        self::assertSame($omitted, $absent->properties['_audit'] ?? null);
        self::assertSame($omitted, $erased->properties['_audit'] ?? null);
        self::assertHoldsNoSecret($this->storedEntry($absent->id), 'the absent owner\'s row');
        self::assertHoldsNoSecret($this->storedEntry($erased->id), 'the erased owner\'s row');
        self::assertSame([], $this->keyUsesOf($absent->id));
        self::assertSame([], $this->keyUsesOf($erased->id));
    }

    /**
     * A write that fails, at a store that quotes the whole record in its
     * failure as a refused insert quotes its bindings, leaves the plaintext in
     * nothing: the spill line holds the envelope, and the reported failure,
     * passed through the framework's own handler, and every line logged hold
     * none of it; what the store saw held the envelope and no plaintext.
     *
     * @return void
     */
    public function testAFailedWriteReportsNoPlaintext(): void
    {
        $framework = app(ExceptionHandler::class);
        $handler   = new RecordingExceptionHandler;
        $quoted    = [];

        app()->instance(ExceptionHandler::class, $handler);
        app()->instance(AuditStore::class, new CallbackStore(static function (FinalisedRecord $record) use (&$quoted): never {
            $quoted[] = json_encode($record->toArray(), JSON_THROW_ON_ERROR);

            throw new \RuntimeException(end($quoted));
        }));

        $this->captureLogLines();

        $record = $this->chargeCard(Reference::of('App\Models\User', '7'));

        foreach ($handler->reports() as $report) {
            $framework->report($report);
        }

        $spills = $this->spillLines();
        $logged = $this->loggedMessages();

        self::assertCount(1, $quoted);
        self::assertHoldsNoSecret($quoted, 'what the store saw');
        self::assertStringContainsString(self::envelopeOf($record)['c'], $quoted[0]);
        self::assertSame([AuditWriteFailedException::class], array_map(static fn (\Throwable $report): string => $report::class, $handler->reports()));
        self::assertHoldsNoSecret($handler->reports(), 'a report');
        self::assertCount(1, $spills);
        self::assertTrue(self::holdsText($spills, self::envelopeOf($record)['c']), 'The spill line does not hold the envelope.');
        self::assertHoldsNoSecret($spills, 'the spill line');
        self::assertCount(2, $logged);
        self::assertHoldsNoSecret($logged, 'a log line');
    }

    /**
     * Capture a charge of a card the actor owns, encrypted under the actor's
     * key, with an amount beside it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function chargeCard(Reference $actor): AuditRecord
    {
        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        return AuditLog::event(self::CODE)->by($actor)->withProperties(['amount' => '12.00', 'card' => self::SECRET . '-card'])->record();
    }

    /**
     * The stored key of the unit, which the test fails without.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function keyOf(KeyUnit $unit): SubjectKeyRow
    {
        $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit->digest()));

        self::assertCount(1, $keys, 'The unit has no key, or more than one.');

        return $keys[0];
    }

    /**
     * The typed plaintext the envelope holds, opened under the key row's data
     * key at the entry and path, in the configured log.
     *
     * @param  array<array-key, int|string>  $envelope
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $path
     * @return string
     */
    private function open(array $envelope, SubjectKeyRow $key, string $entryId, array $path): string
    {
        $dataKey = $this->keyWrapper()->unwrap((string) $key->wrappedKey, (string) $key->wrapKeyId, $key->wrapContext());

        return FieldCipher::open($dataKey, $key->id, (int) ($envelope['v'] ?? 0), (string) ($envelope['c'] ?? ''), $entryId, $path, app(SealSettings::class)->logId());
    }

    /**
     * The key uses the entry should have: one for each distinct key of its
     * owners in the tenant and the category, sorted by key.
     *
     * @param  string  $entryId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     * @return list<array{key_id: string, entry_id: string}>
     */
    private function expectedKeyUses(string $entryId, ?Reference $tenant, array $owners): array
    {
        $keys = array_map(fn (Reference $owner): string => $this->keyOf(new KeyUnit($owner, $tenant, self::CATEGORY))->id, $owners);

        sort($keys, SORT_STRING);

        return array_map(static fn (string $key): array => ['key_id' => $key, 'entry_id' => $entryId], $keys);
    }

    /**
     * The key uses stored for the entry, sorted by key.
     *
     * @param  string  $entryId
     * @return list<array{key_id: string, entry_id: string}>
     */
    private function keyUsesOf(string $entryId): array
    {
        $rows = $this->keyConnection()->table(KeyTables::keyUsesTable())->where('entry_id', $entryId)->orderBy('key_id')->get();

        return array_values(array_map(static fn (object $row): array => ['key_id' => (string) $row->key_id, 'entry_id' => (string) $row->entry_id], $rows->all()));
    }

    /**
     * The stored row of the entry, as the database holds it, which the test
     * fails without.
     *
     * @param  string  $id
     * @return array<string, int|string|null>
     */
    private function storedEntry(string $id): array
    {
        $row = $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->first();

        self::assertNotNull($row, 'The entry is not stored.');

        /** @var array<string, int|string|null> */
        return (array) $row;
    }

    /**
     * The outbox row under the id, as the database holds it, or `null`.
     *
     * @param  string  $id
     * @return ?array<string, int|string|null>
     */
    private function outboxRow(string $id): ?array
    {
        $row = DB::connection(DeliveryTables::outboxConnection())->table(DeliveryTables::outboxTable())->where('id', $id)->first();

        /** @var ?array<string, int|string|null> */
        return $row === null ? null : (array) $row;
    }

    /**
     * The card's envelope in the record, which the test fails without.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array{v: int, k: string, c: string}
     */
    private static function envelopeOf(AuditRecord $record): array
    {
        $envelope = $record->properties['card'] ?? null;

        self::assertIsArray($envelope);
        self::assertIsString($envelope['c'] ?? null);
        self::assertIsString($envelope['k'] ?? null);
        self::assertIsInt($envelope['v'] ?? null);

        return ['v' => $envelope['v'], 'k' => $envelope['k'], 'c' => $envelope['c']];
    }

    /**
     * Make the definition the only one the facade's recorder and the container
     * know, as an application registers it while it boots.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     */
    private static function define(EventDefinition $definition): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define($definition);

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }
}
