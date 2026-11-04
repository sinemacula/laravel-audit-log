<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\WrappingRing;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the package's field encrypter, on whichever engine the
 * suite runs against: every unit of a record looked up in one statement, a
 * unit's first key created through the key creator, an erased owner's and an
 * absent owner's fields dropped, the keys of one entry only, an envelope that
 * opens only at its own entry, path and log, a failure of the key store
 * contained and reported once naming the class alone, and no wrapping secret
 * held.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyEncrypter::class)]
final class SubjectKeyEncrypterTest extends TestCase
{
    use MakesSubjectKeys, SearchesForSecrets;

    /** @var string The code a record encrypting for its actor is captured under. */
    private const string CODE = 'billing.card_charged';

    /** @var string The category every unit here is made in. */
    private const string CATEGORY = 'billing';

    /** @var string The plaintext every value here is sealed as: a string, with its quotes. */
    private const string PLAINTEXT = '"' . self::SECRET . '-4242"';

    /**
     * Bind the package's key wrapper and its encrypter, as the provider will,
     * fresh on every resolution.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
    }

    /**
     * Every unit of the record is looked up in one statement, whatever the
     * order its values come in: two owners of the record, a tenant and a
     * category, three values, and one read of the key store, binding both
     * units, then no creation; each value is sealed under its own owner's key
     * in that tenant and category, never another tenant's.
     *
     * @return void
     */
    public function testOneLookupServesEveryOwnerOfTheRecord(): void
    {
        $tenant = Reference::of('App\Models\Team', '3');
        $first  = Reference::of('App\Models\User', '7');
        $second = Reference::of('App\Models\Customer', '9');

        [$firstKey]  = $this->makeSubjectKey($first, $tenant, self::CATEGORY);
        [$secondKey] = $this->makeSubjectKey($second, $tenant, self::CATEGORY);

        $this->makeSubjectKey($first, Reference::of('App\Models\Team', '4'), self::CATEGORY);

        $statements = $this->keyStatements();
        $encrypter  = $this->encrypter();
        $entryId    = self::entryId();
        $owners     = [$first, $second];

        $envelopes = [
            $encrypter->encrypt($first, self::PLAINTEXT, self::context($entryId, ['properties', 'card'], $owners, $tenant)),
            $encrypter->encrypt($second, self::PLAINTEXT, self::context($entryId, ['properties', 'iban'], $owners, $tenant)),
            $encrypter->encrypt($first, self::PLAINTEXT, self::context($entryId, ['properties', 'iban'], $owners, $tenant)),
        ];

        $lookup = $statements[0] ?? null;

        self::assertCount(1, $statements);
        self::assertInstanceOf(QueryExecuted::class, $lookup);
        self::assertStringContainsString(' in (', $lookup->sql);
        self::assertContains((new KeyUnit($first, $tenant, self::CATEGORY))->digest(), $lookup->bindings);
        self::assertContains((new KeyUnit($second, $tenant, self::CATEGORY))->digest(), $lookup->bindings);
        self::assertSame([$firstKey->id, $secondKey->id, $firstKey->id], array_map(static fn (?array $envelope): ?string => $envelope['k'] ?? null, $envelopes));
        self::assertCount(3, $this->storedSubjectKeys());
    }

    /**
     * A unit with no key is given its first through the key creator, at
     * generation one, live, in the record's tenant and category, and the value
     * is sealed under it; a second value of the owner in the same entry uses
     * the key made, creating no other.
     *
     * @return void
     */
    public function testAFirstOwnerGetsAKeyOnTheSession(): void
    {
        $owner     = Reference::of('App\Models\User', '7');
        $tenant    = Reference::of('App\Models\Team', '3');
        $encrypter = $this->encrypter();
        $entryId   = self::entryId();

        $first  = $encrypter->encrypt($owner, self::PLAINTEXT, self::context($entryId, ['properties', 'card'], [$owner], $tenant));
        $second = $encrypter->encrypt($owner, '42', self::context($entryId, ['properties', 'iban'], [$owner], $tenant));
        $keys   = $this->storedSubjectKeys();

        self::assertCount(1, $keys);

        $key = array_values($keys)[0];

        self::assertSame([1, KeyState::LIVE, (new KeyUnit($owner, $tenant, self::CATEGORY))->digest()], [$key->generation, $key->state, $key->unit]);
        self::assertSame(['App\Models\Team', '3', self::CATEGORY], [$key->tenantType, $key->tenantId, $key->category]);
        self::assertSame([$key->id, $key->id], [$first['k'] ?? null, $second['k'] ?? null]);
        self::assertNotNull($first);
        self::assertSame(self::PLAINTEXT, $this->open($first, $key, $entryId, ['properties', 'card']));
    }

    /**
     * An owner whose latest marker records an erasure is given no key, so its
     * value is dropped; the creator is asked once for the entry, not once per
     * value, and nothing is stored. Through a capture, the field is dropped and
     * counted as omitted, with no reason.
     *
     * @return void
     */
    public function testAnErasedOwnersFieldIsDropped(): void
    {
        $owner = Reference::of('App\Models\User', '7');

        $this->makeSubjectKey($owner, null, self::CATEGORY);
        $this->eraseByHand($owner);

        $markers   = $this->markerReads();
        $encrypter = $this->encrypter();
        $entryId   = self::entryId();

        self::assertNull($encrypter->encrypt($owner, self::PLAINTEXT, self::context($entryId, ['properties', 'card'], [$owner])));
        self::assertNull($encrypter->encrypt($owner, self::PLAINTEXT, self::context($entryId, ['properties', 'iban'], [$owner])));
        self::assertCount(1, $markers);

        $record = $this->captureCardChargedBy($owner);

        self::assertSame(['amount' => '12.00', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['card']]]], $record->properties);
        self::assertCount(1, $this->storedSubjectKeys());
        self::assertFalse(self::holdsText($this->storedEntry($record->id), self::SECRET));
    }

    /**
     * A field whose owner the record does not have is dropped before the
     * encrypter is asked: no key is looked up or made, and the field is counted
     * as omitted, as an erased owner's is.
     *
     * @return void
     */
    public function testAnAbsentOwnersFieldIsDropped(): void
    {
        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->retain('amount')->encrypt('card', KeyOwner::SUBJECT));

        $statements = $this->keyStatements();
        $record     = AuditLog::event(self::CODE)->by(Reference::of('App\Models\User', '7'))->withProperties(['amount' => '12.00', 'card' => self::SECRET . '-4242'])->record();

        self::assertSame(['amount' => '12.00', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['card']]]], $record->properties);
        self::assertCount(0, $statements);
        self::assertSame([], $this->storedSubjectKeys());
        self::assertFalse(self::holdsText($this->storedEntry($record->id), self::SECRET));
    }

    /**
     * A value of another entry starts afresh: its keys are looked up again, so
     * an erasure committed between two records is seen by the second, and by a
     * later value of the first entry too, which is looked up again in turn;
     * nothing of an earlier entry is kept.
     *
     * @return void
     */
    public function testAnotherEntryStartsAfresh(): void
    {
        $owner = Reference::of('App\Models\User', '7');

        [$key] = $this->makeSubjectKey($owner, null, self::CATEGORY);

        $statements = $this->keyStatements();
        $encrypter  = $this->encrypter();
        $first      = self::entryId();
        $second     = self::entryId();

        self::assertSame($key->id, $encrypter->encrypt($owner, self::PLAINTEXT, self::context($first, ['properties', 'card'], [$owner]))['k'] ?? null);
        self::assertSame($key->id, $encrypter->encrypt($owner, self::PLAINTEXT, self::context($second, ['properties', 'card'], [$owner]))['k'] ?? null);
        self::assertCount(2, $statements);

        $this->eraseByHand($owner);

        self::assertNull($encrypter->encrypt($owner, self::PLAINTEXT, self::context($first, ['properties', 'card'], [$owner])));
        self::assertSame($first, self::cachedEntry($encrypter));
        self::assertNull($encrypter->encrypt($owner, self::PLAINTEXT, self::context($second, ['properties', 'card'], [$owner])));
        self::assertSame($second, self::cachedEntry($encrypter));
    }

    /**
     * The envelope opens under its key only at its own entry, path and log: the
     * typed plaintext comes back there, and a copy read at another entry,
     * another path or another log fails to authenticate.
     *
     * @return void
     */
    public function testTheEnvelopeOpensOnlyAtItsEntryAndPath(): void
    {
        $owner    = Reference::of('App\Models\User', '7');
        $entryId  = self::entryId();
        $path     = ['properties', 'items', 0, 'iban'];
        $envelope = $this->encrypter()->encrypt($owner, self::PLAINTEXT, self::context($entryId, $path, [$owner]));
        $key      = array_values($this->storedSubjectKeys())[0];

        self::assertNotNull($envelope);
        self::assertSame(1, $envelope['v']);
        self::assertSame(self::PLAINTEXT, $this->open($envelope, $key, $entryId, $path));

        $elsewhere = [
            'another entry' => [self::entryId(), $path, null],
            'another path'  => [$entryId, ['properties', 'items', 1, 'iban'], null],
            'another log'   => [$entryId, $path, 'other-log'],
        ];

        foreach ($elsewhere as $where => [$entry, $at, $log]) {
            try {
                $this->open($envelope, $key, $entry, $at, $log);

                self::fail(sprintf('The envelope opened at %s.', $where));
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('The envelope does not open under its key at its entry and path.', $exception->getMessage(), $where);
            }
        }
    }

    /**
     * A key the store cannot vouch for fails the encrypter, which the sealer
     * contains: the record is stored with both its encrypted fields dropped,
     * the failure is reported once, naming the encrypter's class alone and
     * chaining nothing, and neither the plaintext nor the data key is in the
     * report, its message, its trace or its frames' arguments.
     *
     * @return void
     */
    public function testAStoreFailureIsContainedAndReportedOnce(): void
    {
        $owner = Reference::of('App\Models\User', '7');

        [$key, $dataKey] = $this->makeSubjectKey($owner, null, self::CATEGORY);

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['hmac' => str_repeat('0', 64)]);

        $handler = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $handler);

        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->encrypt('card', KeyOwner::ACTOR)->encrypt('iban', KeyOwner::ACTOR));

        $record = AuditLog::event(self::CODE)->by($owner)->withProperties(['card' => self::SECRET . '-4242', 'iban' => self::SECRET . '-GB29'])->record();

        self::assertSame(['_audit' => ['omitted' => ['count' => 2, 'paths' => ['card', 'iban']]]], $record->properties);
        self::assertCount(1, $handler->reports());

        $report = $handler->reports()[0];

        self::assertInstanceOf(FieldEncryptionFailedException::class, $report);
        self::assertSame('The field encrypter ' . SubjectKeyEncrypter::class . ' failed, so the value was dropped.', $report->getMessage());
        self::assertNull($report->getPrevious());
        self::assertNotSame([], $report->getTrace());
        self::assertHoldsNoSecret($report, 'the report');
        self::assertFalse(self::holdsText($report, $dataKey), 'The data key was found in the report.');
        self::assertFalse(self::holdsText($this->storedEntry($record->id), self::SECRET));
    }

    /**
     * The encrypter holds the data keys of its entry and nothing more: no
     * wrapping key's secret, and no key derived from it, is anywhere it reaches
     * once it has unwrapped a key, while the data key it unwrapped is, which
     * shows the search reaches its state.
     *
     * @return void
     */
    public function testNoWrappingSecretIsHeld(): void
    {
        $owner = Reference::of('App\Models\User', '7');

        [, $dataKey] = $this->makeSubjectKey($owner, null, self::CATEGORY);

        $encrypter = $this->encrypter();

        self::assertNotNull($encrypter->encrypt($owner, self::PLAINTEXT, self::context(self::entryId(), ['properties', 'card'], [$owner])));

        $secret = app(WrappingRing::class)->current()->secret();

        self::assertTrue(self::holdsText($encrypter, $dataKey), 'The search did not reach the data key the encrypter holds.');
        self::assertFalse(self::holdsText($encrypter, $secret), 'The wrapping secret was found in the encrypter.');
        self::assertFalse(self::holdsText($encrypter, hash_hkdf('sha256', $secret, 32, LocalKeyWrapper::AES_KEY_INFO, '')), 'The wrapping key was found in the encrypter.');
    }

    /**
     * The package's encrypter, built by the container.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter
     */
    private function encrypter(): SubjectKeyEncrypter
    {
        $encrypter = app(FieldEncrypter::class);

        self::assertInstanceOf(SubjectKeyEncrypter::class, $encrypter);

        return $encrypter;
    }

    /**
     * Capture a charge of a card the actor owns, encrypted under the actor's
     * key, with an amount beside it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function captureCardChargedBy(Reference $actor): AuditRecord
    {
        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        return AuditLog::event(self::CODE)->by($actor)->withProperties(['amount' => '12.00', 'card' => self::SECRET . '-4242'])->record();
    }

    /**
     * The typed plaintext the envelope holds, opened under the key row's data
     * key at the entry and path, in the configured log or the one given.
     *
     * @param  array{v: int, k: string, c: string}  $envelope
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $path
     * @param  ?string  $logId
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private function open(array $envelope, SubjectKeyRow $key, string $entryId, array $path, ?string $logId = null): string
    {
        $dataKey = $this->keyWrapper()->unwrap((string) $key->wrappedKey, (string) $key->wrapKeyId, $key->wrapContext());

        return FieldCipher::open($dataKey, $envelope['k'], $envelope['v'], $envelope['c'], $entryId, $path, $logId ?? app(SealSettings::class)->logId());
    }

    /**
     * Each statement run on the subject keys table from here on, on any
     * connection.
     *
     * @return \ArrayObject<int, \Illuminate\Database\Events\QueryExecuted>
     */
    private function keyStatements(): \ArrayObject
    {
        return self::statementsOn(KeyTables::subjectKeysTable());
    }

    /**
     * Each read of the owner markers from here on, on any connection.
     *
     * @return \ArrayObject<int, \Illuminate\Database\Events\QueryExecuted>
     */
    private function markerReads(): \ArrayObject
    {
        return self::statementsOn(KeyTables::ownerErasuresTable());
    }

    /**
     * The stored row of the entry, as the database holds it.
     *
     * @param  string  $id
     * @return ?object
     */
    private function storedEntry(string $id): ?object
    {
        return $this->keyConnection()->table(EntrySettings::table())->where('id', $id)->first();
    }

    /**
     * Each statement run on the table from here on, on any connection.
     *
     * @param  string  $table
     * @return \ArrayObject<int, \Illuminate\Database\Events\QueryExecuted>
     */
    private static function statementsOn(string $table): \ArrayObject
    {
        /** @var \ArrayObject<int, \Illuminate\Database\Events\QueryExecuted> $statements */
        $statements = new \ArrayObject;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($statements, $table): void {
            if (!str_contains($query->sql, $table)) {
                return;
            }

            $statements->append($query);
        });

        return $statements;
    }

    /**
     * The entry whose keys the encrypter holds, read from its state.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter  $encrypter
     * @return ?string
     */
    private static function cachedEntry(SubjectKeyEncrypter $encrypter): ?string
    {
        $entryId = (new \ReflectionProperty(SubjectKeyEncrypter::class, 'entryId'))->getValue($encrypter);

        self::assertTrue($entryId === null || is_string($entryId));

        return $entryId;
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

    /**
     * A context at the path, for the owners, in the configured log, the tenant
     * given and the category every unit here is made in.
     *
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $path
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldContext
     */
    private static function context(string $entryId, array $path, array $owners, ?Reference $tenant = null): FieldContext
    {
        return new FieldContext($entryId, $path, app(SealSettings::class)->logId(), $tenant, self::CATEGORY, $owners);
    }

    /**
     * A fresh entry id.
     *
     * @return string
     */
    private static function entryId(): string
    {
        return Str::uuid7()->toString();
    }
}
