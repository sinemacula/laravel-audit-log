<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for the field reader that opens what the package's encrypter
 * sealed: a live or superseded key reveals each field's typed value; a key is
 * erased only when a verified erasure row of this log, read by the id the key
 * names, lists it as destroyed; an unknown, substituted, unjournalled or
 * unwrappable key, and an envelope that fails to open or decode, are
 * unreadable; the keys are read by id on the writer in one statement, the
 * journal once more only for a page holding an erased key; the answers keep the
 * order given; and nothing is kept from one page to the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyFieldReader::class)]
final class SubjectKeyFieldReaderTest extends TestCase
{
    use InteractsWithReadWriteSplit, MakesSubjectKeys;

    /** @var list<string> The migrations a split's two databases are given, beside the entries. */
    private const array SPLIT_MIGRATIONS = [
        '2026_11_02_000700_create_audit_log_lifecycle_table.php',
        '2026_11_02_001100_create_audit_log_subject_keys_table.php',
        '2026_11_02_001200_create_audit_log_owner_erasures_table.php',
        '2026_11_02_001300_create_audit_log_key_uses_table.php',
    ];

    /** @var string An id no key or journal row has. */
    private const string UNKNOWN_ID = '01932b4e-0000-7000-8000-00000000dead';

    /** @var list<string> The path every field is sealed at, unless a test gives another. */
    private const array CARD = ['properties', 'card'];

    /** @var string What a field reads as when its key was destroyed by a verified erasure. */
    private const string ERASED = '[ERASED]';

    /** @var string What a field reads as when it cannot be read. */
    private const string UNREADABLE = '[UNREADABLE]';

    /** @var list<string> The statements run since the test began listening. */
    private array $statements = [];

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * A live key reveals each field as the typed value it was sealed as, a
     * string `true` apart from the boolean, and a map with its maps as arrays;
     * a superseded key still reveals what it sealed.
     *
     * @return void
     */
    public function testALiveKeyRevealsTheTypedValue(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $values = ['4242', 'true', true, 42, null, ['a' => 1, 'b' => ['x', 2]], ''];
        $fields = [];

        foreach ($values as $index => $value) {
            $path     = ['properties', 'values', $index];
            $fields[] = self::field($entry, $path, $this->sealEnvelope($dataKey, $key->id, $value, $entry, $path));
        }

        $readings = $this->reader()->readAll($fields);

        self::assertSame($values, array_map(static fn (FieldReading $reading): mixed => $reading->value, $readings));
        self::assertSame(array_fill(0, count($values), null), array_map(static fn (FieldReading $reading): mixed => $reading->state, $readings));

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['state' => KeyState::SUPERSEDED->value]);

        self::assertSame($values, array_map(static fn (FieldReading $reading): mixed => $reading->display(), $this->reader()->readAll($fields)));
    }

    /**
     * A tombstoned key is erased only when the erasure row it names is an
     * erasure of this log, whose payload is its digest's and whose signature
     * verifies under a key the ring holds, and lists the key as destroyed: a
     * row whose payload, HMAC or signing key was changed, a row of another kind
     * listing it, and a verified erasure of another owner leave it unreadable.
     *
     * @return void
     */
    public function testErasedNeedsAVerifiedErasureRowListingTheKey(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $other = Reference::of('App\Models\User', '43');
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $this->makeSubjectKey($other);

        $field   = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));
        $erasure = $this->eraseByHand($owner);

        self::assertSame([self::ERASED], $this->displays([$field]));

        $payload = $erasure->payloadMap() ?? [];
        $tampers = [
            'its payload changed' => ['payload' => CanonicalEncoder::encode(['edited' => true] + $payload)],
            'its hmac changed'    => ['hmac' => str_repeat('a', 64)],
            'an unknown key'      => ['key_id' => 'retired'],
        ];

        foreach ($tampers as $label => $tampered) {
            $this->tamperJournal($erasure->sequence, $tampered);

            self::assertSame([self::UNREADABLE], $this->displays([$field]), $label);

            $this->tamperJournal($erasure->sequence, $erasure->toRow());
        }

        self::assertSame([self::ERASED], $this->displays([$field]));

        $holdId = '01932b4e-a000-7000-8000-000000000001';
        $hold   = $this->journalRow(JournalKind::HOLD, ['hold_id' => $holdId, 'basis' => 'legal_claim', 'review_by' => null, 'destroyed' => [['key_id' => $key->id]]], $holdId);
        $others = $this->eraseByHand($other);

        foreach (['a hold' => $hold->id, 'another owner\'s erasure' => $others->id] as $label => $erasureId) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['erasure_id' => $erasureId]);

            self::assertSame([self::UNREADABLE], $this->displays([$field]), $label);
        }
    }

    /**
     * A key with no wrapped key is unreadable without a verified erasure row
     * listing it: one tombstoned with the id of no journal row, a live one
     * whose wrapped key was removed, and an erased one still holding its
     * wrapped key.
     *
     * @return void
     */
    public function testANullKeyWithoutAnErasureRowIsUnreadable(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $field = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));

        $tampers = [
            'tombstoned with no row'     => ['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => self::UNKNOWN_ID],
            'live with no wrapped key'   => ['wrapped_key' => null],
            'erased keeping its key'     => ['state' => KeyState::ERASED->value, 'erasure_id' => self::UNKNOWN_ID],
            'tombstoned with no erasure' => ['state' => KeyState::ERASED->value, 'wrapped_key' => null],
        ];

        foreach ($tampers as $label => $tampered) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($tampered);

            self::assertSame([self::UNREADABLE], $this->displays([$field]), $label);

            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($key->toRow());
        }

        self::assertSame(['4242'], $this->displays([$field]));
    }

    /**
     * A key row that was substituted is unreadable: one whose HMAC, owner,
     * generation or creation time was changed fails its signature, one naming a
     * signing key the ring does not hold cannot be judged, and one holding
     * another key's wrapped key, or naming another wrapping key, fails to
     * unwrap against its own row.
     *
     * @return void
     */
    public function testASubstitutedKeyRowIsUnreadable(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $moved = Reference::of('App\Models\User', '43');
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey($owner);
        [$other]         = $this->makeSubjectKey($moved);

        $field = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));

        $tampers = [
            'its hmac'             => ['hmac' => str_repeat('a', 64)],
            'its owner'            => ['owner_id' => '44', 'unit' => SubjectKeyRow::unitOf('App\Models\User', '44', null, null, self::KEY_CATEGORY)],
            'its generation'       => ['generation' => 2],
            'its creation'         => ['created_at' => '2020-01-01 00:00:00.000000'],
            'its signing key'      => ['key_id' => 'retired'],
            'another wrapped key'  => ['wrapped_key' => $other->wrappedKey],
            'another wrapping key' => ['wrap_key_id' => 'retired-wrap'],
        ];

        foreach ($tampers as $label => $tampered) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($tampered);

            self::assertSame([self::UNREADABLE], $this->displays([$field]), $label);

            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($key->toRow());
        }

        self::assertSame(['4242'], $this->displays([$field]));
    }

    /**
     * A field whose key no row has is unreadable, as is one naming a key by
     * anything but its canonical lower-case id; a page naming no canonical id
     * asks the key store nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnknownKeyIsUnreadable(): void
    {
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $unknown = self::field($entry, self::CARD, $this->sealEnvelope(random_bytes(32), self::UNKNOWN_ID, '4242', $entry, self::CARD));
        $upper   = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, strtoupper($key->id), '4242', $entry, self::CARD));
        $named   = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, 'key-1', '4242', $entry, self::CARD));

        self::assertSame([self::UNREADABLE, self::UNREADABLE, self::UNREADABLE], $this->displays([$unknown, $upper, $named]));

        $this->listen();

        self::assertSame([self::UNREADABLE], $this->displays([$named]));
        self::assertSame([], $this->statements());
    }

    /**
     * An envelope that does not open under its key is unreadable: one of
     * another version, one whose ciphertext was altered, one sealed under
     * another data key naming this key, and one whose plaintext is not typed
     * plaintext, malformed or a float.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEnvelopeThatFailsToOpenOrDecodeIsUnreadable(): void
    {
        $entry = self::entryId();
        $logId = app(SealSettings::class)->logId();

        [$key, $dataKey] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $sealed = $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD);

        $envelopes = [
            'another version'     => ['v' => 2]                           + $sealed,
            'an altered body'     => ['c' => self::altered($sealed['c'])] + $sealed,
            'another data key'    => $this->sealEnvelope(random_bytes(32), $key->id, '4242', $entry, self::CARD),
            'malformed plaintext' => FieldCipher::seal($dataKey, $key->id, 'not json', $entry, self::CARD, $logId),
            'a float'             => FieldCipher::seal($dataKey, $key->id, '1.5', $entry, self::CARD, $logId),
        ];

        foreach ($envelopes as $label => $envelope) {
            self::assertSame([self::UNREADABLE], $this->displays([self::field($entry, self::CARD, $envelope)]), $label);
        }

        self::assertSame(['4242'], $this->displays([self::field($entry, self::CARD, $sealed)]));
    }

    /**
     * A wrapper that fails leaves the fields of the keys it fails to unwrap
     * unreadable without failing the page: one that throws, for whatever reason
     * and with whatever message, and one that answers anything but a data key's
     * length.
     *
     * @return void
     */
    public function testAWrapperThatFailsLeavesTheFieldsUnreadable(): void
    {
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $field = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));

        foreach (['throws' => null, 'answers a short key' => substr($dataKey, 0, 16), 'answers a long key' => $dataKey . 'x'] as $label => $answer) {
            app()->instance(KeyWrapper::class, self::wrapperAnswering($answer));

            self::assertSame([self::UNREADABLE], $this->displays([$field]), $label);
        }

        app()->instance(KeyWrapper::class, self::wrapperAnswering($dataKey));

        self::assertSame(['4242'], $this->displays([$field]));
    }

    /**
     * Keys are read through the storage connection's writer, never a replica
     * lagging behind it: a key and an erasure the replica has not seen are
     * still found, so a field reveals and an erased one reads erased.
     *
     * @return void
     */
    public function testAReplicaIsNeverReadForAKey(): void
    {
        $this->useKeysOnASplit();

        $owner  = Reference::of('App\Models\User', '42');
        $erased = Reference::of('App\Models\User', '43');
        $entry  = self::entryId();

        [$key, $dataKey]      = $this->makeSubjectKey($owner);
        [$gone, $goneDataKey] = $this->makeSubjectKey($erased);

        $this->eraseByHand($erased);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(KeyTables::subjectKeysTable())->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(LifecycleTables::journalTable())->count());

        $fields = [
            self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD)),
            self::field($entry, ['properties', 'pin'], $this->sealEnvelope($goneDataKey, $gone->id, '1234', $entry, ['properties', 'pin'])),
        ];

        self::assertSame(['4242', self::ERASED], $this->displays($fields));
    }

    /**
     * The answers are in the order the fields were given, one for each, a key's
     * fields and a repeated field included, whatever order the key store
     * answers in; a page with no field asks nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheAnswersAreInTheOrderGiven(): void
    {
        $owner  = Reference::of('App\Models\User', '42');
        $erased = Reference::of('App\Models\User', '43');
        $entry  = self::entryId();

        [$key, $dataKey]      = $this->makeSubjectKey($owner);
        [$gone, $goneDataKey] = $this->makeSubjectKey($erased);

        $this->eraseByHand($erased);

        $card    = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));
        $pin     = self::field($entry, ['properties', 'pin'], $this->sealEnvelope($goneDataKey, $gone->id, '1234', $entry, ['properties', 'pin']));
        $count   = self::field($entry, ['context', 'count'], $this->sealEnvelope($dataKey, $key->id, 3, $entry, ['context', 'count']));
        $unknown = self::field($entry, ['ip'], $this->sealEnvelope(random_bytes(32), self::UNKNOWN_ID, '203.0.113.9', $entry, ['ip']));

        self::assertSame(['4242', self::ERASED, self::UNREADABLE, 3, self::ERASED, '4242'], $this->displays([$card, $pin, $unknown, $count, $pin, $card]));
        self::assertSame([3, self::UNREADABLE, '4242'], $this->displays([$count, $unknown, $card]));

        $this->listen();

        self::assertSame([], $this->reader()->readAll([]));
        self::assertSame([], $this->statements());
    }

    /**
     * Each page reads the key store afresh, so the same reader reveals a field
     * on one page and reads it erased on the next once an erasure committed in
     * between; the reader holds nothing but what it was built with.
     *
     * @return void
     */
    public function testNothingIsKeptBetweenPages(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $entry = self::entryId();

        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $reader = $this->reader();
        $field  = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));

        $this->listen();

        self::assertSame('4242', $reader->readAll([$field])[0]->display());
        self::assertCount(1, $this->statements());

        $this->eraseByHand($owner);

        $this->statements = [];

        self::assertSame(self::ERASED, $reader->readAll([$field])[0]->display());
        self::assertCount(2, $this->statements());

        $properties = array_map(static fn (\ReflectionProperty $property): string => $property->getName(), (new \ReflectionClass(SubjectKeyFieldReader::class))->getProperties());

        self::assertSame(['keys', 'keySigner', 'wrapper', 'journalSigner', 'settings'], $properties);
    }

    /**
     * An erasure row of another log never makes a key of this one erased, even
     * signed and listing the key: the key reads unreadable, and erased again
     * once the log is the row's.
     *
     * @return void
     */
    public function testAnErasureRowOfAnotherLogDoesNotMakeItErased(): void
    {
        $config = app(ConfigRepository::class);
        $owner  = Reference::of('App\Models\User', '42');
        $entry  = self::entryId();
        $logId  = $config->get('audit-log.integrity.log_id');

        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $field = self::field($entry, self::CARD, $this->sealEnvelope($dataKey, $key->id, '4242', $entry, self::CARD));

        $config->set('audit-log.integrity.log_id', 'app-other-1');

        $this->eraseByHand($owner);

        $config->set('audit-log.integrity.log_id', $logId);

        self::assertNotSame('app-other-1', app(SealSettings::class)->logId());
        self::assertSame([self::UNREADABLE], $this->displays([$field]));

        $config->set('audit-log.integrity.log_id', 'app-other-1');

        self::assertSame([self::ERASED], $this->displays([$field]));
    }

    /**
     * A page's keys are one statement, however many fields and keys it holds;
     * the journal is read once more only when the page holds an erased key,
     * once however many erased keys and erasures it holds.
     *
     * @return void
     */
    public function testOneKeyReadAndOneJournalReadServeThePage(): void
    {
        $owners = array_map(static fn (int $id): Reference => Reference::of('App\Models\User', (string) $id), [41, 42, 43, 44]);
        $entry  = self::entryId();
        $fields = [];

        foreach ($owners as $index => $owner) {
            [$key, $dataKey] = $this->makeSubjectKey($owner);

            $path     = ['properties', 'owners', $index];
            $fields[] = self::field($entry, $path, $this->sealEnvelope($dataKey, $key->id, "value {$index}", $entry, $path));
        }

        $this->listen();

        self::assertSame(['value 0', 'value 1', 'value 2', 'value 3'], $this->displays($fields));
        self::assertCount(1, $this->statements());
        self::assertStringContainsString(KeyTables::subjectKeysTable(), $this->statements()[0]);

        $this->eraseByHand($owners[0]);
        $this->eraseByHand($owners[1]);

        $this->statements = [];

        self::assertSame([self::ERASED, self::ERASED, 'value 2', 'value 3'], $this->displays($fields));
        self::assertCount(2, $this->statements());
        self::assertStringContainsString(KeyTables::subjectKeysTable(), $this->statements()[0]);
        self::assertStringContainsString(LifecycleTables::journalTable(), $this->statements()[1]);
    }

    /**
     * The reader the container builds, the package's own key wrapper bound
     * first when none is.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader
     */
    private function reader(): SubjectKeyFieldReader
    {
        $this->keyWrapper();

        return app(SubjectKeyFieldReader::class);
    }

    /**
     * What each field shows once a fresh reader reads them as one page.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<array<array-key, mixed>|scalar|null>
     */
    private function displays(array $fields): array
    {
        return array_map(static fn (FieldReading $reading): array|bool|float|int|string|null => $reading->display(), $this->reader()->readAll($fields));
    }

    /**
     * A wrapper whose every unwrap answers the data key given, or throws when
     * none is, and which never wraps.
     *
     * @param  ?string  $answer
     * @return \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper
     */
    private static function wrapperAnswering(#[\SensitiveParameter] ?string $answer): KeyWrapper
    {
        return new readonly class ($answer) implements KeyWrapper {
            /**
             * Constructor.
             *
             * @param  ?string  $answer
             */
            public function __construct(

                /** What every unwrap answers; `null` to throw. */
                #[\SensitiveParameter]
                private ?string $answer,
            ) {}

            /**
             * The one wrapping key.
             *
             * @return string
             */
            #[\Override]
            public function currentKeyId(): string
            {
                return 'outage';
            }

            /**
             * Never wraps.
             *
             * @param  string  $dataKey
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
            {
                throw new \RuntimeException('The key service is unreachable.');
            }

            /**
             * The answer, or a failure naming the wrapped key when there is
             * none.
             *
             * @param  string  $wrapped
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
            {
                return $this->answer ?? throw new \RuntimeException("The key service is unreachable for {$wrapped}.");
            }
        };
    }

    /**
     * The field the envelope is at the segments of the entry, as the projector
     * builds it.
     *
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $segments
     * @param  array{v: int, k: string, c: string}  $envelope
     * @return \SineMacula\Laravel\AuditLog\Privacy\EncryptedField
     */
    private static function field(string $entryId, array $segments, array $envelope): EncryptedField
    {
        $field = EncryptedField::fromEnvelope($entryId, $segments, $envelope);

        self::assertNotNull($field, 'The envelope is not well formed.');

        return $field;
    }

    /**
     * A fresh entry id, as the pipeline mints one.
     *
     * @return string
     */
    private static function entryId(): string
    {
        return Str::uuid7()->toString();
    }

    /**
     * The ciphertext with the first byte after its nonce flipped, still strict
     * base64url of the same length.
     *
     * @param  string  $ciphertext
     * @return string
     */
    private static function altered(string $ciphertext): string
    {
        $bytes = base64_decode(strtr($ciphertext, '-_', '+/'), true);

        self::assertIsString($bytes);

        $bytes[FieldCipher::NONCE_BYTES] = chr(ord($bytes[FieldCipher::NONCE_BYTES]) ^ 0x01);

        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Put the storage connection on a read/write split of two SQLite files,
     * each given the journal and the key tables, so a key made through the
     * split lands on the primary alone.
     *
     * @return void
     */
    private function useKeysOnASplit(): void
    {
        $this->useReadWriteSplit();

        $config = app(ConfigRepository::class);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);

            foreach (self::SPLIT_MIGRATIONS as $file) {
                $migration = require dirname(__DIR__, 3) . '/database/migrations/' . $file;

                self::assertIsObject($migration);
                self::assertTrue(method_exists($migration, 'up'));

                $migration->up();
            }
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);

        self::assertSame(self::SPLIT_CONNECTION, StorageConnection::name());
    }

    /**
     * The statements run since the test began listening, or since they were
     * last forgotten.
     *
     * @return list<string>
     */
    private function statements(): array
    {
        return $this->statements;
    }

    /**
     * Record every statement any connection runs from now on.
     *
     * @return void
     */
    private function listen(): void
    {
        $this->statements = [];

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }
}
