<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Contributors\GarbageIpContributor;
use Tests\Fixtures\Contributors\SecretFillingContributor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * End-to-end tests for the capture pipeline's minimising: the record a capture
 * returns is the record the store holds, on either way of writing it, and
 * nothing is stored when minimising fails. Hashes correlate within their own
 * domain and not across two, every handling of a definition reaches the row,
 * and the IP mode applies to the address of a real request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(RecordMinimiser::class)]
final class CaptureMinimisationTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code most tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The root key every golden value below was computed under. */
    private const string ROOT_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The hash of `alice@example.com` under the root key, as a pseudonym. */
    private const string ALICE_PSEUDONYM = 'bddef478b371e305:bb1b2053d57f40d75b983080b46ba3adb13da822fc435d7df67188df4e4b2a6c';

    /** @var string The hash of `alice@example.com` under the root key, as an identifier. */
    private const string ALICE_IDENTIFIER_HASH = '13f5820b5aa0c097:680a1e05e07bcd260a8f8eda495c167100f4413f08ac4a5d980061e30cd51abf';

    /** @var string The address a request comes from. */
    private const string CLIENT_IP = '203.0.113.7';

    /** @var string The IP mode's setting. */
    private const string IP_MODE = 'audit-log.redaction.ip';

    /**
     * Surface a failure inside a route, and fix the root key.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();

        app(ConfigRepository::class)->set('audit-log.redaction.key', self::ROOT_KEY);
    }

    /**
     * The fake holds the very record the capture returned, already minimised.
     *
     * @return void
     */
    public function testTheFakeHoldsTheMinimisedRecord(): void
    {
        $fake = FakeAuditStore::fake();

        $record = AuditLog::event(self::CODE)->withProperties(['amount' => '1200.00', 'password' => 's3cr3t'])->record();

        self::assertSame([$record], $fake->recorded());
        self::assertSame(['amount' => '1200.00', 'password' => Redactor::MARKER], $fake->recorded()[0]->properties);
    }

    /**
     * A record written after commit reads back from its row as the record the
     * capture returned before the commit.
     *
     * @return void
     */
    public function testTheAfterCommitRowEqualsTheReturnedRecord(): void
    {
        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $record = self::minimisedPending()->record();

        self::assertSame(0, $this->entryCount());

        $connection->commit();

        $this->assertTheRowEquals($record);
    }

    /**
     * A record written immediately reads back from its row as the record the
     * capture returned.
     *
     * @return void
     */
    public function testAnImmediateRowEqualsTheReturnedRecord(): void
    {
        $this->assertTheRowEquals(self::minimisedPending()->immediately()->record());
    }

    /**
     * A minimiser's failure stores no row and leaves nothing waiting on the
     * transaction, so a commit writes nothing either.
     *
     * @return void
     */
    public function testNothingUnminimisedIsStoredWhenMinimisingFails(): void
    {
        app(ConfigRepository::class)->set(self::IP_MODE, 'partial');

        $connection = $this->storageConnection();

        $connection->beginTransaction();

        try {
            AuditLog::event(self::CODE)->withProperties(['password' => 's3cr3t'])->record();

            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.', $exception->getMessage());
        }

        $connection->commit();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A pseudonymised field and an identifier of the same person share neither
     * their fingerprint nor their hash, so a stored field cannot be joined to a
     * sign-in.
     *
     * @return void
     */
    public function testAPseudonymisedFieldDoesNotCorrelateWithAnIdentifierHash(): void
    {
        self::useDefinition(EventDefinition::for(self::CODE)->pseudonymise('email'));

        $record = AuditLog::event(self::CODE)->withIdentifier('alice@example.com')->withProperties(['email' => 'alice@example.com'])->record();

        self::assertSame(['email' => self::ALICE_PSEUDONYM, '_audit' => ['identifier_hash' => self::ALICE_IDENTIFIER_HASH]], $record->properties);
        self::assertSame($record->properties, $this->storedProperties($record->id));
    }

    /**
     * Failed sign-ins for one identifier share one hash, whatever its case or
     * padding, and another identifier has its own.
     *
     * @return void
     */
    public function testFailedSignInsCorrelateByIdentifierHash(): void
    {
        $hashes = [];

        foreach (['alice@example.com', 'Alice@Example.COM', '  alice@example.com '] as $identifier) {
            $record = AuditLog::event('app.sign_in_failed')->withIdentifier($identifier)->failed('invalid_credentials')->record();

            $hashes[] = $this->storedProperties($record->id)['_audit']['identifier_hash'] ?? null;
        }

        self::assertSame([self::ALICE_IDENTIFIER_HASH, self::ALICE_IDENTIFIER_HASH, self::ALICE_IDENTIFIER_HASH], $hashes);

        $other = AuditLog::event('app.sign_in_failed')->withIdentifier('bob@example.com')->failed('invalid_credentials')->record();

        self::assertNotSame(self::ALICE_IDENTIFIER_HASH, $other->properties['_audit']['identifier_hash'] ?? null);
    }

    /**
     * A definition using every handling reaches the row as its table says: a
     * retained value kept, a redacted one the marker, a pseudonymised one its
     * hash, an encrypted one its envelope, a dropped one and an unlisted one
     * removed and counted, and a secret-shaped key the marker though a rule
     * retains it.
     *
     * @return void
     */
    public function testTheHandlingTableEndToEnd(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        app()->instance(FieldEncrypter::class, $encrypter);

        self::useDefinition(
            EventDefinition::for(self::CODE)
                ->retain('amount', 'password')
                ->redact('memo')
                ->pseudonymise('email')
                ->encrypt('card', KeyOwner::SUBJECT)
                ->drop('ssn'),
        );

        $record = AuditLog::event(self::CODE)
            ->on(Reference::of('invoice', '42'))
            ->withProperties([
                'amount'   => '1200.00',
                'password' => 's3cr3t',
                'memo'     => 'Paid in cash.',
                'email'    => 'alice@example.com',
                'card'     => '4242',
                'ssn'      => '078-05-1120',
                'unlisted' => 'gone',
            ])
            ->record();

        $expected = [
            'amount'   => '1200.00',
            'password' => Redactor::MARKER,
            'memo'     => Redactor::MARKER,
            'email'    => self::ALICE_PSEUDONYM,
            'card'     => ['v' => 1, 'k' => 'key_42', 'c' => base64_encode('4242')],
            '_audit'   => ['omitted' => ['count' => 2, 'paths' => ['*', 'ssn']]],
        ];

        self::assertSame($expected, $record->properties);
        self::assertEqualsCanonicalizing($expected, $this->storedProperties($record->id));
        self::assertCount(1, $encrypter->calls());
        self::assertSame('4242', $encrypter->calls()[0][1]);
    }

    /**
     * Rows of `[mode, client address, what the row's column holds]`: every
     * mode, over an IPv4, an IPv6 and an IPv4-mapped address. An encrypted
     * address is its envelope's canonical JSON.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideIpModes(): iterable
    {
        yield from [
            'full, IPv4'       => ['full', self::CLIENT_IP, self::CLIENT_IP],
            'full, IPv6'       => ['full', '2001:DB8::1', '2001:db8::1'],
            'full, mapped'     => ['full', '::ffff:203.0.113.7', self::CLIENT_IP],
            'truncate, IPv4'   => ['truncate', self::CLIENT_IP, '203.0.113.0'],
            'truncate, IPv6'   => ['truncate', '2001:db8:abcd:12::1', '2001:db8:abcd::'],
            'truncate, mapped' => ['truncate', '::ffff:203.0.113.7', '203.0.113.0'],
            'hash, IPv4'       => ['hash', self::CLIENT_IP, '05d70d576b2b05d5:d8cd13f098906335536b7d3cff22a70c382c0d3a2a4c38cbd2815e6a456118e1'],
            'hash, IPv6'       => ['hash', '2001:db8::1', '05d70d576b2b05d5:70ba167d07452e86911ea28f6f4067e2c9963f07d216a158ee83f07f6371c95a'],
            'hash, mapped'     => ['hash', '::ffff:203.0.113.7', '05d70d576b2b05d5:d8cd13f098906335536b7d3cff22a70c382c0d3a2a4c38cbd2815e6a456118e1'],
            'drop, IPv4'       => ['drop', self::CLIENT_IP, null],
            'encrypt, IPv4'    => ['encrypt', self::CLIENT_IP, '{"c":"MjAzLjAuMTEzLjc=","k":"key_1","v":1}'],
            'encrypt, mapped'  => ['encrypt', '::ffff:203.0.113.7', '{"c":"MjAzLjAuMTEzLjc=","k":"key_1","v":1}'],
        ];
    }

    /**
     * The address of a real request reaches the row as its mode says, through
     * the HTTP frame and the request's contributor.
     *
     * @param  string  $mode
     * @param  string  $address
     * @param  ?string  $stored
     * @return void
     */
    #[DataProvider('provideIpModes')]
    public function testAnIpModeAppliesToARealRequest(string $mode, string $address, ?string $stored): void
    {
        app(ConfigRepository::class)->set(self::IP_MODE, $mode);
        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        Route::post('/invoices', static fn (): string => AuditLog::event(self::CODE)->by(Reference::of('user', '1'))->record()->id);

        $this->withServerVariables(['REMOTE_ADDR' => $address])->post('/invoices')->assertOk();

        $entry = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertSame($stored, $entry->ip);
        self::assertNull($entry->properties, 'A stored address, or one dropped by configuration, adds no diagnostic.');
    }

    /**
     * Rows of `[mode]`: every IP mode, since an invalid address is `null` in
     * each of them, `full` included.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEveryIpMode(): iterable
    {
        foreach (IpMode::cases() as $mode) {
            yield $mode->value => [$mode->value];
        }
    }

    /**
     * A request whose address is not valid stores none, in every mode: the
     * request's contributor keeps it out, so nothing was lost to diagnose.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideEveryIpMode')]
    public function testAnInvalidClientIpIsNotStored(string $mode): void
    {
        app(ConfigRepository::class)->set(self::IP_MODE, $mode);

        Route::post('/invoices', static fn (): string => AuditLog::event(self::CODE)->by(Reference::of('user', '1'))->record()->id);

        $this->withServerVariables(['REMOTE_ADDR' => 'not-an-ip'])->post('/invoices')->assertOk();

        $entry = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertNull($entry->ip);
        self::assertStringNotContainsString('not-an-ip', (string) json_encode($entry->getAttributes()));
    }

    /**
     * An invalid address a builder is filled with directly gets past no
     * contributor, so it is removed and diagnosed, in every mode.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideEveryIpMode')]
    public function testAnInvalidFilledIpIsNotStoredAndIsDiagnosed(string $mode): void
    {
        app(ConfigRepository::class)->set(self::IP_MODE, $mode);

        $pending = AuditLog::event(self::CODE);

        $pending->fillClient('not-an-ip', null);

        $record = $pending->record();
        $entry  = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertNull($record->ip);
        self::assertNull($entry->ip);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['$ip']]]], $record->properties);
        self::assertStringNotContainsString('not-an-ip', (string) json_encode($entry->getAttributes()));
    }

    /**
     * Rows of `[mode, address]`: every IP mode over each address that used to
     * be too malformed for a builder to take.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideGarbageIps(): iterable
    {
        foreach (IpMode::cases() as $mode) {
            yield $mode->value . ', empty' => [$mode->value, ''];
            yield $mode->value . ', over-long' => [$mode->value, str_repeat('garbage', 40)];
            yield $mode->value . ', a control character' => [$mode->value, "garbage\0garbage"];
            yield $mode->value . ', not valid UTF-8' => [$mode->value, "garbage\xFF"];
        }
    }

    /**
     * A garbage address loses nothing but itself: the record is stored, its
     * address is `null`, and `$ip` says one was not kept, without its value.
     *
     * @param  string  $mode
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideGarbageIps')]
    public function testAGarbageIpStoresTheRecordWithNoAddress(string $mode, string $address): void
    {
        app(ConfigRepository::class)->set(self::IP_MODE, $mode);
        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $pending = AuditLog::event(self::CODE)->by(Reference::of('user', '1'));

        $pending->fillClient($address, null);

        $record = $pending->record();
        $entry  = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertNull($record->ip);
        self::assertNull($entry->ip);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['$ip']]]], $record->properties);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['$ip']]]], $entry->properties);
        self::assertStringNotContainsString('garbage', (string) json_encode($entry->getAttributes(), JSON_INVALID_UTF8_SUBSTITUTE));
    }

    /**
     * A contributor passing a garbage address fails no write either, and the
     * first contributor to fill it still decides the field.
     *
     * @return void
     */
    public function testAContributorsGarbageIpDoesNotFailTheWrite(): void
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->contribute(GarbageIpContributor::class);

        AuditLog::swap($recorder);

        $record = AuditLog::event(self::CODE)->record();
        $entry  = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertNull($entry->ip);
        self::assertSame(['count' => 1, 'paths' => ['$ip']], $record->properties['_audit']['omitted'] ?? null);
        self::assertStringNotContainsString(GarbageIpContributor::GARBAGE, (string) json_encode($entry->getAttributes()));
    }

    /**
     * Rows of `[raw key, key as stored]`: spellings of a secret's key that hide
     * nothing from the matcher, one repaired as every key is on its way in.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideHostileKeys(): iterable
    {
        yield from [
            'a trailing digit'   => ['password2', 'password2'],
            'brackets'           => ['user[password]', 'user[password]'],
            'a colon before'     => ['data:password', 'data:password'],
            'a colon after'      => ['password:new', 'password:new'],
            'an invalid byte'    => ["password\xFF", "password\u{FFFD}"],
            'a byte order mark'  => ["\u{FEFF}password", "\u{FEFF}password"],
            'a zero-width space' => ["pass\u{200B}word", "pass\u{200B}word"],
            'a soft hyphen'      => ["pass\u{00AD}word", "pass\u{00AD}word"],
        ];
    }

    /**
     * A secret under a hostile spelling of its key reaches neither the
     * properties nor the context, by whichever way the key arrives.
     *
     * @param  string  $key
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideHostileKeys')]
    public function testAHostileSpellingOfAKeyHidesNoSecret(string $key, string $stored): void
    {
        $pending = AuditLog::event(self::CODE)->withProperties([$key => 's3cr3t']);

        $pending->fillContext([$key => 's3cr3t']);

        $record = $pending->record();
        $entry  = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertSame(Redactor::MARKER, $record->properties[$stored] ?? null);
        self::assertSame(Redactor::MARKER, $record->context[$stored] ?? null);
        self::assertStringNotContainsString('s3cr3t', (string) json_encode($entry->getAttributes()));
    }

    /**
     * An owned note under the default encrypter, which has no keys, is dropped
     * and counted under its fixed path, and its text reaches no row.
     *
     * @return void
     */
    public function testAnOwnedNoteIsCountedWithTheDefaultEncrypter(): void
    {
        $record = AuditLog::event(self::CODE)->withNote('Erasable.', Reference::of('user', '1'))->record();

        $expected = ['_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]];

        self::assertSame($expected, $record->properties);
        self::assertEqualsCanonicalizing($expected, $this->storedProperties($record->id));
    }

    /**
     * A plaintext note, which has no owner, is stored as given and sits after
     * the caller's own keys, as does the hash of its identifier.
     *
     * @return void
     */
    public function testAPlaintextNoteAndIdentifierSitInTheReservedArea(): void
    {
        $record = AuditLog::event(self::CODE)
            ->withProperties(['amount' => '1200.00'])
            ->withIdentifier('alice@example.com')
            ->withNote('Approved by phone.')
            ->record();

        self::assertSame(['amount' => '1200.00', '_audit' => ['note' => 'Approved by phone.', 'identifier_hash' => self::ALICE_IDENTIFIER_HASH]], $record->properties);
    }

    /**
     * A context a contributor filled after the builder was described is
     * redacted as any other, on the record and in its row.
     *
     * @return void
     */
    public function testAContributedContextIsRedacted(): void
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->contribute(SecretFillingContributor::class);

        AuditLog::swap($recorder);

        $record = AuditLog::event(self::CODE)->record();
        $entry  = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertSame(['api_key' => Redactor::MARKER, 'plan' => 'pro'], array_intersect_key($record->context ?? [], ['api_key' => true, 'plan' => true]));
        self::assertSame(SecretFillingContributor::ACTOR_ID, $entry->actor_id);
        self::assertStringNotContainsString(SecretFillingContributor::SECRET, (string) json_encode($entry->getAttributes()));
    }

    /**
     * A context over its budget loses its application's keys and keeps the
     * package's own, and the loss is diagnosed in the properties, since the
     * context holds no diagnostics.
     *
     * @return void
     */
    public function testAContextOverItsBudgetIsDiagnosedInTheProperties(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.max_context_bytes', 1024);

        $pending = AuditLog::event(self::CODE);

        $pending->fillContext(['channel' => 'email', 'application' => str_repeat('a', 1024), 'other' => str_repeat('b', 900)]);

        $record = $pending->record();

        self::assertSame(['channel' => 'email', 'other' => str_repeat('b', 900)], $record->context);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['context.*']]]], $record->properties);
        self::assertSame($record->properties, $this->storedProperties($record->id));
    }

    /**
     * The row under the record's id reads back as what the capture returned.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     */
    private function assertTheRowEquals(AuditRecord $record): void
    {
        $returned = $record->toArray();
        $stored   = $this->storedRow($record->id);

        self::assertSame(CanonicalEncoder::encode($returned), CanonicalEncoder::encode(array_intersect_key($stored, $returned)));
        self::assertSame(Redactor::MARKER, json_decode((string) json_encode($stored['properties']), true, flags: JSON_THROW_ON_ERROR)['password']);
    }

    /**
     * The properties of the row under the id, as stored, read as arrays.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @return array<array-key, mixed>
     */
    private function storedProperties(string $id): array
    {
        $properties = json_decode((string) json_encode($this->storedRow($id)['properties']), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($properties);

        return $properties;
    }

    /**
     * A builder with values each step of minimising changes: a secret-shaped
     * key, its context, a client address the mode keeps, and a hashed
     * identifier.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function minimisedPending(): PendingRecord
    {
        $pending = AuditLog::event(self::CODE)
            ->on(Reference::of('invoice', '42'))
            ->withProperties(['amount' => '1200.00', 'password' => 's3cr3t', 'customer' => ['api_key' => 's3cr3t', 'name' => 'Alice']])
            ->withIdentifier('alice@example.com')
            ->withNote('Approved by phone.');

        $pending->fillContext(['api_key' => 's3cr3t', 'plan' => 'pro']);
        $pending->fillClient('::ffff:203.0.113.7', 'Example/1.0');

        return $pending;
    }

    /**
     * Make the definition's recorder the facade's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     */
    private static function useDefinition(EventDefinition $definition): void
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->define($definition);

        AuditLog::swap($recorder);
    }
}
