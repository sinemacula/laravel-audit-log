<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\IpMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;

/**
 * Unit tests for the record minimiser: the order of its steps, what each does
 * to the context, the collisions, the address, the note, the identifier and the
 * properties, that every diagnostic lands in one list, and which settings fail
 * the capture and when.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordMinimiser::class)]
final class RecordMinimiserTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The code every record here is of. */
    private const string CODE = 'invoice.approved';

    /** @var string The root key every hash here is made under. */
    private const string ROOT_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The address a dynamic key or an identifier could be. */
    private const string EMAIL = 'bob@example.com';

    /** @var string The value that must reach no diagnostic. */
    private const string PLANTED = 's3cr3t';

    /** @var string The address most records here come from. */
    private const string ADDRESS = '203.0.113.7';

    /** @var string The diagnostic path of an address that was not stored. */
    private const string IP_PATH = '$ip';

    /** @var string The diagnostic path of a note that was not stored. */
    private const string NOTE_PATH = '_audit.note';

    /** @var string The text of every note here. */
    private const string NOTE = 'Approved by phone.';

    /** @var string The hash of `alice@example.com` under the root key, from the identifier domain's golden vectors. */
    private const string ALICE_HASH = '13f5820b5aa0c097:680a1e05e07bcd260a8f8eda495c167100f4413f08ac4a5d980061e30cd51abf';

    /** @var string The hash of the address under the root key, from the IP domain's golden vectors. */
    private const string ADDRESS_HASH = '05d70d576b2b05d5:d8cd13f098906335536b7d3cff22a70c382c0d3a2a4c38cbd2815e6a456118e1';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The reporter of the capture under test. */
    private RecordingExceptionHandler $handler;

    /**
     * Give each test its own reporter.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new RecordingExceptionHandler;
    }

    /**
     * Under the permissive definition a record with no secret-shaped key,
     * within its budgets, is exactly what the builder held, and no diagnostic
     * is added.
     *
     * @return void
     */
    public function testAPermissiveRecordIsUnchanged(): void
    {
        $pending = self::pending()->withProperties(['amount' => '1200.00', 'lines' => [1, 2], 'customer' => ['name' => 'Alice']]);

        $pending->fillClient(self::ADDRESS, 'Mozilla/5.0');
        $pending->fillContext(['route' => 'invoices.approve', 'method' => 'POST']);

        $minimised = $this->minimise($pending);

        self::assertSame(['amount' => '1200.00', 'lines' => [1, 2], 'customer' => ['name' => 'Alice']], $minimised->properties);
        self::assertSame(['route' => 'invoices.approve', 'method' => 'POST'], $minimised->context);
        self::assertSame(self::ADDRESS, $minimised->ip);
    }

    /**
     * A record holding nothing minimises to nothing.
     *
     * @return void
     */
    public function testAnEmptyRecordIsAllNull(): void
    {
        $minimised = $this->minimise(self::pending());

        self::assertNull($minimised->properties);
        self::assertNull($minimised->context);
        self::assertNull($minimised->ip);
    }

    /**
     * Key redaction runs before the rules, so a rule retaining a secret-shaped
     * key keeps only the marker, hashing or encrypting it changes nothing, and
     * a rule can redact what the key matcher exempts. Caps run after the rule
     * chose, so only a retained string is cut.
     *
     * @return void
     */
    public function testTheOrderIsRedactThenRulesThenCaps(): void
    {
        $definition = EventDefinition::for(self::CODE)
            ->retain('password', 'long')
            ->redact('token_id')
            ->pseudonymise('api_key', 'long_pseudonym');

        $long    = str_repeat('a', 2000);
        $pending = self::pending()->withProperties([
            'password'       => self::PLANTED,
            'token_id'       => 'exempt',
            'api_key'        => self::PLANTED,
            'long'           => $long,
            'long_pseudonym' => $long,
        ]);

        $properties = $this->minimise($pending, $definition)->properties;

        self::assertIsArray($properties);
        self::assertSame(Redactor::MARKER, $properties['password']);
        self::assertSame(Redactor::MARKER, $properties['token_id']);
        self::assertSame(Redactor::MARKER, $properties['api_key']);
        self::assertSame(str_repeat('a', 1024), $properties['long']);
        self::assertIsString($properties['long_pseudonym']);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $properties['long_pseudonym']);
    }

    /**
     * An event definition's rules and its unlisted default are for the
     * properties alone: the context keeps a key a rule names and every other.
     *
     * @return void
     */
    public function testNoRuleTouchesTheContext(): void
    {
        $pending = self::pending();

        $pending->fillContext(['plan' => 'pro', 'other' => 'kept']);

        $minimised = $this->minimise($pending, EventDefinition::for(self::CODE)->drop('plan'));

        self::assertSame(['plan' => 'pro', 'other' => 'kept'], $minimised->context);
        self::assertNull($minimised->properties);
    }

    /**
     * The context's secret-shaped key becomes the marker, a long string is cut
     * at every depth, and the context stays within its budget.
     *
     * @return void
     */
    public function testTheContextIsRedactedCappedAndBudgeted(): void
    {
        $pending = self::pending();

        $pending->fillContext([
            'api_key' => self::PLANTED,
            'nested'  => ['long' => str_repeat('a', 2000)],
            'route'   => 'invoices.approve',
        ]);

        self::assertSame(['api_key' => Redactor::MARKER, 'nested' => ['long' => str_repeat('a', 1024)], 'route' => 'invoices.approve'], $this->minimise($pending)->context);

        $crowded  = self::contextOf(['big_one' => str_repeat('a', 1000), 'big_two' => str_repeat('b', 900), 'route' => 'kept']);
        $budgeted = $this->minimise($crowded, redaction: ['max_context_bytes' => 1024])->context;

        self::assertSame(['big_two' => str_repeat('b', 900), 'route' => 'kept'], $budgeted);
    }

    /**
     * What the context's budget omits is diagnosed in the properties' metadata,
     * prefixed `context.`, and the context itself holds no diagnostic.
     *
     * @return void
     */
    public function testContextOmissionsArePrefixedInThePropertiesDiagnostics(): void
    {
        $minimised = $this->minimise(self::contextOf(['big_one' => str_repeat('a', 1000), 'big_two' => str_repeat('b', 900)]), redaction: ['max_context_bytes' => 1024]);

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['context.*']]]], $minimised->properties);
        self::assertSame(['big_two' => str_repeat('b', 900)], $minimised->context);
    }

    /**
     * Each budget governs its own value: a context over its budget and within
     * the properties', and properties within the context's, are not mixed up.
     *
     * @return void
     */
    public function testEachBudgetGovernsItsOwnValue(): void
    {
        $pending = self::contextOf(['a' => str_repeat('a', 900), 'b' => str_repeat('b', 800)]);

        $pending->withProperties(['first' => str_repeat('c', 900), 'second' => str_repeat('d', 800)]);

        $minimised = $this->minimise($pending, redaction: ['max_bytes' => 8192, 'max_context_bytes' => 1024]);

        self::assertSame(['b' => str_repeat('b', 800)], $minimised->context);

        $omitted = ['count' => 1, 'paths' => ['context.*']];

        self::assertSame(['first' => str_repeat('c', 900), 'second' => str_repeat('d', 800), '_audit' => ['omitted' => $omitted]], $minimised->properties);
    }

    /**
     * The properties' budget comes from `max_bytes`, and the final encoding
     * fits it with its diagnostics.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testThePropertiesAreHeldToTheirBudget(): void
    {
        $values = [];

        foreach (range(1, 10) as $number) {
            $values['field_' . $number] = str_repeat('a', 1000);
        }

        $properties = $this->minimise(self::pending()->withProperties($values), redaction: ['max_bytes' => 8192])->properties;

        self::assertIsArray($properties);
        self::assertCount(4, $properties);
        self::assertSame(['count' => 7, 'paths' => ['*']], self::omitted($properties));
        self::assertLessThanOrEqual(8192, strlen(json_encode($properties, CanonicalEncoder::JSON_FLAGS)));
    }

    /**
     * A colliding property's key is masked, literal only where a rule names it,
     * and counted, while the first value stays.
     *
     * @return void
     */
    public function testAPropertyCollisionIsCountedAndMasked(): void
    {
        $pending = self::pending()->withProperties(['ssn' => 'first', "ssn\0" => 'second', 'x' => 1, "x\0" => 2]);

        $properties = $this->minimise($pending, EventDefinition::for(self::CODE)->retain('ssn')->retain('x'))->properties;

        self::assertSame(['ssn' => 'first', 'x' => 1, '_audit' => ['omitted' => ['count' => 2, 'paths' => ['ssn', 'x']]]], $properties);

        $unnamed = $this->minimise(self::pending()->withProperties(['x' => 1, "x\0" => 2]))->properties;

        self::assertSame(['x' => 1, '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $unnamed);
    }

    /**
     * A colliding context key is masked with the context's own rule, under its
     * prefix, literal only for a fixed package name, and counted.
     *
     * @return void
     */
    public function testAContextCollisionIsCountedAndMasked(): void
    {
        $minimised = $this->minimise(self::contextOf(['route' => 'first', "route\0" => 'second', 'plan' => 'pro', "plan\0" => 'free']));

        self::assertSame(['route' => 'first', 'plan' => 'pro'], $minimised->context);
        self::assertSame(['_audit' => ['omitted' => ['count' => 2, 'paths' => ['context.*', 'context.route']]]], $minimised->properties);
    }

    /**
     * The key of a collision can be anything a client sent, so neither the raw
     * key nor its cleaned form is ever written.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARawCollisionKeyNeverReachesTheDiagnostics(): void
    {
        $pending = self::contextOf([self::EMAIL => 'first', self::EMAIL . "\0" => 'second'])->withProperties([self::EMAIL => 'first', self::EMAIL . "\0" => 'second']);

        $properties = $this->minimise($pending)->properties;

        self::assertIsArray($properties);
        self::assertSame(['count' => 2, 'paths' => ['*', 'context.*']], self::omitted($properties));
        self::assertStringNotContainsString(self::EMAIL, json_encode(self::omitted($properties), JSON_THROW_ON_ERROR));
    }

    /**
     * A literal dot in a colliding key is one segment, so a rule on the nested
     * path of the same spelling never lends it a literal.
     *
     * @return void
     */
    public function testALiteralDotInACollisionIsMaskedAsOneSegment(): void
    {
        $pending = self::pending()->withProperties(['a.b' => ['x' => 1, "x\0" => 2]]);

        $properties = $this->minimise($pending, EventDefinition::for(self::CODE)->retain('a.b.x')->unlisted(FieldHandling::RETAIN))->properties;

        self::assertIsArray($properties);
        self::assertSame(['count' => 1, 'paths' => ['*.*']], self::omitted($properties));
    }

    /**
     * The builder carries the paths of 32 collisions, and those past them still
     * count, for the properties and the context alike.
     *
     * @return void
     */
    public function testCollisionsPastThe32CarriedStillCount(): void
    {
        $properties = [];
        $context    = [];

        foreach (range(1, 40) as $number) {
            $properties['p' . $number]        = 1;
            $properties['p' . $number . "\0"] = 2;
        }

        foreach (range(1, 35) as $number) {
            $context['c' . $number]        = 1;
            $context['c' . $number . "\0"] = 2;
        }

        $stored = $this->minimise(self::contextOf($context)->withProperties($properties))->properties;

        self::assertIsArray($stored);
        self::assertSame(['count' => 75, 'paths' => ['*', 'context.*']], self::omitted($stored));
    }

    /**
     * A plaintext note goes to the metadata, after the caller's keys.
     *
     * @return void
     */
    public function testAPlaintextNoteGoesToTheMetadataAfterTheCallersKeys(): void
    {
        $pending = self::pending()->withNote(self::NOTE)->withProperties(['amount' => '1200.00', 'currency' => 'GBP']);

        $properties = $this->minimise($pending)->properties;

        self::assertSame(['amount' => '1200.00', 'currency' => 'GBP', '_audit' => ['note' => self::NOTE]], $properties);
        self::assertIsArray($properties);
        self::assertSame(['amount', 'currency', '_audit'], array_keys($properties));
    }

    /**
     * A note and nothing else gives only the metadata.
     *
     * @return void
     */
    public function testANoteAloneGivesOnlyTheMetadata(): void
    {
        self::assertSame(['_audit' => ['note' => self::NOTE]], $this->minimise(self::pending()->withNote(self::NOTE))->properties);
    }

    /**
     * Rows of `[what owns the note, the id of the party whose key it is sealed
     * under]`: the actor, the subject and a reference it was given.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference, 1: string}>
     */
    public static function provideNoteOwners(): iterable
    {
        yield from [
            'the actor'   => [KeyOwner::ACTOR, 'actor-1'],
            'the subject' => [KeyOwner::SUBJECT, 'subject-1'],
            'a reference' => [Reference::of('team', 'team-1'), 'team-1'],
        ];
    }

    /**
     * With no encrypter bound, an owned note is dropped and diagnosed, even
     * with its owner present, and its text is stored nowhere.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideNoteOwners')]
    public function testAnOwnedNoteWithNoEncrypterIsDroppedAndDiagnosed(KeyOwner|Reference $owner, string $id): void
    {
        $properties = $this->minimise(self::parties()->withNote(self::NOTE, $owner))->properties;

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => [self::NOTE_PATH]]]], $properties);
        self::assertStringNotContainsString($id, (string) json_encode($properties));
        self::assertSame([], $this->handler->reports());
    }

    /**
     * Rows of `[owner]`: the two owners a record can lack.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner}>
     */
    public static function provideAbsentOwners(): iterable
    {
        yield from [
            'the actor'   => [KeyOwner::ACTOR],
            'the subject' => [KeyOwner::SUBJECT],
        ];
    }

    /**
     * A note owned by a party the record does not have is dropped and diagnosed
     * without troubling the encrypter, which could have sealed it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner  $owner
     * @return void
     */
    #[DataProvider('provideAbsentOwners')]
    public function testAnOwnedNoteWithAnAbsentOwnerIsDroppedAndDiagnosed(KeyOwner $owner): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $properties = $this->minimise(self::pending()->withNote(self::NOTE, $owner), encrypter: $encrypter)->properties;

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => [self::NOTE_PATH]]]], $properties);
        self::assertSame([], $encrypter->calls());
    }

    /**
     * An owned note with a key is stored as its envelope under that owner, with
     * the plaintext sealed whole.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideNoteOwners')]
    public function testAnOwnedNoteWithAnEncrypterStoresItsEnvelope(KeyOwner|Reference $owner, string $id): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $properties = $this->minimise(self::parties()->withNote(self::NOTE, $owner), encrypter: $encrypter)->properties;

        self::assertSame(['_audit' => ['note' => ['v' => 1, 'k' => 'key_' . $id, 'c' => base64_encode(self::NOTE)]]], $properties);
        self::assertCount(1, $encrypter->calls());
        self::assertSame($id, $encrypter->calls()[0][0]->id);
        self::assertSame(self::NOTE, $encrypter->calls()[0][1]);
    }

    /**
     * An encrypter that throws on a note does not fail the capture: the note is
     * dropped and diagnosed, and one payload-free failure is reported.
     *
     * @return void
     */
    public function testAThrowingEncrypterOnANoteIsContained(): void
    {
        $properties = $this->minimise(self::parties()->withNote(self::NOTE, KeyOwner::ACTOR), encrypter: new ThrowingFieldEncrypter)->properties;

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => [self::NOTE_PATH]]]], $properties);
        self::assertCount(1, $this->handler->reports());
        self::assertInstanceOf(FieldEncryptionFailedException::class, $this->handler->reports()[0]);
        self::assertStringNotContainsString(self::NOTE, $this->handler->reports()[0]->getMessage());
    }

    /**
     * One capture meets one failure: the address, the note and a field that
     * would each call a broken encrypter call it once, report once, and are
     * each diagnosed.
     *
     * @return void
     */
    public function testOneFailureIsReportedPerCapture(): void
    {
        $encrypter = new ThrowingFieldEncrypter;
        $pending   = self::parties()->withNote(self::NOTE, KeyOwner::ACTOR)->withProperties(['card' => '4242']);

        $pending->fillClient(self::ADDRESS, null);

        $minimised = $this->minimise($pending, EventDefinition::for(self::CODE)->encrypt('card', KeyOwner::ACTOR), ['ip' => 'encrypt'], $encrypter);

        self::assertSame(['_audit' => ['omitted' => ['count' => 3, 'paths' => [self::IP_PATH, self::NOTE_PATH, 'card']]]], $minimised->properties);
        self::assertNull($minimised->ip);
        self::assertSame(1, $encrypter->calls());
        self::assertCount(1, $this->handler->reports());
    }

    /**
     * The steps run in their order, which is what a capture's encrypter sees:
     * the address, then the note, then the fields.
     *
     * @return void
     */
    public function testTheAddressThenTheNoteThenTheFieldsAreSealed(): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $pending   = self::parties()->withNote(self::NOTE, KeyOwner::SUBJECT)->withProperties(['card' => '4242']);

        $pending->fillClient(self::ADDRESS, null);

        $this->minimise($pending, EventDefinition::for(self::CODE)->encrypt('card', KeyOwner::ACTOR), ['ip' => 'encrypt'], $encrypter);

        self::assertSame([self::ADDRESS, self::NOTE, '4242'], array_map(static fn (array $call): string => $call[1], $encrypter->calls()));
    }

    /**
     * An encrypted field and an encrypted address are sealed under the record's
     * actor, as the snapshot holds it.
     *
     * @return void
     */
    public function testFieldsAndTheAddressAreSealedUnderTheSnapshotsParties(): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $pending   = self::parties()->withProperties(['card' => '4242', 'iban' => 'GB00']);

        $pending->fillClient(self::ADDRESS, null);

        $definition = EventDefinition::for(self::CODE)->encrypt('card', KeyOwner::ACTOR)->encrypt('iban', KeyOwner::SUBJECT);
        $minimised  = $this->minimise($pending, $definition, ['ip' => 'encrypt'], $encrypter);

        self::assertSame([
            'card' => ['v' => 1, 'k' => 'key_actor-1', 'c' => base64_encode('4242')],
            'iban' => ['v' => 1, 'k' => 'key_subject-1', 'c' => base64_encode('GB00')],
        ], $minimised->properties);
        self::assertSame(CanonicalEncoder::encode(['v' => 1, 'k' => 'key_actor-1', 'c' => base64_encode(self::ADDRESS)]), $minimised->ip);
    }

    /**
     * The identifier's hash goes to the reserved area, after the caller's keys
     * and a note, and is the golden vector of the identifier domain.
     *
     * @return void
     */
    public function testTheIdentifierHashIsInTheReservedArea(): void
    {
        $pending = self::pending()->withProperties(['attempt' => 1])->withNote(self::NOTE)->withIdentifier('Alice@Example.COM');

        self::assertSame(['attempt' => 1, '_audit' => ['note' => self::NOTE, 'identifier_hash' => self::ALICE_HASH]], $this->minimise($pending)->properties);
    }

    /**
     * An unlisted drop never loses the identifier, because it is not a
     * property.
     *
     * @return void
     */
    public function testTheIdentifierSurvivesAnUnlistedDrop(): void
    {
        $pending = self::pending()->withProperties(['attempt' => 1])->withIdentifier('alice@example.com');

        $properties = $this->minimise($pending, EventDefinition::for(self::CODE))->properties;

        self::assertSame(['_audit' => ['identifier_hash' => self::ALICE_HASH, 'omitted' => ['count' => 1, 'paths' => ['*']]]], $properties);
    }

    /**
     * In `drop` mode no hash is stored, and nothing is diagnosed: it is
     * configuration rather than loss.
     *
     * @return void
     */
    public function testDropModeStoresNoIdentifier(): void
    {
        self::assertNull($this->minimise(self::pending()->withIdentifier('alice@example.com'), redaction: ['identifiers' => 'drop'])->properties);
    }

    /**
     * A blank identifier is what a sign-in form can post, so it stores no hash
     * and no diagnostic.
     *
     * @return void
     */
    public function testABlankIdentifierStoresNoHash(): void
    {
        self::assertNull($this->minimise(self::pending()->withIdentifier("  \0 "))->properties);
    }

    /**
     * The identifier is never stored as given, in the properties or anywhere
     * else the record holds.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnIdentifierIsNeverInThePlainProperties(): void
    {
        $pending = self::pending()->withProperties(['attempt' => 1])->withIdentifier(self::EMAIL);

        $minimised = $this->minimise($pending);

        self::assertStringNotContainsString(self::EMAIL, json_encode([$minimised->properties, $minimised->context, $minimised->ip], JSON_THROW_ON_ERROR));
    }

    /**
     * An address that is not valid is stored in no mode, and is diagnosed.
     *
     * @return void
     */
    public function testAnInvalidIpIsNullAndDiagnosed(): void
    {
        $pending = self::pending();

        $pending->fillClient('not-an-ip', null);

        $minimised = $this->minimise($pending);

        self::assertNull($minimised->ip);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => [self::IP_PATH]]]], $minimised->properties);
    }

    /**
     * Rows of `[mode, what is stored]`: every mode that needs no encrypter.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideIpModes(): iterable
    {
        yield from [
            'full'     => ['full', self::ADDRESS],
            'truncate' => ['truncate', '203.0.113.0'],
            'hash'     => ['hash', self::ADDRESS_HASH],
            'drop'     => ['drop', null],
        ];
    }

    /**
     * The configured mode decides what is stored of the address, and none of
     * these diagnoses anything.
     *
     * @param  string  $mode
     * @param  ?string  $stored
     * @return void
     */
    #[DataProvider('provideIpModes')]
    public function testTheIpModeIsApplied(string $mode, ?string $stored): void
    {
        $pending = self::pending();

        $pending->fillClient(self::ADDRESS, null);

        $minimised = $this->minimise($pending, redaction: ['ip' => $mode]);

        self::assertSame($stored, $minimised->ip);
        self::assertNull($minimised->properties);
    }

    /**
     * Whatever removed it, every removal lands in the one list, sorted, counted
     * together, under `properties._audit.omitted`.
     *
     * @return void
     */
    public function testEveryDiagnosticLandsInOneList(): void
    {
        $pending = self::contextOf(['big_one' => str_repeat('a', 1000), 'big_two' => str_repeat('b', 900)])
            ->withProperties(['ssn' => 1, "ssn\0" => 2, 'other' => 3, 'card' => '4242'])
            ->withNote(self::NOTE, KeyOwner::ACTOR);

        $pending->fillClient('not-an-ip', null);

        $properties = $this->minimise($pending, EventDefinition::for(self::CODE)->retain('ssn')->encrypt('card', KeyOwner::SUBJECT), ['max_context_bytes' => 1024])->properties;

        $omitted = ['count' => 6, 'paths' => [self::IP_PATH, '*', self::NOTE_PATH, 'card', 'context.*', 'ssn']];

        self::assertSame(['ssn' => 1, '_audit' => ['omitted' => $omitted]], $properties);
    }

    /**
     * Rows of `[the leaf, a malformed value, the message]`: one per setting
     * read on every capture.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'keys'              => ['keys', 'password', '`audit-log.redaction.keys` must be a list of key names, each of at least one token.'],
            'identifiers'       => ['identifiers', 'maybe', '`audit-log.redaction.identifiers` must be `hash` or `drop`.'],
            'ip'                => ['ip', 'partial', '`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.'],
            'max_bytes'         => ['max_bytes', 8191, '`audit-log.redaction.max_bytes` must be an integer from 8192 to 16777216.'],
            'max_context_bytes' => ['max_context_bytes', 1023, '`audit-log.redaction.max_context_bytes` must be an integer from 1024 to 16777216.'],
        ];
    }

    /**
     * A malformed setting fails the capture of a record that holds nothing it
     * would apply to.
     *
     * @param  string  $leaf
     * @param  int|string  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedSettingFailsTheCall(string $leaf, int|string $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $this->minimise(self::pending(), redaction: [$leaf => $value]);
    }

    /**
     * Several malformed settings fail on the key names first, whatever the
     * budgets and the modes hold, so the first reader decides what a capture
     * reports; protects against a mutation that leaves the keys to the
     * redactor's read.
     *
     * @return void
     */
    public function testTheKeyNamesAreReadFirst(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.redaction.keys` must be a list of key names, each of at least one token.');

        $this->minimise(self::pending(), redaction: ['keys' => 'password', 'max_bytes' => 1, 'identifiers' => 'maybe', 'ip' => 'partial']);
    }

    /**
     * The settings are read before any encrypter is called, so a malformed
     * budget sends no plaintext anywhere.
     *
     * @return void
     */
    public function testAMalformedSettingFailsBeforeAnythingIsSealed(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        try {
            $this->minimise(self::parties()->withNote(self::NOTE, KeyOwner::ACTOR), redaction: ['max_bytes' => 1], encrypter: $encrypter);

            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $encrypter->calls());
        }
    }

    /**
     * Rows of `[how a record comes to need a hash]`: an identifier, a pseudonym
     * and a hashed address.
     *
     * @return iterable<string, array{0: \Closure(self): \SineMacula\Laravel\AuditLog\Privacy\Minimised}>
     */
    public static function provideHashes(): iterable
    {
        yield from [
            'an identifier' => [static fn (self $test): Minimised => $test->minimise(self::pending()->withIdentifier('alice@example.com'), redaction: ['key' => 'short'])],
            'a pseudonym'   => [static function (self $test): Minimised {
                $pending = self::pending()->withProperties(['email' => self::EMAIL]);

                return $test->minimise($pending, EventDefinition::for(self::CODE)->pseudonymise('email'), ['key' => 'short']);
            }],
            'an address' => [static function (self $test): Minimised {
                $pending = self::pending();
                $pending->fillClient(self::ADDRESS, null);

                return $test->minimise($pending, redaction: ['key' => 'short', 'ip' => 'hash']);
            }],
        ];
    }

    /**
     * A malformed key leaves a record that needs no hash alone, and fails each
     * that does, never falling back to the application key.
     *
     * @param  \Closure(self): \SineMacula\Laravel\AuditLog\Privacy\Minimised  $capture
     * @return void
     */
    #[DataProvider('provideHashes')]
    public function testAMalformedKeyFailsOnlyWhenAHashIsNeeded(\Closure $capture): void
    {
        $unneeded = self::pending()->withProperties(['amount' => 1])->withIdentifier('alice@example.com');
        $unhashed = $this->minimise($unneeded, redaction: ['key' => 'short', 'identifiers' => 'drop']);

        self::assertSame(['amount' => 1], $unhashed->properties);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.redaction.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes.');

        $capture($this);
    }

    /**
     * A key past the ceiling leaves with its branch before anything else reads
     * a key, in the properties and the context alike, and each removal is
     * counted under a path masked whole, whatever the rules are: the key, and
     * what was under it, reach neither the record nor a diagnostic.
     *
     * @return void
     */
    public function testAKeyPastTheCeilingLeavesWithItsBranch(): void
    {
        $key     = self::PLANTED . str_repeat('k', KeyCeiling::MAX_BYTES);
        $pending = self::contextOf(['kept' => 1, $key => self::PLANTED, 'outer' => [$key => self::PLANTED]]);

        $pending->withProperties(['amount' => '1200.00', $key => self::PLANTED, 'outer' => [$key => self::PLANTED]]);

        $minimised = $this->minimise($pending);

        self::assertSame(['amount' => '1200.00', 'outer' => [], '_audit' => ['omitted' => ['count' => 4, 'paths' => ['*', 'context.*']]]], $minimised->properties);
        self::assertSame(['kept' => 1, 'outer' => []], $minimised->context);
    }

    /**
     * A failure reaches the caller without the record's payload, in its message
     * or in the arguments of any frame, which production's setting would hide
     * and so hide a leak from this test too.
     *
     * @return void
     */
    public function testAFailureMessageHoldsNoPayload(): void
    {
        $pending = self::contextOf(['plan' => self::PLANTED]);

        $pending->withProperties(['email' => self::PLANTED])->withNote(self::PLANTED)->withIdentifier(self::PLANTED);

        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            foreach ([['ip' => 'partial'], ['key' => 'short'], ['max_bytes' => 'many']] as $redaction) {
                try {
                    $this->minimise($pending, EventDefinition::for(self::CODE)->pseudonymise('email'), $redaction);

                    self::fail('Expected the setting to be refused.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertTrue(self::holdsText($exception->getTrace(), 'args'), 'The frames must have kept their arguments to search.');
                    self::assertFalse(self::holdsText($exception, self::PLANTED), 'The failure holds the payload.');
                    self::assertNull($exception->getPrevious());
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * The snapshot holds the raw payload, so it is marked sensitive on the way
     * in and on every private helper it passes through.
     *
     * @return void
     */
    public function testTheSnapshotParameterIsSensitive(): void
    {
        foreach (['minimise', 'logCollisions', 'storableNote', 'noteOwner'] as $method) {
            $parameter = (new \ReflectionMethod(RecordMinimiser::class, $method))->getParameters()[0];

            self::assertSame('snapshot', $parameter->getName(), $method);
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $method);
        }
    }

    /**
     * What the minimiser leaves of the builder, under the permissive definition
     * unless one is given. Public, so a data provider's closure can call it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  array<string, mixed>  $redaction
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     */
    public function minimise(PendingRecord $pending, ?EventDefinition $definition = null, array $redaction = [], ?FieldEncrypter $encrypter = null): Minimised
    {
        $settings = new RedactionSettings(new Repository(['app' => ['key' => self::ROOT_KEY], 'audit-log' => ['redaction' => $redaction]]));
        $hasher   = new IdentifierHasher($settings);
        $sealer   = new EnvelopeSealer($encrypter ?? new NoFieldEncrypter, $this->handler);

        $minimiser = new RecordMinimiser($settings, new Redactor($settings), new IpMinimiser($settings, $hasher), $hasher, $sealer);

        return $minimiser->minimise($pending->snapshot(), $definition ?? EventDefinition::permissive(EventCode::of(self::CODE)));
    }

    /**
     * A builder of the code, holding nothing else.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function pending(): PendingRecord
    {
        return (new PendingRecord)->event(self::CODE);
    }

    /**
     * A builder of the code with an actor and a subject.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function parties(): PendingRecord
    {
        return self::pending()->by(Reference::of('user', 'actor-1'))->on(Reference::of('invoice', 'subject-1'));
    }

    /**
     * A builder of the code with the context filled.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $context
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function contextOf(array $context): PendingRecord
    {
        $pending = self::pending();

        $pending->fillContext($context);

        return $pending;
    }

    /**
     * The diagnostics of the stored properties.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @return mixed
     */
    private static function omitted(array $properties): mixed
    {
        self::assertIsArray($properties['_audit'] ?? null);

        return $properties['_audit']['omitted'] ?? null;
    }
}
