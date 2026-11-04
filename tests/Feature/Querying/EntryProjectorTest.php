<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Querying\RevealingFieldReader;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the projection of a stored entry into the entry a viewer is
 * shown: a reason concealed on the stored value, properties and context
 * projected recursively, every encryption envelope, an owned note and an
 * encrypted IP address read through the field reader, `encrypted`, `erased`,
 * `unreadable` or a revealed value, a throwing reader contained and reported
 * once naming its class, no ciphertext anywhere in what is shown, and only a
 * descriptor the artifact inspector accepts lifted out of the properties.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EntryProjector::class)]
final class EntryProjectorTest extends TestCase
{
    /** @var string The entry's id. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A key id as a derived key's fingerprint gives it. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string A digest in lower-case hex. */
    private const string DIGEST = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

    /** @var string An encrypted IP address as the `encrypt` mode stores it. */
    private const string ENCRYPTED_IP = '{"c":"aXAgY2lwaGVydGV4dA","k":"key_42","v":1}';

    /** @var string The refusal a failed field reader is reported with. */
    private const string READER_FAILED = 'The field reader Tests\Fixtures\Querying\RevealingFieldReader failed.';

    /**
     * A reason is `null` when the stored properties flag `concealed` as `true`,
     * which the shown properties still say.
     *
     * @return void
     */
    public function testAConcealedReasonIsNulledFromTheStoredValue(): void
    {
        $entry = self::project(self::stored('{"concealed":true,"attempts":3}', ['outcome' => 'failure', 'reason' => 'account_rate_limited']));

        self::assertNull($entry->reason);
        self::assertNull($entry->toArray()['reason']);
        self::assertSame(['concealed' => true, 'attempts' => 3], $entry->properties);
        self::assertStringNotContainsString('account_rate_limited', (string) json_encode($entry->toArray()));
    }

    /**
     * Rows of `[properties]`: stored properties whose `concealed` is not
     * exactly `true`, or is not at the top of a map.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnconcealedProperties(): iterable
    {
        yield from [
            'no flag'               => ['{"attempts":3}'],
            'false'                 => ['{"concealed":false}'],
            'the string true'       => ['{"concealed":"true"}'],
            'the integer 1'         => ['{"concealed":1}'],
            'null'                  => ['{"concealed":null}'],
            'a flag nested deeper'  => ['{"_audit":{"concealed":true}}'],
            'a list holding a flag' => ['[{"concealed":true}]'],
        ];
    }

    /**
     * A flag that is not exactly `true` at the top of the stored properties
     * conceals nothing.
     *
     * @param  string  $properties
     * @return void
     */
    #[DataProvider('provideUnconcealedProperties')]
    public function testAConcealedFlagThatIsNotTrueConcealsNothing(string $properties): void
    {
        self::assertSame('over_limit', self::project(self::stored($properties, ['outcome' => 'denied', 'reason' => 'over_limit']))->reason);
    }

    /**
     * Maps become associative arrays and lists stay lists at every depth; an
     * empty map and an empty list are both empty arrays, and a map with numeric
     * keys keeps its keys.
     *
     * @return void
     */
    public function testPropertiesAreProjectedRecursively(): void
    {
        $entry = self::project(self::stored('{"amount":"1200.00","empty":{},"none":[],"lines":[{"sku":"A1","tags":["x",{"y":null}]}],"by_id":{"7":"a","10":"b"},"ok":true}'));

        self::assertSame([
            'amount' => '1200.00',
            'empty'  => [],
            'none'   => [],
            'lines'  => [['sku' => 'A1', 'tags' => ['x', ['y' => null]]]],
            'by_id'  => [7 => 'a', 10 => 'b'],
            'ok'     => true,
        ], $entry->properties);
    }

    /**
     * An envelope at any depth, in a map or a list, is read through the field
     * reader at its path, the list's indexes as digits, in the order the
     * properties hold them, and shown as the reader answers.
     *
     * @return void
     */
    public function testAnEnvelopeAnywhereGoesThroughTheFieldReader(): void
    {
        $reader = new RevealingFieldReader(['properties.cards.1.number' => '4242']);
        $cards  = '[{"number":"none"},{"number":' . self::envelope('bnVtYmVy') . '}]';
        $stored = self::stored('{"card":' . self::envelope('Y2FyZA') . ',"cards":' . $cards . ',"deep":{"a":{"b":' . self::envelope('ZGVlcA') . '}}}');

        $entry = self::project($stored, $reader);

        self::assertSame(['properties.card', 'properties.cards.1.number', 'properties.deep.a.b'], $reader->paths());
        self::assertSame(['Y2FyZA', 'bnVtYmVy', 'ZGVlcA'], array_map(static fn ($field): string => $field->ciphertext, $reader->fields()));
        self::assertSame([self::ID], array_values(array_unique(array_map(static fn ($field): string => $field->entryId, $reader->fields()))));
        self::assertSame([
            'card'  => '[ENCRYPTED]',
            'cards' => [['number' => 'none'], ['number' => '4242']],
            'deep'  => ['a' => ['b' => '[ENCRYPTED]']],
        ], $entry->properties);
    }

    /**
     * A map of exactly an integer `v` from 1 and non-empty strings `k` and `c`
     * is read through the field reader even when the application stored that
     * shape itself, so its `c` is never shown; one whose parts the envelope's
     * rules refuse is `unreadable` without asking the reader; and a map that
     * only resembles one is shown as a map.
     *
     * @return void
     */
    public function testAnEnvelopeShapedPropertyIsAlwaysRead(): void
    {
        $reader = new RevealingFieldReader;
        $stored = self::stored('{"own":{"k":"mine","c":"plain words","v":2},"dirty":{"v":1,"k":"key\u0007","c":"x"},"unsafe":{"v":9007199254740992,"k":"k","c":"x"},'
            . '"text":{"v":"1","k":"k","c":"shown"},"zero":{"v":0,"k":"k","c":"shown"},"more":{"v":1,"k":"k","c":"shown","d":1},"blank":{"v":1,"k":"","c":"shown"},'
            . '"number":{"v":1,"k":"k","c":42},"empty":{"v":1,"k":"k","c":""}}');

        $entry = self::project($stored, $reader);

        self::assertSame(['properties.own'], $reader->paths());
        self::assertSame('[ENCRYPTED]', $entry->properties['own']);
        self::assertSame('[UNREADABLE]', $entry->properties['dirty']);
        self::assertSame('[UNREADABLE]', $entry->properties['unsafe']);
        self::assertSame(['v' => '1', 'k' => 'k', 'c' => 'shown'], $entry->properties['text']);
        self::assertSame(['v' => 0, 'k' => 'k', 'c' => 'shown'], $entry->properties['zero']);
        self::assertSame(['v' => 1, 'k' => 'k', 'c' => 'shown', 'd' => 1], $entry->properties['more']);
        self::assertSame(['v' => 1, 'k' => '', 'c' => 'shown'], $entry->properties['blank']);
        self::assertSame(['v' => 1, 'k' => 'k', 'c' => 42], $entry->properties['number']);
        self::assertSame(['v' => 1, 'k' => 'k', 'c' => ''], $entry->properties['empty']);
        self::assertStringNotContainsString('plain words', (string) json_encode($entry->toArray()));
    }

    /**
     * An owned note, sealed at `_audit.note`, is read through the field reader
     * there, beside the metadata the entry keeps as it was stored.
     *
     * @return void
     */
    public function testAnOwnedNoteGoesThroughTheFieldReader(): void
    {
        $reader = new RevealingFieldReader(['properties._audit.note' => 'called the customer']);
        $entry  = self::project(self::stored('{"amount":"1200.00","_audit":{"note":' . self::envelope('bm90ZQ') . ',"omitted":{"count":1,"paths":["*"]}}}'), $reader);

        self::assertSame(['properties._audit.note'], $reader->paths());
        self::assertSame(['amount' => '1200.00', '_audit' => ['note' => 'called the customer', 'omitted' => ['count' => 1, 'paths' => ['*']]]], $entry->properties);
    }

    /**
     * An IP address stored as an envelope under the `encrypt` mode is read
     * through the field reader at `ip`.
     *
     * @return void
     */
    public function testAnEncryptedIpGoesThroughTheFieldReader(): void
    {
        $sealed   = new RevealingFieldReader;
        $revealed = new RevealingFieldReader(['ip' => '203.0.113.7']);

        self::assertSame('[ENCRYPTED]', self::project(self::stored(fields: ['ip' => self::ENCRYPTED_IP]), $sealed)->ip);
        self::assertSame('203.0.113.7', self::project(self::stored(fields: ['ip' => self::ENCRYPTED_IP]), $revealed)->ip);

        $field = $revealed->fields()[0];

        self::assertSame(['ip'], $revealed->paths());
        self::assertSame('aXAgY2lwaGVydGV4dA', $field->ciphertext);
        self::assertSame('key_42', $field->keyReference);
        self::assertSame(1, $field->version);
    }

    /**
     * Rows of `[ip, what the reader answers]`: values beginning `{` that are
     * not an encrypted address, and an encrypted address the reader reveals as
     * something other than a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>|int|null}>
     */
    public static function provideMalformedIps(): iterable
    {
        yield from [
            'JSON that does not parse' => ['{', null],
            'a missing part'           => ['{"v":1}', null],
            'an extra part'            => ['{"c":"x","k":"y","v":1,"n":2}', null],
            'version 0'                => ['{"c":"x","k":"y","v":0}', null],
            'a nested ciphertext'      => ['{"c":{"a":"x"},"k":"y","v":1}', null],
            'a brace and words'        => ['{not an address}', null],
            'revealed as an integer'   => [self::ENCRYPTED_IP, 42],
            'revealed as null'         => [self::ENCRYPTED_IP, null],
            'revealed as an array'     => [self::ENCRYPTED_IP, ['203.0.113.7']],
        ];
    }

    /**
     * A stored IP beginning `{` that is not exactly an envelope is `unreadable`
     * and never reaches the reader, and one the reader reveals as anything but
     * a string is `unreadable` too.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $ip
     * @param  array<array-key, mixed>|int|null  $answer
     * @return void
     */
    #[DataProvider('provideMalformedIps')]
    public function testAMalformedEncryptedIpIsUnreadable(string $ip, array|int|null $answer): void
    {
        $reader = new RevealingFieldReader(['ip' => $answer]);

        self::assertSame('[UNREADABLE]', self::project(self::stored(fields: ['ip' => $ip]), $reader)->ip);
        self::assertSame($ip === self::ENCRYPTED_IP ? ['ip'] : [], $reader->paths());
    }

    /**
     * Rows of `[ip]`: addresses kept in a mode that does not encrypt, or none.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideStoredIps(): iterable
    {
        yield from [
            'a full address'      => ['203.0.113.7'],
            'a truncated address' => ['203.0.113.0'],
            'a truncated IPv6'    => ['2001:db8::'],
            'a hash'              => ['3f2a9c0d6b1e4f7a8c5d2e9b0a1f6c3d7e4b8a2c9f5d1e6b3a7c0f4d8e2b9a6c'],
            'a brace later on'    => ['x{"c":"x","k":"y","v":1}'],
            'none'                => [null],
        ];
    }

    /**
     * An address stored in any other mode, or none, is shown as stored and
     * never reaches the reader.
     *
     * @param  ?string  $ip
     * @return void
     */
    #[DataProvider('provideStoredIps')]
    public function testATruncatedOrHashedIpIsShownAsStored(?string $ip): void
    {
        $reader = new RevealingFieldReader;

        self::assertSame($ip, self::project(self::stored(fields: ['ip' => $ip]), $reader)->ip);
        self::assertSame([], $reader->paths());
    }

    /**
     * A field whose owner's keys were destroyed reads as `[ERASED]`, a
     * property, a note and an address alike.
     *
     * @return void
     */
    public function testAnErasedFieldReadsAsErased(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => FieldState::ERASED, 'properties._audit.note' => FieldState::ERASED, 'ip' => FieldState::ERASED]);
        $stored = self::stored(self::sealed(['card' => 'Y2FyZA'], '"_audit":{"note":' . self::envelope('bm90ZQ') . '}'), ['ip' => self::ENCRYPTED_IP]);
        $entry  = self::project($stored, $reader);

        self::assertSame(['card' => '[ERASED]', '_audit' => ['note' => '[ERASED]']], $entry->properties);
        self::assertSame('[ERASED]', $entry->ip);
    }

    /**
     * A revealed field is shown as the value the reader gave, a map as it is,
     * and a field the reader calls unreadable as its marker.
     *
     * @return void
     */
    public function testARevealedFieldReadsAsItsValue(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => '4242', 'properties.address' => ['city' => 'Leeds'], 'properties.pin' => FieldState::UNREADABLE]);
        $entry  = self::project(self::stored(self::sealed(['card' => 'Y2FyZA', 'address' => 'YWRkcmVzcw', 'pin' => 'cGlu'])), $reader);

        self::assertSame(['card' => '4242', 'address' => ['city' => 'Leeds'], 'pin' => '[UNREADABLE]'], $entry->properties);
    }

    /**
     * A reader that throws costs each field it throws on, shown as
     * `[UNREADABLE]`, and the failure is reported once for the projection,
     * naming the reader's class alone: nothing it threw is kept, chained or
     * shown, and the next projection is reported once again.
     *
     * @return void
     */
    public function testAThrowingReaderIsUnreadableAndReportedOnce(): void
    {
        $thrown  = new \RuntimeException('plaintext 4242 leaked');
        $handler = new RecordingExceptionHandler;
        $reader  = new RevealingFieldReader([
            'properties.card'        => $thrown,
            'properties._audit.note' => $thrown,
            'ip'                     => $thrown,
            'context.secret'         => $thrown,
            'properties.ok'          => 'fine',
        ]);

        $properties = self::sealed(['card' => 'Y2FyZA', 'ok' => 'b2s'], '"_audit":{"note":' . self::envelope('bm90ZQ') . '}');
        $stored     = self::stored($properties, ['ip' => self::ENCRYPTED_IP], self::sealed(['secret' => 'c2VjcmV0']));

        $entry = self::project($stored, $reader, $handler);

        self::assertSame(['card' => '[UNREADABLE]', 'ok' => 'fine', '_audit' => ['note' => '[UNREADABLE]']], $entry->properties);
        self::assertSame('[UNREADABLE]', $entry->ip);
        self::assertSame(['secret' => '[UNREADABLE]'], $entry->context);
        self::assertCount(1, $handler->reports());

        $report = $handler->reports()[0];

        self::assertInstanceOf(\UnexpectedValueException::class, $report);
        self::assertSame(self::READER_FAILED, $report->getMessage());
        self::assertNull($report->getPrevious());
        self::assertStringNotContainsString('4242', (string) json_encode($entry->toArray()));

        $again = new RecordingExceptionHandler;

        self::project($stored, $reader, $again);

        self::assertCount(1, $again->reports());
    }

    /**
     * The entries of a page are projected together, so a reader that throws on
     * every one of them is reported once for the page, while each entry still
     * shows its field as `[UNREADABLE]`.
     *
     * @return void
     */
    public function testAReaderThatThrowsOnEveryEntryOfAPageIsReportedOnce(): void
    {
        $handler = new RecordingExceptionHandler;
        $reader  = new RevealingFieldReader(['properties.card' => new \RuntimeException('plaintext 4242 leaked')]);
        $stored  = self::stored('{"card":' . self::envelope('Y2FyZA') . '}');

        $entries = (new EntryProjector($reader, $handler))->project([$stored, $stored, $stored]);

        self::assertCount(3, $entries);
        $shown = array_map(static fn (TrailEntry $entry): array => $entry->properties, $entries);

        self::assertSame([['card' => '[UNREADABLE]'], ['card' => '[UNREADABLE]'], ['card' => '[UNREADABLE]']], $shown);
        self::assertCount(1, $handler->reports());
        self::assertSame(self::READER_FAILED, $handler->reports()[0]->getMessage());
    }

    /**
     * A reader that answers is never reported, and a reporter that fails is
     * contained: the entry is still shown.
     *
     * @return void
     */
    public function testOnlyAFailureIsReportedAndABrokenReporterIsContained(): void
    {
        $quiet = new RecordingExceptionHandler;

        self::project(self::stored('{"card":' . self::envelope('Y2FyZA') . '}', ['ip' => self::ENCRYPTED_IP]), new RevealingFieldReader, $quiet);

        self::assertSame([], $quiet->reports());

        $broken = new RecordingExceptionHandler(throwsOnReport: true);
        $entry  = self::project(self::stored('{"card":' . self::envelope('Y2FyZA') . '}'), new RevealingFieldReader(['properties.card' => new \LogicException('x')]), $broken);

        self::assertSame(['card' => '[UNREADABLE]'], $entry->properties);
        self::assertCount(1, $broken->reports());
    }

    /**
     * With the package's own reader, no ciphertext of a property, a nested
     * envelope, an owned note, the context or the address reaches any string
     * the shown entry holds.
     *
     * @return void
     */
    public function testNoCiphertextReachesTheEntry(): void
    {
        $ciphertexts = ['Y2FyZCBjaXBoZXJ0ZXh0', 'bGlzdCBjaXBoZXJ0ZXh0', 'bm90ZSBjaXBoZXJ0ZXh0', 'Y29udGV4dCBjaXBoZXJ0ZXh0', 'aXAgY2lwaGVydGV4dA'];
        $properties  = self::sealed(['card' => $ciphertexts[0]], '"cards":[' . self::envelope($ciphertexts[1]) . '],"_audit":{"note":' . self::envelope($ciphertexts[2]) . '}');
        $stored      = self::stored($properties, ['ip' => self::ENCRYPTED_IP], '{"route":"x","token":' . self::envelope($ciphertexts[3]) . '}');

        $strings = self::stringsOf(self::project($stored)->toArray());

        self::assertNotEmpty($strings);

        foreach ($ciphertexts as $ciphertext) {
            self::assertStringContainsString($ciphertext, $stored->line(), $ciphertext);

            foreach ($strings as $string) {
                self::assertStringNotContainsString($ciphertext, $string, $ciphertext);
            }
        }
    }

    /**
     * The context is read as the properties are, an envelope in it through the
     * field reader at its path under `context`.
     *
     * @return void
     */
    public function testTheContextIsReadAsThePropertiesAre(): void
    {
        $reader = new RevealingFieldReader(['context.headers.token' => FieldState::ERASED]);
        $entry  = self::project(self::stored(context: '{"route":"invoices.approve","headers":{"token":' . self::envelope('dG9rZW4') . '},"empty":{}}'), $reader);

        self::assertSame(['context.headers.token'], $reader->paths());
        self::assertSame(['route' => 'invoices.approve', 'headers' => ['token' => '[ERASED]'], 'empty' => []], $entry->context);
        self::assertSame([], self::project(self::stored(context: null))->context);
        self::assertSame([], self::project(self::stored('null'))->properties);
    }

    /**
     * The properties, the address and then the context are read, in that order.
     *
     * @return void
     */
    public function testTheFieldsAreReadInOrder(): void
    {
        $reader = new RevealingFieldReader;

        self::project(self::stored('{"card":' . self::envelope('Y2FyZA') . '}', ['ip' => self::ENCRYPTED_IP], '{"token":' . self::envelope('dG9rZW4') . '}'), $reader);

        self::assertSame(['properties.card', 'ip', 'context.token'], $reader->paths());
    }

    /**
     * A descriptor the artifact inspector accepts is lifted out of the
     * properties to the entry's manifest, as its kind, count and digest; the
     * metadata it was in is dropped when it held nothing else and kept, less
     * the descriptor, when it did; and the stored entry is left as it was.
     *
     * @return void
     */
    public function testTheManifestIsLiftedOutOfTheProperties(): void
    {
        $alone  = self::stored('{"batch":"march","_audit":{"manifest":' . self::descriptor() . '}}');
        $beside = self::stored('{"batch":"march","_audit":{"omitted":{"count":1,"paths":["*"]},"manifest":' . self::descriptor() . '}}');
        $line   = $alone->line();

        $entry = self::project($alone);

        self::assertSame(['kind' => 'bulk', 'count' => 3, 'digest' => self::DIGEST], $entry->manifest);
        self::assertSame(['batch' => 'march'], $entry->properties);
        self::assertSame(['batch' => 'march', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], self::project($beside)->properties);
        self::assertSame(['kind' => 'bulk', 'count' => 3, 'digest' => self::DIGEST], self::project($beside)->manifest);
        self::assertSame($line, $alone->line());
        self::assertNull(self::project(self::stored())->manifest);
    }

    /**
     * Rows of `[descriptor]`: descriptors the artifact inspector refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedDescriptors(): iterable
    {
        yield from [
            'an unknown kind'   => [self::descriptor(kind: 'archive')],
            'a bulk count of 0' => [self::descriptor(count: 0)],
            'an extra key'      => [substr(self::descriptor(), 0, -1) . ',"members":"x"}'],
            'a missing key'     => ['{"artifact_id":"0192f5a0-7c1e-7000-8000-00000000000a","kind":"bulk","count":3}'],
            'not a map'         => ['"bulk"'],
            'a count as text'   => [self::descriptor(count: '"3"')],
        ];
    }

    /**
     * A descriptor the artifact inspector refuses is never shown: the entry has
     * no manifest, the descriptor is dropped from the properties, and the page
     * is not refused for it.
     *
     * @param  string  $descriptor
     * @return void
     */
    #[DataProvider('provideMalformedDescriptors')]
    public function testAMalformedDescriptorIsNeverShown(string $descriptor): void
    {
        $entry = self::project(self::stored('{"batch":"march","_audit":{"manifest":' . $descriptor . '}}'));

        self::assertNull($entry->manifest);
        self::assertSame(['batch' => 'march'], $entry->properties);
    }

    /**
     * References, enums, versions and times are built from the stored
     * columns; a reference of which only one part is stored is none.
     *
     * @return void
     */
    public function testTheColumnsAreTyped(): void
    {
        $fields = [
            'outcome'          => 'denied',
            'reason'           => 'over_limit',
            'principal_type'   => 'service',
            'principal_id'     => '9',
            'subject_type'     => null,
            'tenant_id'        => null,
            'origin'           => null,
            'provenance'       => 'imported',
            'source_record_id' => 'legacy-9',
        ];

        $entry = self::project(self::stored(fields: $fields));

        self::assertSame(self::ID, $entry->id);
        self::assertSame('invoice.approved', $entry->event);
        self::assertSame(1, $entry->eventVersion);
        self::assertSame(1, $entry->recordVersion);
        self::assertSame(1, $entry->integrityVersion);
        self::assertSame('finance', $entry->category);
        self::assertSame(Outcome::DENIED, $entry->outcome);
        self::assertSame('over_limit', $entry->reason);
        self::assertEquals(Reference::of('user', '42'), $entry->actor);
        self::assertNull($entry->subject);
        self::assertEquals(Reference::of('service', '9'), $entry->principal);
        self::assertNull($entry->tenant);
        self::assertNull($entry->origin);
        self::assertSame(Provenance::IMPORTED, $entry->provenance);
        self::assertSame('legacy-9', $entry->sourceRecordId);
        self::assertSame('web', $entry->guard);
        self::assertSame('app:ticket-123', $entry->correlationId);
        self::assertSame('app-eu-1', $entry->sourceId);
        self::assertSame('eu-west-2', $entry->sourceRegion);
        self::assertSame('Mozilla/5.0', $entry->userAgent);
        self::assertSame(self::KEY_ID, $entry->keyId);
        self::assertSame(self::HMAC, $entry->hmac);
        self::assertSame(RecordFactory::OCCURRED_AT, $entry->toArray()['occurred_at']);
        self::assertSame(RecordFactory::RECORDED_AT, $entry->toArray()['recorded_at']);
        self::assertSame(Origin::HTTP, self::project(self::stored())->origin);
    }

    /**
     * Rows of `[column, stored value]`: columns whose stored value the shown
     * entry cannot hold.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnshowableColumns(): iterable
    {
        yield from [
            'an unknown outcome'    => ['outcome', 'maybe'],
            'an unknown origin'     => ['origin', 'carrier_pigeon'],
            'an unknown provenance' => ['provenance', 'rumoured'],
            'properties as text'    => ['properties', '"text"'],
            'a context as a number' => ['context', '5'],
        ];
    }

    /**
     * A column the shown entry cannot hold is refused, naming the column and
     * never the value.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideUnshowableColumns')]
    public function testAColumnTheEntryCannotHoldIsRefused(string $column, string $value): void
    {
        $stored = StoredEntry::fromRow([$column => $value] + self::row(), new RowCodec);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A stored entry\'s `%s` cannot be shown.', $column));

        self::project($stored);
    }

    /**
     * An entry recorded through the facade, with a field encrypted under the
     * actor, a note owned by the actor and an address in the `encrypt` mode, is
     * read back from the table and shown with each fragment read through the
     * field reader and none of its ciphertexts.
     *
     * @return void
     */
    public function testARecordedEntryIsReadThroughTheSeam(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.ip', 'encrypt');
        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);
        $recorder->define(EventDefinition::for('invoice.approved')->encrypt('card', KeyOwner::ACTOR));

        AuditLog::swap($recorder);

        $pending = AuditLog::event('invoice.approved')->by(Reference::of('user', '42'))->withProperties(['card' => '4242'])->withNote('called the customer', KeyOwner::ACTOR);
        $pending->fillClient('203.0.113.7', null);

        $record = $pending->immediately()->record();
        $row    = (array) DB::table(EntrySettings::table())->where('id', $record->id)->first();
        $reader = new RevealingFieldReader(['properties.card' => '4242']);
        $entry  = self::project(StoredEntry::fromRow($row, new RowCodec), $reader);

        self::assertSame(['properties.card', 'properties._audit.note', 'ip'], $reader->paths());
        self::assertSame('4242', $entry->properties['card']);
        self::assertSame(['note' => '[ENCRYPTED]'], $entry->properties['_audit']);
        self::assertSame('[ENCRYPTED]', $entry->ip);

        foreach ([base64_encode('called the customer'), base64_encode('203.0.113.7')] as $ciphertext) {
            self::assertStringNotContainsString($ciphertext, (string) json_encode($entry->toArray()));
        }
    }

    /**
     * The projector the package resolves reads through the field reader bound
     * in the container.
     *
     * @return void
     */
    public function testTheProjectorReadsThroughTheBoundReader(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => '4242']);

        app()->instance(FieldReader::class, $reader);

        $entry = app(EntryProjector::class)->project([self::stored('{"card":' . self::envelope('Y2FyZA') . '}')])[0];

        self::assertSame(['card' => '4242'], $entry->properties);
        self::assertSame(['properties.card'], $reader->paths());
    }

    /**
     * The entry of the stored entry, read through the reader given, or the
     * package's own, and reported to the handler given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\FieldReader  $reader
     * @param  ?\Tests\Fixtures\Privacy\RecordingExceptionHandler  $handler
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private static function project(StoredEntry $stored, ?FieldReader $reader = null, ?RecordingExceptionHandler $handler = null): TrailEntry
    {
        return (new EntryProjector($reader ?? new SealedFieldReader, $handler ?? new RecordingExceptionHandler))->project([$stored])[0];
    }

    /**
     * A stored entry of a captured record of an approved invoice, with the
     * fields given in place of its own and its JSON columns as given.
     *
     * @param  string  $properties
     * @param  array<string, ?string>  $fields
     * @param  ?string  $context
     * @return \SineMacula\Laravel\AuditLog\Querying\StoredEntry
     */
    private static function stored(string $properties = '{"amount":"1200.00"}', array $fields = [], ?string $context = '{"route":"invoices.approve"}'): StoredEntry
    {
        return StoredEntry::fromRow(['properties' => $properties, 'context' => $context] + self::row($fields), new RowCodec);
    }

    /**
     * The stored row of a captured record of an approved invoice, with the
     * fields given in place of its own, finalised at `RECORDED_AT` under the
     * fixed key id and HMAC.
     *
     * @param  array<string, ?string>  $fields
     * @return array<string, int|string|null>
     */
    private static function row(array $fields = []): array
    {
        $record    = RecordFactory::withFields(['id' => self::ID, ...$fields], RecordFactory::captured(id: self::ID));
        $finalised = new FinalisedRecord($record, RecordFactory::RECORDED_AT, 1, self::KEY_ID, self::HMAC);

        return (new RowCodec)->encode($finalised);
    }

    /**
     * An envelope of version 1 under `key_42`, holding the ciphertext.
     *
     * @param  string  $ciphertext
     * @return string
     */
    private static function envelope(string $ciphertext): string
    {
        return sprintf('{"v":1,"k":"key_42","c":"%s"}', $ciphertext);
    }

    /**
     * A JSON map of an envelope under each key holding the ciphertext given,
     * then any further members given as JSON.
     *
     * @param  array<string, string>  $ciphertexts
     * @param  ?string  $more
     * @return string
     */
    private static function sealed(array $ciphertexts, ?string $more = null): string
    {
        $members = array_map(static fn (string $key, string $ciphertext): string => sprintf('"%s":%s', $key, self::envelope($ciphertext)), array_keys($ciphertexts), $ciphertexts);

        return '{' . implode(',', [...$members, ...($more === null ? [] : [$more])]) . '}';
    }

    /**
     * A descriptor of an artifact, as JSON, of the kind and count given.
     *
     * @param  string  $kind
     * @param  int|string  $count
     * @return string
     */
    private static function descriptor(string $kind = 'bulk', int|string $count = 3): string
    {
        return sprintf('{"artifact_id":"0192f5a0-7c1e-7000-8000-00000000000a","kind":"%s","digest":"%s","count":%s}', $kind, self::DIGEST, $count);
    }

    /**
     * Every string the value holds, its keys included, at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @return list<string>
     */
    private static function stringsOf(array $value): array
    {
        $strings = [];

        foreach ($value as $key => $member) {
            $strings[] = (string) $key;

            if (is_array($member)) {
                array_push($strings, ...self::stringsOf($member));

                continue;
            }

            if (!is_string($member)) {
                continue;
            }

            $strings[] = $member;
        }

        return $strings;
    }
}
