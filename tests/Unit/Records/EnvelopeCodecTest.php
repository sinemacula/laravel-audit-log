<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Config\Repository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the envelope codec: the canonical envelope it encodes and its
 * bound; decoding without loss, so numeric-key maps, empty containers, `null`
 * columns, an imported record's fields, Unicode and the largest integers come
 * back with the same canonical bytes and signature; each refusal as its own
 * failure, in a fixed order; that nothing is minimised, sanitised or finalised
 * again; and that no refusal carries the envelope.
 *
 * Envelopes are signed here directly with the key's secret, as the signer
 * signs, so a value capture never produces (an object at the top of a column, a
 * redactable value) can be signed and read back. The ring and the signer are
 * the package's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeCodec::class)]
final class EnvelopeCodecTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string When the record is finalised: after the activity occurred. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string The signing key's id. */
    private const string KEY_ID = 'k2026';

    /** @var string The signing key's secret, as its own 32 bytes. */
    private const string CURRENT_SECRET = 'envelope-codec current secret 32';

    /** @var string The retired key's id. */
    private const string RETIRED_ID = 'k2025';

    /** @var string The retired key's secret, as its own 32 bytes. */
    private const string RETIRED_SECRET = 'envelope-codec retired secret 32';

    /** @var string The `app.key` a ring without explicit keys derives its key from. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string An HMAC that stands in until the envelope is signed. */
    private const string PLACEHOLDER_HMAC = '0000000000000000000000000000000000000000000000000000000000000000';

    /** @var string The import batch an imported record came in. */
    private const string IMPORT_BATCH_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string A string the tests replace with raw JSON that no PHP value encodes canonically. */
    private const string MARKER = '__raw__';

    /** @var list<string> The entries table's columns, in order. */
    private const array COLUMNS = [
        'id', 'record_version', 'event', 'event_version', 'category', 'outcome', 'reason', 'actor_type', 'actor_id',
        'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id', 'credential_id',
        'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'origin', 'provenance', 'source_id',
        'source_region', 'source_record_id', 'import_batch_id', 'ip', 'user_agent', 'context', 'properties',
        'occurred_at', 'recorded_at', 'integrity_version', 'key_id', 'hmac',
    ];

    /**
     * Restore UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        parent::tearDown();
    }

    /**
     * The bounds are two 16 MiB budgets and 64 KiB of other columns, and six
     * times that for an input, since a spill line writes `%` as six bytes.
     *
     * @return void
     */
    public function testTheBoundsArePinned(): void
    {
        self::assertSame((2 * 16 * 1024 * 1024) + (64 * 1024), EnvelopeCodec::MAX_BYTES);
        self::assertSame(6 * EnvelopeCodec::MAX_BYTES, EnvelopeCodec::MAX_ENCODED_BYTES);
    }

    /**
     * A record is encoded as the canonical encoding of its 36 columns, keys
     * sorted, exactly as the signer encodes what it signs.
     *
     * @return void
     */
    public function testEncodesTheCanonicalEnvelope(): void
    {
        $finalised = self::signer()->sign(RecordFactory::captured(id: self::ID), self::RECORDED_AT);
        $envelope  = self::codec()->encode($finalised);
        $decoded   = json_decode($envelope, true, 512, JSON_THROW_ON_ERROR);

        self::assertSame(CanonicalEncoder::encode($finalised->toArray()), $envelope);
        self::assertIsArray($decoded);

        $keys = self::COLUMNS;
        sort($keys, SORT_STRING);

        self::assertSame($keys, array_keys($decoded));
        self::assertSame($finalised->hmac, $decoded['hmac']);
    }

    /**
     * A record whose envelope is exactly the bound is encoded, and one byte
     * more is refused as oversize, naming its id (protects against an
     * off-by-one mutation of the bound).
     *
     * @return void
     */
    public function testRefusesARecordOverTheBound(): void
    {
        self::withMemory(static function (): void {

            $codec = self::codec();
            $base  = strlen($codec->encode(self::padded(0)));

            self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($codec->encode(self::padded(EnvelopeCodec::MAX_BYTES - $base))));

            try {
                $codec->encode(self::padded(EnvelopeCodec::MAX_BYTES - $base + 1));
                self::fail('Expected an envelope over the bound to be refused.');
            } catch (EnvelopeRejectedException $exception) {
                self::assertSame(EnvelopeFailure::OVERSIZE, $exception->failure);
                self::assertSame(self::ID, $exception->id);
            }
        });
    }

    /**
     * Rows of `[columns in place of the captured record's]`: numeric-key maps,
     * alone, out of order and nested three deep; empty lists and empty maps,
     * nested and at the top; a one-key map whose key is `0` and a map with
     * sequential numeric keys, signed from objects; `null` context and
     * properties; an imported record's fields; 4-byte Unicode; the largest
     * integers; and a decimal as a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideVectors(): iterable
    {
        yield from [
            'a map with one numeric key'           => [['properties' => [5 => 'a']]],
            'a map with numeric keys out of order' => [['properties' => [1 => 'x', 0 => 'y']]],
            'numeric-key maps nested three deep'   => [['properties' => ['a' => ['b' => ['c' => [5 => 'a', 'd' => [1 => 'x', 0 => 'y']]]]]]],
            'an empty list nested'                 => [['properties' => ['lines' => [], 'more' => [[]]]]],
            'an empty list at the top'             => [['context' => [], 'properties' => []]],
            'an empty map nested'                  => [['properties' => ['meta' => new \stdClass, 'list' => [new \stdClass]]]],
            'an empty map at the top'              => [['context' => new \stdClass, 'properties' => new \stdClass]],
            'a one-key map whose key is 0'         => [['properties' => (object) ['0' => 'a']]],
            'a map with sequential numeric keys'   => [['properties' => (object) ['0' => 'a', '1' => 'b'], 'context' => ['n' => (object) ['0' => (object) ['0' => 'x']]]]],
            'null context and properties'          => [['context' => null, 'properties' => null]],
            'an imported record'                   => [['provenance' => 'imported', 'source_record_id' => 'old-42', 'import_batch_id' => self::IMPORT_BATCH_ID, 'origin' => null]],
            '4-byte Unicode'                       => [['properties' => ['emoji' => "\u{1F600} \u{1F469}\u{200D}\u{1F4BB}", "\u{1F511}" => 'key'], 'user_agent' => "\u{1F600}"]],
            'the largest integers'                 => [['properties' => ['safe' => 9007199254740991, 'max' => PHP_INT_MAX, 'min' => PHP_INT_MIN]]],
            'a decimal as a string'                => [['properties' => ['amount' => '1200.50', 'zero' => '0.0']]],
        ];
    }

    /**
     * A decoded envelope encodes to exactly the bytes it was decoded from.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideVectors')]
    public function testDecodingGivesTheSameCanonicalBytes(array $fields): void
    {
        $envelope = self::envelope($fields);
        $codec    = self::codec();

        self::assertSame($envelope, $codec->encode($codec->decode($envelope)));
    }

    /**
     * A decoded envelope keeps its signature and how it was signed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideVectors')]
    public function testDecodingKeepsTheHmac(array $fields): void
    {
        $columns = self::columns($fields);
        $decoded = self::codec()->decode(CanonicalEncoder::encode($columns));

        self::assertSame($columns['hmac'], $decoded->hmac);
        self::assertSame(self::KEY_ID, $decoded->keyId);
        self::assertSame(1, $decoded->integrityVersion);
        self::assertSame(self::RECORDED_AT, $decoded->recordedAt);
    }

    /**
     * A decoded envelope gives every column in table order, each of the type
     * and canonical value it was decoded as: an object stays an object and a
     * list a list.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideVectors')]
    public function testDecodingKeepsEveryColumn(array $fields): void
    {
        $envelope = self::envelope($fields);
        $expected = get_object_vars(self::object($envelope));
        $actual   = self::codec()->decode($envelope)->toArray();

        self::assertSame(self::COLUMNS, array_keys($actual));

        foreach (self::COLUMNS as $column) {
            self::assertSame(get_debug_type($expected[$column]), get_debug_type($actual[$column]), $column);
            self::assertSame(CanonicalEncoder::encode($expected[$column]), CanonicalEncoder::encode($actual[$column]), $column);
        }
    }

    /**
     * A decoded record verifies under the signer, as given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideVectors')]
    public function testADecodedRecordVerifies(array $fields): void
    {
        self::assertTrue(self::signer()->verifies(self::codec()->decode(self::envelope($fields))->toArray()));
    }

    /**
     * Decoding the encoding of a decoded record changes nothing: its envelope,
     * its record's array view and its signature are the same.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideVectors')]
    public function testDecodingTwiceChangesNothing(array $fields): void
    {
        $codec = self::codec();
        $once  = $codec->decode(self::envelope($fields));
        $twice = $codec->decode($codec->encode($once));

        self::assertSame($codec->encode($once), $codec->encode($twice));
        self::assertSame($once->record->toArray(), $twice->record->toArray());
        self::assertSame($once->hmac, $twice->hmac);
    }

    /**
     * The record keeps array views of its JSON columns for reading, while the
     * finalised record gives them as decoded: a map with sequential numeric
     * keys reads as a list and stays a map, and `{}` reads as `[]` and stays
     * `{}`.
     *
     * @return void
     */
    public function testTheRecordKeepsArrayViewsOfItsJsonColumns(): void
    {
        $decoded = self::codec()->decode(self::envelope(['context' => new \stdClass, 'properties' => (object) ['0' => 'a', '1' => 'b']]));

        self::assertSame([], $decoded->record->context);
        self::assertSame(['a', 'b'], $decoded->record->properties);
        self::assertEquals(new \stdClass, $decoded->toArray()['context']);
        self::assertEquals((object) ['0' => 'a', '1' => 'b'], $decoded->toArray()['properties']);
    }

    /**
     * An envelope signed with a key's secret but altered after, in any column
     * or in its signature, is a signature mismatch naming its id.
     *
     * @return void
     */
    public function testATamperedValueIsASignatureMismatch(): void
    {
        $tampered = [
            'a column'           => ['event' => 'invoice.voided'],
            'a nested value'     => ['properties' => ['amount' => '1300.00']],
            'a key'              => ['properties' => ['amounts' => '1200.00']],
            'an object to list'  => ['context' => []],
            'the time recorded'  => ['recorded_at' => '2026-11-01T12:00:01.654322Z'],
            'the signature'      => ['hmac' => str_repeat('a', 64)],
            'the key that signs' => ['key_id' => self::RETIRED_ID],
        ];

        $codec = self::codec([self::KEY_ID => self::CURRENT_SECRET, self::RETIRED_ID => self::RETIRED_SECRET]);

        foreach ($tampered as $what => $after) {
            $exception = self::rejection(self::envelope(['context' => new \stdClass], $after), codec: $codec);

            self::assertSame(EnvelopeFailure::SIGNATURE_MISMATCH, $exception->failure, $what);
            self::assertSame(self::ID, $exception->id, $what);
        }
    }

    /**
     * An envelope with a column its version does not have is malformed, even
     * one the signature does not cover, and so is an `unsigned` that is not
     * `true`.
     *
     * @return void
     */
    public function testAnAddedKeyIsMalformed(): void
    {
        foreach (['extra' => null, 'unsigned' => false, 'Id' => self::ID, '0' => 'a'] as $column => $value) {
            $exception = self::rejection(self::envelope([], [$column => $value]));

            self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure, (string) $column);
            self::assertSame(self::ID, $exception->id, (string) $column);
        }
    }

    /**
     * Rows of `[column]`: each of the 36 columns.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideColumns(): iterable
    {
        foreach (self::COLUMNS as $column) {
            yield $column => [$column];
        }
    }

    /**
     * An envelope without any one column is malformed, a missing version
     * included, never unsupported: a missing column is never read as `null`.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideColumns')]
    public function testAMissingKeyIsMalformed(string $column): void
    {
        $exception = self::rejection(self::without($column));

        self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure);
        self::assertSame($column === 'id' ? null : self::ID, $exception->id);
    }

    /**
     * Rows of `[column, value]`: a value of another kind for each kind of
     * column, and for each version.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideWrongKinds(): iterable
    {
        yield from [
            'a string column holding null'                 => ['event', null],
            'a string column holding an integer'           => ['category', 1],
            'a string column holding a list'               => ['outcome', ['success']],
            'the key id holding an integer'                => ['key_id', 2026],
            'the HMAC holding null'                        => ['hmac', null],
            'a nullable column holding an integer'         => ['reason', 5],
            'a nullable column holding a boolean'          => ['guard', false],
            'a nullable column holding an object'          => ['actor_id', new \stdClass],
            'an integer column holding a digit string'     => ['event_version', '1'],
            'an integer column holding null'               => ['event_version', null],
            'an integer column holding a boolean'          => ['event_version', true],
            'the record version holding a digit string'    => ['record_version', '1'],
            'the record version holding null'              => ['record_version', null],
            'the integrity version holding a digit string' => ['integrity_version', '1'],
            'an instant column holding the stored form'    => ['occurred_at', '2026-11-01 12:00:00.123456'],
            'an instant column without microseconds'       => ['recorded_at', '2026-11-01T12:00:01Z'],
            'an instant column on a date that is not'      => ['recorded_at', '2026-02-30T12:00:01.000000Z'],
            'an instant column holding null'               => ['occurred_at', null],
            'an instant column holding an integer'         => ['recorded_at', 1793534401],
            'a JSON column holding a string'               => ['context', '{}'],
            'a JSON column holding an integer'             => ['properties', 1],
            'a JSON column holding a boolean'              => ['properties', true],
        ];
    }

    /**
     * An envelope with a value of another kind in any column is malformed,
     * whether or not the value is signed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideWrongKinds')]
    public function testAWrongKindIsMalformed(string $column, mixed $value): void
    {
        self::assertSame(EnvelopeFailure::MALFORMED, self::rejection(self::envelope([$column => $value]))->failure);
        self::assertSame(EnvelopeFailure::MALFORMED, self::rejection(self::envelope([], [$column => $value]))->failure);
    }

    /**
     * A float anywhere is malformed, never a mismatch: it has no canonical
     * form, so the signature cannot be checked, and nothing the package signs
     * holds one.
     *
     * @return void
     */
    public function testAFloatIsMalformed(): void
    {
        $envelopes = [
            'in a property'      => self::raw(self::envelope(['properties' => ['ratio' => self::MARKER]]), '0.5'),
            'a whole float'      => self::raw(self::envelope(['properties' => ['ratio' => self::MARKER]]), '1.0'),
            'an exponent'        => self::raw(self::envelope(['properties' => ['ratio' => self::MARKER]]), '1e3'),
            'a version as float' => self::raw(self::envelope([], ['event_version' => self::MARKER]), '1.0'),
        ];

        foreach ($envelopes as $where => $envelope) {
            $exception = self::rejection($envelope);

            self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure, $where);
            self::assertSame(self::ID, $exception->id, $where);
        }
    }

    /**
     * An integer past PHP's range decodes as a float, which is malformed in a
     * property and in an integer column alike.
     *
     * @return void
     */
    public function testAnIntegerPastTheRangeIsMalformed(): void
    {
        foreach (['9223372036854775808', '-9223372036854775809'] as $integer) {
            $inAProperty = self::raw(self::envelope(['properties' => ['n' => self::MARKER]]), $integer);
            $inAColumn   = self::raw(self::envelope([], ['event_version' => self::MARKER]), $integer);
            $asAVersion  = self::raw(self::envelope([], ['record_version' => self::MARKER]), $integer);

            self::assertSame(EnvelopeFailure::MALFORMED, self::rejection($inAProperty)->failure, $integer);
            self::assertSame(EnvelopeFailure::MALFORMED, self::rejection($inAColumn)->failure, $integer);
            self::assertSame(EnvelopeFailure::MALFORMED, self::rejection($asAVersion)->failure, $integer);
        }
    }

    /**
     * Rows of `[input]`: inputs that are not JSON.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidJson(): iterable
    {
        yield from [
            'nothing'                => [''],
            'whitespace'             => [" \n"],
            'an open brace'          => ['{'],
            'a cut-off envelope'     => ['{"id":"' . self::ID . '"'],
            'a trailing comma'       => ['{"id":"' . self::ID . '",}'],
            'trailing bytes'         => ['{"id":"' . self::ID . '"} x'],
            'two envelopes'          => ['{"id":"' . self::ID . '"}{"id":"' . self::ID . '"}'],
            'invalid UTF-8'          => ["{\"id\":\"\xff\"}"],
            'a byte-order mark'      => ["\u{FEFF}{\"id\":\"" . self::ID . '"}'],
            'a single-quoted string' => ['{\'id\':\'' . self::ID . '\'}'],
            'a bare word'            => ['nul'],
        ];
    }

    /**
     * Input that is not JSON is malformed, and the refusal names no id, even
     * one it could have read.
     *
     * @param  string  $input
     * @return void
     */
    #[DataProvider('provideInvalidJson')]
    public function testInvalidJsonIsMalformed(string $input): void
    {
        $exception = self::rejection($input);

        self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure);
        self::assertNull($exception->id);
    }

    /**
     * JSON that is not an object (a list, the envelope inside a list, a string,
     * a number, a boolean or `null`) is malformed.
     *
     * @return void
     */
    public function testAListIsMalformed(): void
    {
        foreach (['[]', '[' . self::envelope() . ']', '"' . self::ID . '"', '1', 'true', 'null'] as $input) {
            $exception = self::rejection($input);

            self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure, $input);
            self::assertNull($exception->id, $input);
        }
    }

    /**
     * An envelope signed with a key the ring does not hold is unverifiable,
     * never a mismatch: under a ring without that key, under one that derives
     * its key from `app.key`, and under a key id the ring never had.
     *
     * @return void
     */
    public function testAnUnknownKeyIsDistinct(): void
    {
        $retiredOnly = self::codec([self::RETIRED_ID => self::RETIRED_SECRET], self::RETIRED_ID);
        $derived     = self::codec([], null);

        $cases = [
            'a ring without the key' => [self::envelope(), $retiredOnly],
            'a derived ring'         => [self::envelope(), $derived],
            'a key never held'       => [self::envelope(['key_id' => 'k1999']), self::codec()],
        ];

        foreach ($cases as $what => [$envelope, $codec]) {
            $exception = self::rejection($envelope, codec: $codec);

            self::assertSame(EnvelopeFailure::UNKNOWN_KEY, $exception->failure, $what);
            self::assertSame(self::ID, $exception->id, $what);
        }
    }

    /**
     * An integrity version this release does not verify is unsupported, never
     * malformed or a mismatch.
     *
     * @return void
     */
    public function testAnUnsupportedIntegrityVersionIsDistinct(): void
    {
        foreach ([2, 0, -1, PHP_INT_MAX] as $version) {
            $exception = self::rejection(self::envelope(['integrity_version' => $version]));

            self::assertSame(EnvelopeFailure::UNSUPPORTED_VERSION, $exception->failure, (string) $version);
            self::assertSame(self::ID, $exception->id, (string) $version);
        }
    }

    /**
     * A record version this release does not read is unsupported, never
     * malformed, even though the schema of that version is unknown.
     *
     * @return void
     */
    public function testAnUnsupportedRecordVersionIsDistinct(): void
    {
        foreach ([2, 0, -1] as $version) {
            $exception = self::rejection(self::envelope(['record_version' => $version], ['extra' => true]));

            self::assertSame(EnvelopeFailure::UNSUPPORTED_VERSION, $exception->failure, (string) $version);
            self::assertSame(self::ID, $exception->id, (string) $version);
        }
    }

    /**
     * A line that says it is unsigned is counted as unsigned, never verified,
     * whatever else it holds or lacks.
     *
     * @return void
     */
    public function testAnUnsignedLineIsDistinct(): void
    {
        $signed  = self::columns([], ['unsigned' => true]);
        $bare    = ['id' => self::ID, 'unsigned' => true];
        $without = array_diff_key($signed, ['hmac' => true, 'key_id' => true, 'integrity_version' => true]);

        foreach (['with every column' => $signed, 'with an id alone' => $bare, 'without a signature' => $without] as $what => $columns) {
            $exception = self::rejection(CanonicalEncoder::encode($columns));

            self::assertSame(EnvelopeFailure::UNSIGNED, $exception->failure, $what);
            self::assertSame(self::ID, $exception->id, $what);
        }
    }

    /**
     * An envelope whose id is not the one expected is an id mismatch naming the
     * envelope's own id; the expected id, exactly, passes, and no id expected
     * passes too.
     *
     * @return void
     */
    public function testTheWrongIdIsAnIdMismatch(): void
    {
        $codec    = self::codec();
        $envelope = self::envelope();

        foreach (['01932b4e-8a40-7000-8000-000000000002', strtoupper(self::ID), '', self::ID . ' '] as $expected) {
            $exception = self::rejection($envelope, $expected);

            self::assertSame(EnvelopeFailure::ID_MISMATCH, $exception->failure, $expected);
            self::assertSame(self::ID, $exception->id, $expected);
        }

        self::assertSame(self::ID, $codec->decode($envelope, self::ID)->record->id);
        self::assertSame(self::ID, $codec->decode($envelope)->record->id);
    }

    /**
     * An input longer than the encoded bound is refused as oversize before it
     * is parsed, so even one that is not JSON is never read; an input exactly
     * as long is parsed (protects against an off-by-one mutation of the bound).
     *
     * @return void
     */
    public function testAnOversizeInputIsRefusedBeforeItIsParsed(): void
    {
        self::withMemory(static function (): void {

            $over      = str_repeat('[', EnvelopeCodec::MAX_ENCODED_BYTES + 1);
            $exception = self::rejection($over);

            self::assertSame(EnvelopeFailure::OVERSIZE, $exception->failure);
            self::assertNull($exception->id);

            unset($over);

            self::assertSame(EnvelopeFailure::MALFORMED, self::rejection(str_repeat('[', EnvelopeCodec::MAX_ENCODED_BYTES))->failure);
        });
    }

    /**
     * Rows of `[input, expected id, failure]`: two failures at once, and the
     * one checked first.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure}>
     */
    public static function provideOrder(): iterable
    {
        $other = '01932b4e-8a40-7000-8000-000000000002';
        $float = self::raw(self::envelope(['key_id' => 'k1999', 'properties' => [self::MARKER]]), '0.5');

        yield from [
            'not an object before unsigned'            => ['[{"unsigned":true}]', null, EnvelopeFailure::MALFORMED],
            'unsigned before a missing version'        => [self::without('record_version', [], ['unsigned' => true]), null, EnvelopeFailure::UNSIGNED],
            'unsigned before an unsupported version'   => [self::envelope(['record_version' => 2], ['unsigned' => true]), null, EnvelopeFailure::UNSIGNED],
            'a missing before an unsupported version'  => [self::without('record_version', ['integrity_version' => 2]), null, EnvelopeFailure::MALFORMED],
            'a mistyped before an unsupported version' => [self::envelope(['record_version' => 2], ['integrity_version' => '1']), null, EnvelopeFailure::MALFORMED],
            'an unsupported version before a column'   => [self::envelope(['integrity_version' => 2], ['extra' => true]), null, EnvelopeFailure::UNSUPPORTED_VERSION],
            'an unsupported version before a kind'     => [self::envelope(['record_version' => 2], ['event' => 1]), null, EnvelopeFailure::UNSUPPORTED_VERSION],
            'an added column before an unknown key'    => [self::envelope(['key_id' => 'k1999'], ['extra' => true]), null, EnvelopeFailure::MALFORMED],
            'a wrong kind before a mismatch'           => [self::envelope([], ['event' => 1, 'hmac' => str_repeat('a', 64)]), null, EnvelopeFailure::MALFORMED],
            'an unknown key before a mismatch'         => [self::envelope(['key_id' => 'k1999'], ['hmac' => str_repeat('a', 64)]), null, EnvelopeFailure::UNKNOWN_KEY],
            'an unknown key before a float'            => [$float, null, EnvelopeFailure::UNKNOWN_KEY],
            'a mismatch before an id mismatch'         => [self::envelope([], ['event' => 'invoice.voided']), $other, EnvelopeFailure::SIGNATURE_MISMATCH],
            'an id mismatch before a refusal'          => [self::envelope(['recorded_at' => '2026-11-01T11:00:00.000000Z']), $other, EnvelopeFailure::ID_MISMATCH],
            'a refusal of the record last'             => [self::envelope(['recorded_at' => '2026-11-01T11:00:00.000000Z']), self::ID, EnvelopeFailure::MALFORMED],
        ];
    }

    /**
     * With two failures, the one checked first is the one named, in the order
     * the input's size, its JSON, unsigned, a version's type, a version's
     * support, the schema, the key, the signature, the id and the record.
     *
     * @param  string  $input
     * @param  ?string  $expectedId
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     * @return void
     */
    #[DataProvider('provideOrder')]
    public function testEachOutcomeIsCheckedInOrder(string $input, ?string $expectedId, EnvelopeFailure $failure): void
    {
        self::assertSame($failure, self::rejection($input, $expectedId)->failure);
    }

    /**
     * Rows of `[columns in place of the captured record's]`: signed envelopes
     * whose values a finalised record refuses.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideRefusedRecords(): iterable
    {
        yield from [
            'recorded before it occurred' => [['recorded_at' => '2026-11-01T11:00:00.000000Z']],
            'an upper-case id'            => [['id' => strtoupper(self::ID)]],
            'an id that is no UUID'       => [['id' => 'inv-0042']],
            'an upper-case import batch'  => [['import_batch_id' => '0192F1C4-7B8E-7C3A-9D2E-5F6A7B8C9D0E']],
        ];
    }

    /**
     * A signed envelope whose record the finalised record refuses is malformed,
     * and names its id only when that id is a lower-case UUID.
     *
     * @param  array<string, string>  $fields
     * @return void
     */
    #[DataProvider('provideRefusedRecords')]
    public function testARecordTheConstructorRefusesIsMalformed(array $fields): void
    {
        $exception = self::rejection(self::envelope($fields));

        self::assertSame(EnvelopeFailure::MALFORMED, $exception->failure);
        self::assertSame(isset($fields['id']) ? null : self::ID, $exception->id);
    }

    /**
     * The deepest JSON column the store reads back decodes inside an envelope,
     * whose own object is one level more; a column one level deeper, which the
     * store cannot read back either, is malformed.
     *
     * @return void
     */
    public function testDecodesEveryDepthTheStoreReadsBack(): void
    {
        // The canonical encoding recurses once per level, past a debugger's
        // default limit on nested calls
        $nesting = ini_set('xdebug.max_nesting_level', '4096');

        try {
            $deepest = self::envelope(['properties' => ['a' => self::nested(510)]]);
            $deeper  = self::envelope(['properties' => ['a' => self::nested(511)]]);

            self::assertSame($deepest, self::codec()->encode(self::codec()->decode($deepest)));
            self::assertSame(EnvelopeFailure::MALFORMED, self::rejection($deeper)->failure);
        } finally {
            if ($nesting !== false) {
                ini_set('xdebug.max_nesting_level', $nesting);
            }
        }
    }

    /**
     * Nothing is minimised or sanitised again: a value capture would redact, a
     * full IP address, a control character and an array deeper than capture
     * keeps, all signed directly, come back whole.
     *
     * @return void
     */
    public function testNothingIsMinimisedOrSanitisedAgain(): void
    {
        $properties = ['password' => 'hunter2', 'api_token' => 'tok_live_1', 'deep' => self::nested(12)];

        $decoded = self::codec()->decode(self::envelope([
            'properties' => $properties,
            'context'    => ['authorization' => 'Bearer abc'],
            'ip'         => '203.0.113.7',
            'user_agent' => "Agent\0\u{202E}",
        ]));

        self::assertSame(CanonicalEncoder::encode($properties), CanonicalEncoder::encode($decoded->record->properties));
        self::assertSame('hunter2', $decoded->record->properties['password'] ?? null);
        self::assertSame(['authorization' => 'Bearer abc'], $decoded->record->context);
        self::assertSame('203.0.113.7', $decoded->record->ip);
        self::assertSame("Agent\0\u{202E}", $decoded->record->userAgent);
    }

    /**
     * The provenance and the import fields are kept as signed, and every other
     * field the captured record had.
     *
     * @return void
     */
    public function testTheProvenanceIsKept(): void
    {
        $imported = [
            'provenance'       => 'imported',
            'source_record_id' => 'legacy-0042',
            'import_batch_id'  => self::IMPORT_BATCH_ID,
            'source_id'        => 'legacy-app',
            'source_region'    => null,
        ];

        $record = self::codec()->decode(self::envelope($imported))->record;

        self::assertSame(['imported', 'legacy-0042', self::IMPORT_BATCH_ID, 'legacy-app', null], [
            $record->provenance, $record->sourceRecordId, $record->importBatchId, $record->sourceId, $record->sourceRegion,
        ]);

        self::assertSame(CanonicalEncoder::encode(array_replace(RecordFactory::captured(id: self::ID)->toArray(), $imported)), CanonicalEncoder::encode($record->toArray()));
    }

    /**
     * The id, which need not be a version 7 UUID, and both times are kept as
     * signed, never regenerated or stamped again; a record recorded at the
     * instant it occurred is kept too.
     *
     * @return void
     */
    public function testTheIdAndTimesAreKept(): void
    {
        $id      = '6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b';
        $decoded = self::codec()->decode(self::envelope(['id' => $id, 'occurred_at' => '2020-01-01T00:00:00.000001Z', 'recorded_at' => '2020-01-01T00:00:00.000001Z']), $id);

        self::assertSame($id, $decoded->record->id);
        self::assertSame('2020-01-01T00:00:00.000001Z', $decoded->record->occurredAt);
        self::assertSame('2020-01-01T00:00:00.000001Z', $decoded->recordedAt);
    }

    /**
     * An envelope signed with a retired key the ring still holds decodes, and
     * keeps that key's id.
     *
     * @return void
     */
    public function testAnEnvelopeSignedWithARetiredKeyDecodes(): void
    {
        $envelope = self::envelope(['key_id' => self::RETIRED_ID], secret: self::RETIRED_SECRET);
        $decoded  = self::codec([self::KEY_ID => self::CURRENT_SECRET, self::RETIRED_ID => self::RETIRED_SECRET])->decode($envelope);

        self::assertSame(self::RETIRED_ID, $decoded->keyId);
    }

    /**
     * The envelope and the record are marked sensitive on every method of the
     * codec, so no frame of a trace carries them.
     *
     * @return void
     */
    public function testTheJsonIsMarkedSensitive(): void
    {
        $sensitive = ['json', 'record', 'fields', 'value'];

        foreach ((new \ReflectionClass(EnvelopeCodec::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                if (!in_array($parameter->getName(), $sensitive, true)) {
                    continue;
                }

                self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), "{$method->getName()}(\${$parameter->getName()})");
            }
        }

        $decode = (new \ReflectionMethod(EnvelopeCodec::class, 'decode'))->getParameters()[0];
        $encode = (new \ReflectionMethod(EnvelopeCodec::class, 'encode'))->getParameters()[0];

        self::assertSame(['json', 'record'], [$decode->getName(), $encode->getName()]);
        self::assertCount(1, $decode->getAttributes(\SensitiveParameter::class));
        self::assertCount(1, $encode->getAttributes(\SensitiveParameter::class));
    }

    /**
     * No refusal carries the envelope: its message is fixed, it has no previous
     * exception, and no frame of its trace holds a value of it, with the
     * arguments of every frame kept.
     *
     * @return void
     */
    public function testNoRefusalCarriesTheEnvelope(): void
    {
        $planted = ['properties' => ['note' => self::SECRET]];

        $inputs = [
            'not JSON'          => '{"note":"' . self::SECRET . '"',
            'not an object'     => '["' . self::SECRET . '"]',
            'unsigned'          => self::envelope($planted, ['unsigned' => true]),
            'a missing version' => self::without('record_version', $planted),
            'a wrong kind'      => self::envelope($planted, ['event' => 1]),
            'a mismatch'        => self::envelope($planted, ['event' => 'invoice.voided']),
            'an unknown key'    => self::envelope($planted + ['key_id' => 'k1999']),
            'a float'           => self::raw(self::envelope(['properties' => ['note' => self::SECRET, 'n' => self::MARKER]]), '0.5'),
            'an id mismatch'    => self::envelope($planted),
            'a refused record'  => self::envelope($planted + ['recorded_at' => '2026-11-01T11:00:00.000000Z']),
        ];

        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            foreach ($inputs as $what => $input) {
                $exception = self::rejection($input, $what === 'an id mismatch' ? '01932b4e-8a40-7000-8000-000000000002' : null);

                self::assertNull($exception->getPrevious(), $what);
                self::assertHoldsNoSecret($exception, "the refusal of {$what}");
            }
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * The envelope's columns: a captured record finalised under `k2026`, with
     * the fields given in place of its own and signed over the result with the
     * secret, as the signer signs, unless an HMAC is given; then the columns
     * given after signing put in place, unsigned.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  array<array-key, mixed>  $after
     * @param  string  $secret
     * @return array<array-key, mixed>
     */
    private static function columns(array $fields = [], array $after = [], string $secret = self::CURRENT_SECRET): array
    {
        $finalised = new FinalisedRecord(RecordFactory::captured(id: self::ID), self::RECORDED_AT, 1, self::KEY_ID, self::PLACEHOLDER_HMAC);
        $columns   = array_replace($finalised->toArray(), $fields);
        $signed    = array_intersect_key($columns, array_flip(RecordSigner::SIGNED_COLUMNS));

        $columns['hmac'] = array_key_exists('hmac', $fields) ? $fields['hmac'] : hash_hmac('sha256', CanonicalEncoder::encode($signed), $secret);

        return array_replace($columns, $after);
    }

    /**
     * The canonical encoding of the envelope's columns without the column
     * given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  array<array-key, mixed>  $fields
     * @param  array<array-key, mixed>  $after
     * @return string
     */
    private static function without(string $column, array $fields = [], array $after = []): string
    {
        return CanonicalEncoder::encode(array_diff_key(self::columns($fields, $after), [$column => true]));
    }

    /**
     * The canonical encoding of the envelope's columns.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  array<array-key, mixed>  $after
     * @param  string  $secret
     * @return string
     */
    private static function envelope(array $fields = [], array $after = [], string $secret = self::CURRENT_SECRET): string
    {
        return CanonicalEncoder::encode(self::columns($fields, $after, $secret));
    }

    /**
     * The envelope with the marker's one string replaced by raw JSON that no
     * PHP value encodes canonically, such as a float.
     *
     * @param  string  $envelope
     * @param  string  $json
     * @return string
     *
     * @throws \LogicException
     */
    private static function raw(string $envelope, string $json): string
    {
        $replaced = str_replace('"' . self::MARKER . '"', $json, $envelope, $count);

        if ($count !== 1) {
            throw new \LogicException('The envelope must hold the marker once.');
        }

        return $replaced;
    }

    /**
     * The refusal of the input by the codec given, or by one over `k2026`.
     *
     * @param  string  $input
     * @param  ?string  $expectedId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\EnvelopeCodec  $codec
     * @return \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private static function rejection(#[\SensitiveParameter] string $input, ?string $expectedId = null, ?EnvelopeCodec $codec = null): EnvelopeRejectedException
    {
        try {
            ($codec ?? self::codec())->decode($input, $expectedId);
        } catch (EnvelopeRejectedException $exception) {
            return $exception;
        }

        self::fail('Expected the envelope to be refused.');
    }

    /**
     * The envelope decoded with objects as `stdClass`.
     *
     * @param  string  $envelope
     * @return \stdClass
     *
     * @throws \JsonException
     */
    private static function object(string $envelope): \stdClass
    {
        $decoded = json_decode($envelope, false, 513, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $decoded);

        return $decoded;
    }

    /**
     * A captured record finalised with a property of the length given, for an
     * envelope of an exact size.
     *
     * @param  int  $length
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function padded(int $length): FinalisedRecord
    {
        $record = RecordFactory::withFields(['properties' => ['pad' => str_repeat('a', $length)]], RecordFactory::captured(id: self::ID));

        return new FinalisedRecord($record, self::RECORDED_AT, 1, self::KEY_ID, self::PLACEHOLDER_HMAC);
    }

    /**
     * Empty lists nested to the depth given, the outermost included.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $depth
     * @return list<mixed>
     */
    private static function nested(int $depth): array
    {
        $value = [];

        for ($level = 1; $level < $depth; $level++) {
            $value = [$value];
        }

        return $value;
    }

    /**
     * Run the test with room for envelopes at their bounds, then restore the
     * memory limit, as far as what the process still holds allows: a debugger
     * can keep the last exceptions' frames, and a limit below them is refused
     * with a warning. An unlimited process stays so.
     *
     * @param  \Closure(): void  $test
     * @return void
     */
    private static function withMemory(\Closure $test): void
    {
        $original = ini_get('memory_limit');

        ini_set('memory_limit', '1G');

        try {
            $test();
        } finally {
            gc_mem_caches();

            $limit = ini_parse_quantity($original);

            ini_set('memory_limit', $limit < 0 ? $original : (string) max($limit, memory_get_usage(true)));
        }
    }

    /**
     * A codec over a signer of the explicit ring of the keys given, signing
     * with the current one, or, with no keys, of the key derived from
     * `app.key`.
     *
     * @param  array<string, string>  $keys
     * @param  ?string  $current
     * @return \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec
     */
    private static function codec(array $keys = [self::KEY_ID => self::CURRENT_SECRET], ?string $current = self::KEY_ID): EnvelopeCodec
    {
        return new EnvelopeCodec(self::signer($keys, $current));
    }

    /**
     * A signer of the explicit ring of the keys given, or, with no keys, of the
     * key derived from `app.key`.
     *
     * @param  array<string, string>  $keys
     * @param  ?string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\RecordSigner
     */
    private static function signer(array $keys = [self::KEY_ID => self::CURRENT_SECRET], ?string $current = self::KEY_ID): RecordSigner
    {
        $config = new Repository(['audit-log' => ['integrity' => ['keys' => $keys, 'current' => $current]], 'app' => ['key' => self::APP_KEY]]);

        return new RecordSigner(new KeyRing(new IntegritySettings($config)));
    }
}
