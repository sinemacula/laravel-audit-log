<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the record signer: signing under the ring's signing key and
 * version 1, pinned byte for byte by the golden entry; verification that fails
 * for a tampered column and only then answers `false`, refusing an unknown key,
 * an unsupported version, a missing column, a malformed HMAC and a value with
 * no canonical form; the source digest of an imported record, signed and
 * captured; and the captured-content digest that leaves out the finalisation
 * columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSigner::class)]
final class RecordSignerTest extends TestCase
{
    /** @var string The golden entry: the v1 record's finalisation, its canonical string, HMAC and digest. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/entry-v1.json';

    /** @var string The golden v1 record's envelope. */
    private const string RECORD = __DIR__ . '/../../Fixtures/Records/audit-record-v1.json';

    /** @var string The id a captured record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The batch of a second import of the factory's assertion. */
    private const string OTHER_BATCH_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0f';

    /** @var string When the record is finalised: after the activity occurred. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string The current key's secret, as its own 32 bytes. */
    private const string CURRENT_SECRET = 'record-signer current secret 32!';

    /** @var string The retired key's secret, as its own 32 bytes. */
    private const string RETIRED_SECRET = 'record-signer retired secret 32!';

    /** @var string The test `app.key`, as Laravel writes it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string An `app.key` of 32 zero bytes, as `base64:`. */
    private const string ZERO_APP_KEY = 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

    /** @var string The id of the key derived from the test `app.key`. */
    private const string DERIVED_ID = 'd03d4735ce37bd961';

    /** @var string The id of the key derived from 32 zero bytes. */
    private const string ZERO_ID = 'd456bb9a43d6f0486';

    /** @var string Why a missing column is refused, by the column it names. */
    private const string MISSING_MESSAGE = 'A stored entry has no `%s` column; every column is required to verify it.';

    /** @var string Why the ring refuses a short secret for `k2026`. */
    private const string SHORT_SECRET_MESSAGE = '`audit-log.integrity.keys.k2026` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.';

    /** @var string Why a malformed HMAC is refused. */
    private const string HMAC_MESSAGE = 'A stored entry\'s `hmac` must be 64 lower-case hexadecimal characters.';

    /** @var list<string> The entries table's columns, in order. */
    private const array COLUMNS = [
        'id', 'record_version', 'event', 'event_version', 'category', 'outcome', 'reason', 'actor_type', 'actor_id',
        'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id', 'credential_id',
        'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'origin', 'provenance', 'source_id',
        'source_region', 'source_record_id', 'import_batch_id', 'source_digest', 'ip', 'user_agent', 'context',
        'properties', 'occurred_at', 'recorded_at', 'integrity_version', 'key_id', 'hmac',
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
     * A record is signed under the ring's current key and integrity version 1,
     * finalised at the time given, with the HMAC-SHA256 of its canonical
     * envelope under that key's secret; with no explicit ring, the key derived
     * from `app.key` signs.
     *
     * @return void
     */
    public function testSignsWithTheCurrentKeyUnderVersion1(): void
    {
        $record    = self::record();
        $finalised = self::signer()->sign($record, self::RECORDED_AT);

        self::assertSame(1, RecordSigner::VERSION);
        self::assertSame($record, $finalised->record);
        self::assertSame(self::RECORDED_AT, $finalised->recordedAt);
        self::assertSame(1, $finalised->integrityVersion);
        self::assertSame('k2026', $finalised->keyId);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode(self::unsigned($finalised)), self::CURRENT_SECRET), $finalised->hmac);

        $derived = self::signer(self::ring([]))->sign($record, self::RECORDED_AT);

        self::assertSame(self::DERIVED_ID, $derived->keyId);
        self::assertSame(1, $derived->integrityVersion);
        self::assertNotSame($finalised->hmac, $derived->hmac);
    }

    /**
     * The golden v1 record, finalised under the golden key and time, signs byte
     * for byte: its canonical envelope is the pinned string, and its HMAC is
     * the pinned one, which PHP's own HMAC of that string confirms.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenEntrySignsByteForByte(): void
    {
        $finalised = self::goldenSigner()->sign(self::goldenRecord(), self::golden('recorded_at'));

        self::assertSame(self::golden('key_id'), $finalised->keyId);
        self::assertSame(self::golden('canonical'), CanonicalEncoder::encode(self::unsigned($finalised)));
        self::assertSame(self::golden('hmac'), $finalised->hmac);
        self::assertSame(self::golden('hmac'), hash_hmac('sha256', self::golden('canonical'), self::golden('secret')));
        self::assertSame(32, strlen(self::golden('secret')));
    }

    /**
     * The golden entry, as an engine returns it and the codec decodes it,
     * verifies, whatever order the engine keeps its JSON keys in.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenEntryVerifiesAsStored(): void
    {
        $signer    = self::goldenSigner();
        $finalised = $signer->sign(self::goldenRecord(), self::golden('recorded_at'));
        $row       = (new RowCodec)->encode($finalised);

        self::assertTrue($signer->verifies(self::stored($finalised)));

        $row['context']    = '{"route":"invoices.approve","method":"POST"}';
        $row['properties'] = '{"lines":[1,2],"_audit":{"note":"Approved after review"},"currency":"GBP","amount":"1200.00"}';

        self::assertTrue($signer->verifies((new RowCodec)->decode($row)));
    }

    /**
     * The signed envelope is the finalised record's envelope without its HMAC:
     * the 36 signed columns, the finalisation columns included, and nothing
     * else.
     *
     * @return void
     */
    public function testTheSignedEnvelopeIsTheFinalisedRecordWithoutItsHmac(): void
    {
        $finalised = self::signer()->sign(self::record(), self::RECORDED_AT);
        $unsigned  = self::unsigned($finalised);

        self::assertSame(RecordSigner::SIGNED_COLUMNS, array_keys($unsigned));
        self::assertSame(self::RECORDED_AT, $unsigned['recorded_at']);
        self::assertSame(1, $unsigned['integrity_version']);
        self::assertSame('k2026', $unsigned['key_id']);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode($unsigned), self::CURRENT_SECRET), $finalised->hmac);
    }

    /**
     * A finalised record verifies as its envelope, and as the row the codec
     * writes and reads back, under an explicit ring and a derived one.
     *
     * @return void
     */
    public function testAFinalisedRecordVerifies(): void
    {
        $signer    = self::signer();
        $finalised = $signer->sign(self::record(), self::RECORDED_AT);

        self::assertTrue($signer->verifies($finalised->toArray()));
        self::assertTrue($signer->verifies(self::stored($finalised)));

        $derived = self::signer(self::ring([]));

        self::assertTrue($derived->verifies(self::stored($derived->sign(self::record(), self::RECORDED_AT))));
    }

    /**
     * Rows of `[column, stored value]`: each signed column but the integrity
     * version, changed, emptied to `null`, or given a value where it held
     * `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideSignedColumns(): iterable
    {
        foreach (self::tampering() as $column => $value) {
            yield $column => [$column, $value];
        }
    }

    /**
     * Changing any signed column of a stored row fails verification, answering
     * `false`; the integrity version is the one exception, since every other
     * version is refused (see `testAnUnsupportedIntegrityVersionIsUnexpected()`
     * and `testTheIntegrityVersionIsSigned()`).
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideSignedColumns')]
    public function testTamperingAnyColumnFailsVerification(string $column, mixed $value): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        self::assertTrue($signer->verifies($row));
        self::assertNotEquals($row[$column], $value);

        $row[$column] = $value;

        self::assertFalse($signer->verifies($row), sprintf('Tampering `%s` should fail verification.', $column));
    }

    /**
     * The tampering rows cover every signed column but the integrity version,
     * so a column added to the signed set without a row fails here.
     *
     * @return void
     */
    public function testTheTamperingRowsCoverEverySignedColumn(): void
    {
        self::assertSame(array_values(array_diff(RecordSigner::SIGNED_COLUMNS, ['integrity_version'])), array_keys(self::tampering()));
    }

    /**
     * The integrity version is signed: the HMAC of the envelope under another
     * version, or without one, is not the record's.
     *
     * @return void
     */
    public function testTheIntegrityVersionIsSigned(): void
    {
        $finalised = self::signer()->sign(self::record(), self::RECORDED_AT);
        $unsigned  = self::unsigned($finalised);
        $other     = ['integrity_version' => 2] + $unsigned;
        $without   = array_diff_key($unsigned, ['integrity_version' => true]);

        self::assertNotSame($finalised->hmac, hash_hmac('sha256', CanonicalEncoder::encode($other), self::CURRENT_SECRET));
        self::assertNotSame($finalised->hmac, hash_hmac('sha256', CanonicalEncoder::encode($without), self::CURRENT_SECRET));
    }

    /**
     * A nested property changed, nested list members reordered, and a time
     * moved by one microsecond each fail verification, while nested keys
     * reordered, as an engine may return them, still verify.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTamperingANestedPropertyOrAMicrosecondFailsVerification(): void
    {
        $signer    = self::signer();
        $record    = self::record(['order' => ['total' => '10.00', 'lines' => [1, 2], 'meta' => ['b' => 'x', 'a' => 'y']]]);
        $finalised = $signer->sign($record, self::RECORDED_AT);
        $codec     = new RowCodec;
        $row       = $codec->encode($finalised);

        $variants = [
            'reordered keys' => [true, ['properties' => '{"order":{"meta":{"a":"y","b":"x"},"lines":[1,2],"total":"10.00"}}']],
            'nested value'   => [false, ['properties' => '{"order":{"total":"10.01","lines":[1,2],"meta":{"b":"x","a":"y"}}}']],
            'list order'     => [false, ['properties' => '{"order":{"total":"10.00","lines":[2,1],"meta":{"b":"x","a":"y"}}}']],
            'nested key'     => [false, ['properties' => '{"order":{"total":"10.00","lines":[1,2],"meta":{"b":"x","A":"y"}}}']],
            'occurred_at'    => [false, ['occurred_at' => '2026-11-01 12:00:00.123457']],
            'recorded_at'    => [false, ['recorded_at' => '2026-11-01 12:00:01.654320']],
        ];

        foreach ($variants as $label => [$verifies, $changes]) {
            self::assertSame($verifies, $signer->verifies($codec->decode(array_replace($row, $changes))), $label);
        }
    }

    /**
     * A row whose key id is swapped for another key of the ring fails
     * verification: the other key's HMAC is not the row's.
     *
     * @return void
     */
    public function testAnotherKeyIdInTheRingFailsVerification(): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        $row['key_id'] = 'k2025';

        self::assertFalse($signer->verifies($row));
    }

    /**
     * A row signed under a key the ring does not hold is unverifiable, never
     * tampered: the unknown key exception names the key id, and an explicit
     * ring never verifies with the derived key.
     *
     * @return void
     */
    public function testAKeyIdOutsideTheRingIsUnknown(): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        foreach (['k2024', self::DERIVED_ID] as $keyId) {
            try {
                $signer->verifies(['key_id' => $keyId] + $row);
                self::fail('Expected the key to be unknown.');
            } catch (UnknownKeyException $exception) {
                self::assertSame($keyId, $exception->keyId);
            }
        }
    }

    /**
     * A row signed under a key that has since stopped signing still verifies:
     * an explicit key whose `current` has moved on, and a key derived from an
     * `app.key` that was rotated into `app.previous_keys`.
     *
     * @return void
     */
    public function testARetiredKeyStillVerifiesItsRows(): void
    {
        $retired = self::signer(self::explicitRing('k2025'))->sign(self::record(), self::RECORDED_AT);

        self::assertSame('k2025', $retired->keyId);
        self::assertTrue(self::signer()->verifies(self::stored($retired)));

        $before = self::signer(self::ring([]))->sign(self::record(), self::RECORDED_AT);
        $after  = self::signer(self::ring([], ['key' => self::ZERO_APP_KEY, 'previous_keys' => [self::APP_KEY]]));

        self::assertSame(self::DERIVED_ID, $before->keyId);
        self::assertSame(self::ZERO_ID, $after->sign(self::record(), self::RECORDED_AT)->keyId);
        self::assertTrue($after->verifies(self::stored($before)));
    }

    /**
     * An integrity version this release does not verify is refused, naming the
     * version, or its type when it is not an integer, so a digit string or a
     * `null` is never read as version 1.
     *
     * @return void
     */
    public function testAnUnsupportedIntegrityVersionIsUnexpected(): void
    {
        self::assertSame([1], RecordSigner::SUPPORTED_VERSIONS);

        $row = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));

        $versions = [
            'Integrity version 2 is not supported by this release.'      => 2,
            'Integrity version 0 is not supported by this release.'      => 0,
            'Integrity version string is not supported by this release.' => '1',
            'Integrity version null is not supported by this release.'   => null,
        ];

        foreach ($versions as $message => $version) {
            try {
                self::signer()->verifies(['integrity_version' => $version] + $row);
                self::fail('Expected the version to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[column]`: every column of the entries table.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEveryColumn(): iterable
    {
        foreach (self::COLUMNS as $column) {
            yield $column => [$column];
        }
    }

    /**
     * A row without any one column is malformed, never read as having `null`
     * there, nullable columns included, and the refusal names the column.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideEveryColumn')]
    public function testAMissingColumnIsMalformedNeverNull(string $column): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        unset($row[$column]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf(self::MISSING_MESSAGE, $column));

        $signer->verifies($row);
    }

    /**
     * A nullable column holding `null` is present: the record's `reason` and
     * `source_record_id` are `null`, and its row verifies.
     *
     * @return void
     */
    public function testANullColumnIsPresent(): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        self::assertNull($row['reason']);
        self::assertNull($row['source_record_id']);
        self::assertTrue($signer->verifies($row));
    }

    /**
     * Rows of `[stored HMAC]`: values that are not HMAC-SHA256 as lower-case
     * hex.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedHmacs(): iterable
    {
        $hmac = str_repeat('0123456789abcdef', 4);

        yield from [
            'upper case'       => [strtoupper($hmac)],
            '63 characters'    => [substr($hmac, 1)],
            '65 characters'    => [$hmac . '0'],
            'not hex'          => ['g' . substr($hmac, 1)],
            'trailing newline' => [$hmac . "\n"],
            'leading space'    => [' ' . substr($hmac, 1)],
            'empty'            => [''],
            'null'             => [null],
            'an integer'       => [42],
            'binary'           => [hash('sha256', 'x', true)],
        ];
    }

    /**
     * A stored HMAC that is not HMAC-SHA256 as lower-case hex is malformed,
     * never a mismatch.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $hmac
     * @return void
     */
    #[DataProvider('provideMalformedHmacs')]
    public function testAMalformedHmacIsUnexpected(mixed $hmac): void
    {
        $row = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::HMAC_MESSAGE);

        self::signer()->verifies(['hmac' => $hmac] + $row);
    }

    /**
     * A key id that is not a string is malformed; it is never cast to look up a
     * key.
     *
     * @return void
     */
    public function testAKeyIdThatIsNotAStringIsUnexpected(): void
    {
        $row = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));

        foreach ([null, 2026, ['k2026']] as $keyId) {
            try {
                self::signer(self::explicitRing('k2026', ['2026' => self::CURRENT_SECRET]))->verifies(['key_id' => $keyId] + $row);
                self::fail('Expected the key id to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('A stored entry\'s `key_id` must be a string.', $exception->getMessage());
            }
        }
    }

    /**
     * A malformed row is refused in a fixed order: a missing column, then the
     * HMAC, then the integrity version, then the key id, then the ring's
     * unknown key.
     *
     * @return void
     */
    public function testRefusalsAreReportedInOrder(): void
    {
        $row = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));
        $bad = ['hmac' => 'x', 'integrity_version' => 2, 'key_id' => null] + $row;

        $cases = [
            sprintf(self::MISSING_MESSAGE, 'reason')                => array_diff_key($bad, ['reason' => true]),
            self::HMAC_MESSAGE                                      => $bad,
            'Integrity version 2 is not supported by this release.' => ['hmac' => $row['hmac']]                           + $bad,
            'A stored entry\'s `key_id` must be a string.'          => ['hmac' => $row['hmac'], 'integrity_version' => 1] + $bad,
        ];

        foreach ($cases as $message => $case) {
            try {
                self::signer()->verifies($case);
                self::fail('Expected the row to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }

        $this->expectException(UnknownKeyException::class);

        self::signer()->verifies(['key_id' => 'k2024', 'properties' => 1.5] + $row);
    }

    /**
     * A string property edited in the stored JSON into the bare number it
     * spells decodes as a float, which has no canonical form: the row is
     * malformed, never verified as the original string.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAStringPropertyEditedIntoABareNumberIsMalformedNeverVerified(): void
    {
        $signer    = self::signer();
        $finalised = $signer->sign(self::record(['big' => '9223372036854775808']), self::RECORDED_AT);
        $codec     = new RowCodec;
        $row       = $codec->encode($finalised);

        self::assertSame('{"big":"9223372036854775808"}', $row['properties']);

        $row['properties'] = '{"big":9223372036854775808}';

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A float cannot be encoded canonically; the package stores decimals as strings.');

        $signer->verifies($codec->decode($row));
    }

    /**
     * Rows of `[column, stored value]`: values with no canonical form, in a
     * JSON column or a string column.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideValuesWithNoCanonicalForm(): iterable
    {
        yield from [
            'a fraction'          => ['properties', json_decode('{"amount":12.5}'), 'A float cannot be encoded canonically; the package stores decimals as strings.'],
            'an exponent'         => ['context', json_decode('{"n":1e2}'), 'A float cannot be encoded canonically; the package stores decimals as strings.'],
            'another object'      => ['properties', ['at' => new \DateTimeImmutable('2026-11-01')], 'A value of type DateTimeImmutable cannot be encoded canonically.'],
            'invalid UTF-8'       => ['user_agent', "Mozilla\xB1", 'A string that is not valid UTF-8 cannot be encoded canonically.'],
            'a float in a column' => ['record_version', 1.0, 'A float cannot be encoded canonically; the package stores decimals as strings.'],
        ];
    }

    /**
     * A row holding a value with no canonical form is malformed, never a
     * mismatch.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideValuesWithNoCanonicalForm')]
    public function testAValueWithNoCanonicalFormIsMalformed(string $column, mixed $value, string $message): void
    {
        $row = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        self::signer()->verifies([$column => $value] + $row);
    }

    /**
     * Columns a row has beyond version 1's are not signed: they are ignored,
     * even one with no canonical form, and the row still verifies.
     *
     * @return void
     */
    public function testColumnsOutsideVersion1AreNotSigned(): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        self::assertTrue($signer->verifies($row + ['notes' => 'added later', 'weight' => 1.5, 7 => 'x']));
    }

    /**
     * Verification never normalises: a user agent holding a control character
     * the text sanitiser would strip, signed as it is, verifies as it is, and
     * the row's bytes are left unchanged.
     *
     * @return void
     */
    public function testVerificationNeverNormalises(): void
    {
        $agent = "Mozilla/5.0\x01\u{202E}";

        self::assertNotSame($agent, TextSanitizer::clean($agent));

        $signer    = self::signer();
        $finalised = $signer->sign(RecordFactory::withFields(['user_agent' => $agent], self::record()), self::RECORDED_AT);
        $row       = self::stored($finalised);

        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode(self::unsigned($finalised)), self::CURRENT_SECRET), $finalised->hmac);
        self::assertTrue($signer->verifies($row));
        self::assertSame($agent, $row['user_agent']);
        self::assertFalse($signer->verifies(['user_agent' => TextSanitizer::clean($agent)] + $row));
    }

    /**
     * The captured-content digest leaves out the finalisation columns: the same
     * record finalised at another time, under another key or version, has one
     * digest, the SHA-256 of its captured envelope.
     *
     * @return void
     */
    public function testTheCapturedDigestLeavesOutTheFinalisationColumns(): void
    {
        $record  = self::record();
        $current = self::stored(self::signer()->sign($record, self::RECORDED_AT));
        $retired = self::stored(self::signer(self::explicitRing('k2025'))->sign($record, '2026-11-02T08:00:00.000001Z'));
        $digest  = self::signer()->capturedDigest($current);

        self::assertSame(hash('sha256', CanonicalEncoder::encode($record->toArray())), $digest);
        self::assertSame($digest, self::signer()->capturedDigest($retired));
        self::assertSame($digest, self::signer()->capturedDigest(['integrity_version' => 9, 'hmac' => null] + $current));
        self::assertSame($digest, self::signer()->capturedDigest(array_diff_key($current, array_flip(['recorded_at', 'integrity_version', 'key_id', 'hmac']))));
        self::assertNotSame($current['hmac'], $retired['hmac']);
    }

    /**
     * Rows of `[column, stored value]`: each captured column, changed, emptied
     * to `null`, or given a value where it held `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideCapturedColumns(): iterable
    {
        foreach (self::tampering() as $column => $value) {
            if (!in_array($column, RecordSigner::CAPTURED_COLUMNS, true)) {
                continue;
            }

            yield $column => [$column, $value];
        }
    }

    /**
     * The captured-content digest covers every captured column: changing any
     * one changes the digest.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideCapturedColumns')]
    public function testTheCapturedDigestCoversEveryCapturedColumn(string $column, mixed $value): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        self::assertNotSame($signer->capturedDigest($row), $signer->capturedDigest([$column => $value] + $row), $column);
    }

    /**
     * Rows of `[column]`: every captured column.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEveryCapturedColumn(): iterable
    {
        foreach (array_slice(self::COLUMNS, 0, 33) as $column) {
            yield $column => [$column];
        }
    }

    /**
     * The digest requires every captured column, nullable ones included, and
     * the refusal names the column.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideEveryCapturedColumn')]
    public function testTheCapturedDigestRequiresEveryCapturedColumn(string $column): void
    {
        $signer = self::signer();
        $row    = self::stored($signer->sign(self::record(), self::RECORDED_AT));

        unset($row[$column]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf(self::MISSING_MESSAGE, $column));

        $signer->capturedDigest($row);
    }

    /**
     * The golden entry's captured-content digest is pinned, and is PHP's own
     * SHA-256 of the canonical captured envelope.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenCapturedDigestIsPinned(): void
    {
        $signer    = self::goldenSigner();
        $record    = self::goldenRecord();
        $finalised = $signer->sign($record, self::golden('recorded_at'));

        self::assertSame(self::golden('captured_digest'), $signer->capturedDigest(self::stored($finalised)));
        self::assertSame(self::golden('captured_digest'), hash('sha256', CanonicalEncoder::encode($record->toArray())));
    }

    /**
     * An imported record's source digest is signed and captured: its row
     * verifies as signed, a digest edited, emptied or set where there was none
     * fails verification and changes the captured digest, and two imports of
     * one assertion, with their own ids and batches, have one source digest and
     * two captured digests.
     *
     * @return void
     */
    public function testTheSourceDigestIsSigned(): void
    {
        $signer   = self::signer();
        $imported = self::stored($signer->sign(RecordFactory::imported(), self::RECORDED_AT));
        $captured = self::stored($signer->sign(self::record(), self::RECORDED_AT));
        $source   = RecordFactory::source();
        $again    = RecordFactory::imported(new ImportedSource($source->sourceId, $source->sourceRegion, $source->sourceRecordId, self::OTHER_BATCH_ID, $source->sourceDigest));
        $repeat   = self::stored($signer->sign($again, self::RECORDED_AT));

        self::assertContains('source_digest', RecordSigner::CAPTURED_COLUMNS);
        self::assertTrue($signer->verifies($imported));
        self::assertSame(RecordFactory::source()->sourceDigest, $imported['source_digest']);

        foreach ([str_repeat('0', 64), null] as $value) {
            self::assertFalse($signer->verifies(['source_digest' => $value] + $imported));
            self::assertNotSame($signer->capturedDigest($imported), $signer->capturedDigest(['source_digest' => $value] + $imported));
        }

        self::assertFalse($signer->verifies(['source_digest' => str_repeat('0', 64)] + $captured));
        self::assertSame($imported['source_digest'], $repeat['source_digest']);
        self::assertNotSame($signer->capturedDigest($imported), $signer->capturedDigest($repeat));
    }

    /**
     * The signed columns are the envelope without `hmac`, and the captured
     * columns are the captured record's, both in table order (S1).
     *
     * @return void
     */
    public function testTheSignedAndCapturedColumnsAreTheEnvelope(): void
    {
        $finalised = self::signer()->sign(self::record(), self::RECORDED_AT);

        self::assertSame(self::COLUMNS, array_keys($finalised->toArray()));
        self::assertSame(array_slice(self::COLUMNS, 0, 36), RecordSigner::SIGNED_COLUMNS);
        self::assertSame(array_slice(self::COLUMNS, 0, 33), RecordSigner::CAPTURED_COLUMNS);
        self::assertSame(array_keys(self::record()->toArray()), RecordSigner::CAPTURED_COLUMNS);
    }

    /**
     * Signing propagates refusals: a malformed ring signs and verifies nothing,
     * and a time before the activity occurred is the finalised record's
     * refusal.
     *
     * @return void
     */
    public function testSigningPropagatesRefusals(): void
    {
        $row     = self::stored(self::signer()->sign(self::record(), self::RECORDED_AT));
        $refused = [
            'signing'      => static fn (RecordSigner $signer): FinalisedRecord => $signer->sign(self::record(), self::RECORDED_AT),
            'verification' => static fn (RecordSigner $signer): bool => $signer->verifies($row),
        ];

        foreach ($refused as $label => $call) {
            try {
                $call(self::signer(self::ring(['keys' => ['k2026' => 'short'], 'current' => 'k2026'])));
                self::fail(sprintf('Expected %s to be refused.', $label));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::SHORT_SECRET_MESSAGE, $exception->getMessage(), $label);
            }
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A finalised record cannot be recorded before the activity occurred.');

        self::signer()->sign(self::record(), '2026-11-01T12:00:00.123455Z');
    }

    /**
     * For each signed column but the integrity version, a decoded stored value
     * that differs from the captured record's, finalised by `signer()`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<string, mixed>
     */
    private static function tampering(): array
    {
        return [
            'id'               => '01932b4e-8a40-7000-8000-000000000002',
            'record_version'   => 2,
            'event'            => 'invoice.voided',
            'event_version'    => 2,
            'category'         => 'billing',
            'outcome'          => 'failure',
            'reason'           => 'policy',
            'actor_type'       => 'service',
            'actor_id'         => '43',
            'subject_type'     => 'order',
            'subject_id'       => 'inv_0043',
            'principal_type'   => 'team',
            'principal_id'     => '7',
            'tenant_type'      => null,
            'tenant_id'        => 'org_02',
            'credential_id'    => 'key_01',
            'guard'            => 'api',
            'session_id'       => 'sess_ref_1',
            'request_id'       => 'req-1',
            'trace_id'         => '4bf92f3577b34da6a3ce929d0e0e4736',
            'correlation_id'   => 'app:ticket-124',
            'origin'           => 'console',
            'provenance'       => 'imported',
            'source_id'        => 'app-us-1',
            'source_region'    => null,
            'source_record_id' => 'r1',
            'import_batch_id'  => '01932b4e-8a40-7000-8000-0000000000bb',
            'source_digest'    => str_repeat('5d', 32),
            'ip'               => '203.0.113.8',
            'user_agent'       => null,
            'context'          => json_decode('{"method":"GET","route":"invoices.approve"}'),
            'properties'       => json_decode('{"amount":"1200.01"}'),
            'occurred_at'      => '2026-11-01T12:00:00.123457Z',
            'recorded_at'      => '2026-11-01T12:00:01.654322Z',
            'key_id'           => 'k2025',
        ];
    }

    /**
     * A captured record of an approved invoice with the properties given, under
     * the pinned id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function record(array $properties = ['amount' => '1200.00']): AuditRecord
    {
        return RecordFactory::captured($properties, self::ID);
    }

    /**
     * The finalised record's envelope without its HMAC: what is signed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @return array<string, mixed>
     */
    private static function unsigned(FinalisedRecord $finalised): array
    {
        return array_diff_key($finalised->toArray(), ['hmac' => true]);
    }

    /**
     * The finalised record as an engine stores it and the codec reads it back.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @return array<string, mixed>
     */
    private static function stored(FinalisedRecord $finalised): array
    {
        $codec = new RowCodec;

        return $codec->decode($codec->encode($finalised));
    }

    /**
     * A signer over the ring given, or over the explicit two-key ring that
     * signs with `k2026`.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\KeyRing  $ring
     * @return \SineMacula\Laravel\AuditLog\Integrity\RecordSigner
     */
    private static function signer(?KeyRing $ring = null): RecordSigner
    {
        return new RecordSigner($ring ?? self::explicitRing('k2026'));
    }

    /**
     * The explicit ring of `k2026` and `k2025`, and any other keys given, with
     * the current key named.
     *
     * @param  string  $current
     * @param  array<array-key, string>  $others
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function explicitRing(string $current, array $others = []): KeyRing
    {
        return self::ring(['keys' => ['k2026' => self::CURRENT_SECRET, 'k2025' => self::RETIRED_SECRET] + $others, 'current' => $current]);
    }

    /**
     * A ring over the integrity and application settings given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $app
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $integrity, array $app = ['key' => self::APP_KEY]): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity], 'app' => $app])));
    }

    /**
     * The golden entry's field.
     *
     * @param  'canonical'|'captured_digest'|'hmac'|'key_id'|'recorded_at'|'secret'  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function golden(string $field): string
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
        $value  = is_array($golden) ? ($golden[$field] ?? null) : null;

        if (!is_string($value)) {
            self::fail(sprintf('The golden entry has no `%s`.', $field));
        }

        return $value;
    }

    /**
     * The golden v1 record, built from its envelope.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \JsonException
     */
    private static function goldenRecord(): AuditRecord
    {
        $envelope = json_decode((string) file_get_contents(self::RECORD), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($envelope)) {
            self::fail('The golden v1 record is not an envelope.');
        }

        $fields = [];

        foreach ($envelope as $name => $value) {
            if (!is_string($name)) {
                self::fail('The golden v1 record has a field with no name.');
            }

            $fields[$name] = $value;
        }

        return RecordFactory::withFields($fields);
    }

    /**
     * A signer whose one key is the golden entry's.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\RecordSigner
     *
     * @throws \JsonException
     */
    private static function goldenSigner(): RecordSigner
    {
        return self::signer(self::ring(['keys' => [self::golden('key_id') => self::golden('secret')], 'current' => self::golden('key_id')]));
    }
}
