<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the row codec: encoding a record's row and decoding it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RowCodec::class)]
final class RowCodecTest extends TestCase
{
    /** @var string The id a captured record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string When the record is finalised: after the activity occurred, at a non-zero microsecond. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.000001Z';

    /** @var string A key id as a derived key's fingerprint gives it. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var array<string, string> The entries table's columns and what each holds, in order. */
    private const array COLUMNS = [
        'id'                => 'string',
        'record_version'    => 'integer',
        'event'             => 'string',
        'event_version'     => 'integer',
        'category'          => 'string',
        'outcome'           => 'string',
        'reason'            => 'nullable',
        'actor_type'        => 'nullable',
        'actor_id'          => 'nullable',
        'subject_type'      => 'nullable',
        'subject_id'        => 'nullable',
        'principal_type'    => 'nullable',
        'principal_id'      => 'nullable',
        'tenant_type'       => 'nullable',
        'tenant_id'         => 'nullable',
        'credential_id'     => 'nullable',
        'guard'             => 'nullable',
        'session_id'        => 'nullable',
        'request_id'        => 'nullable',
        'trace_id'          => 'nullable',
        'correlation_id'    => 'nullable',
        'origin'            => 'nullable',
        'provenance'        => 'string',
        'source_id'         => 'string',
        'source_region'     => 'nullable',
        'source_record_id'  => 'nullable',
        'import_batch_id'   => 'nullable',
        'source_digest'     => 'nullable',
        'ip'                => 'nullable',
        'user_agent'        => 'nullable',
        'context'           => 'json',
        'properties'        => 'json',
        'occurred_at'       => 'time',
        'recorded_at'       => 'time',
        'integrity_version' => 'integer',
        'key_id'            => 'string',
        'hmac'              => 'string',
    ];

    /** @var string The default time zone before a test changed it. */
    private string $timeZone;

    /**
     * Remember the default time zone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->timeZone = date_default_timezone_get();
    }

    /**
     * Restore the default time zone and UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        date_default_timezone_set($this->timeZone);
        Str::createUuidsNormally();

        parent::tearDown();
    }

    /**
     * The columns are the finalised record's envelope, in table order (S1).
     *
     * @return void
     */
    public function testTheColumnsAreTheEnvelopeInTableOrder(): void
    {
        self::assertSame(self::COLUMNS, RowCodec::COLUMNS);
        self::assertSame(array_keys(self::COLUMNS), array_keys(self::finalised()->toArray()));
        self::assertCount(37, RowCodec::COLUMNS);
    }

    /**
     * Every column is encoded for the insert, in table order.
     *
     * @return void
     */
    public function testEncodesEveryColumnForTheInsert(): void
    {
        $row = (new RowCodec)->encode(self::finalised());

        self::assertSame([
            'id'                => self::ID,
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'finance',
            'outcome'           => 'success',
            'reason'            => null,
            'actor_type'        => 'user',
            'actor_id'          => '42',
            'subject_type'      => 'invoice',
            'subject_id'        => 'inv_0042',
            'principal_type'    => null,
            'principal_id'      => null,
            'tenant_type'       => 'organisation',
            'tenant_id'         => 'org_01',
            'credential_id'     => null,
            'guard'             => 'web',
            'session_id'        => null,
            'request_id'        => null,
            'trace_id'          => null,
            'correlation_id'    => 'app:ticket-123',
            'origin'            => 'http',
            'provenance'        => 'captured',
            'source_id'         => 'app-eu-1',
            'source_region'     => 'eu-west-2',
            'source_record_id'  => null,
            'import_batch_id'   => null,
            'source_digest'     => null,
            'ip'                => '203.0.113.7',
            'user_agent'        => 'Mozilla/5.0',
            'context'           => '{"route":"invoices.approve","method":"POST"}',
            'properties'        => '{"amount":"1200.00"}',
            'occurred_at'       => '2026-11-01 12:00:00.123456',
            'recorded_at'       => '2026-11-01 12:00:01.000001',
            'integrity_version' => 1,
            'key_id'            => self::KEY_ID,
            'hmac'              => self::HMAC,
        ], $row);
    }

    /**
     * Times are written in UTC with all six fractional digits.
     *
     * @return void
     */
    public function testTimesAreWrittenAsUtcWithSixFractionalDigits(): void
    {
        $codec = new RowCodec;

        $micro = $codec->encode(self::finalised());
        $whole = $codec->encode(self::finalised(RecordFactory::captured(id: self::ID, occurredAt: '2026-11-01T12:00:00.000000Z'), '2026-11-01T12:00:00.000000Z'));

        self::assertSame('2026-11-01 12:00:00.123456', $micro['occurred_at']);
        self::assertSame('2026-11-01 12:00:01.000001', $micro['recorded_at']);
        self::assertSame('2026-11-01 12:00:00.000000', $whole['occurred_at']);
        self::assertSame('2026-11-01 12:00:00.000000', $whole['recorded_at']);
    }

    /**
     * An occurrence time not in the package's form is refused on encode.
     *
     * @return void
     */
    public function testRefusesATimeNotInThePackagesForm(): void
    {
        $record = RecordFactory::withFields(['occurred_at' => '2026-11-01 12:00:00.123456'], RecordFactory::captured(id: self::ID));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A time must be ISO-8601 UTC with microseconds, such as 2026-11-01T12:00:00.123456Z.');

        (new RowCodec)->encode(self::finalised($record));
    }

    /**
     * JSON is written with fixed flags, and a numeric-key map stays a map.
     *
     * @return void
     */
    public function testJsonIsWrittenWithFixedFlags(): void
    {
        $record = RecordFactory::withFields([
            'context'    => [2 => 'b', 10 => 'a'],
            'properties' => ['note' => 'é/😀 "q" \\', 'lines' => [1, 2], 'empty' => []],
        ], RecordFactory::captured(id: self::ID));

        $row = (new RowCodec)->encode(self::finalised($record));

        self::assertSame('{"2":"b","10":"a"}', $row['context']);
        self::assertSame('{"note":"é/😀 \"q\" \\\","lines":[1,2],"empty":[]}', $row['properties']);
    }

    /**
     * A payload that JSON cannot encode is refused as it is encoded.
     *
     * @return void
     */
    public function testRefusesAPayloadJsonCannotEncode(): void
    {
        $record = RecordFactory::withFields(['properties' => ['note' => "\xB1"]], RecordFactory::captured(id: self::ID));

        $this->expectException(\JsonException::class);

        (new RowCodec)->encode(self::finalised($record));
    }

    /**
     * Absent context and properties are written and read back as `null`.
     *
     * @return void
     */
    public function testAbsentPayloadsStayNull(): void
    {
        $codec  = new RowCodec;
        $record = RecordFactory::withFields(['context' => null, 'properties' => null], RecordFactory::captured(id: self::ID));
        $row    = $codec->encode(self::finalised($record));

        self::assertNull($row['context']);
        self::assertNull($row['properties']);

        $envelope = $codec->decode($row);

        self::assertNull($envelope['context']);
        self::assertNull($envelope['properties']);
    }

    /**
     * An encoded row decodes back to the record's envelope.
     *
     * @return void
     */
    public function testDecodesARowBackToTheEnvelope(): void
    {
        $codec     = new RowCodec;
        $finalised = self::finalised(RecordFactory::captured(['order' => ['lines' => [1, 2], 'total' => '10.00'], 'tags' => []], self::ID));
        $envelope  = $codec->decode($codec->encode($finalised));

        self::assertSame(array_keys(self::COLUMNS), array_keys($envelope));
        self::assertSame(CanonicalEncoder::encode($finalised->toArray()), CanonicalEncoder::encode($envelope));
        self::assertSame(self::RECORDED_AT, $envelope['recorded_at']);
        self::assertSame(RecordFactory::OCCURRED_AT, $envelope['occurred_at']);
        self::assertSame(1, $envelope['record_version']);
        self::assertInstanceOf(\stdClass::class, $envelope['context']);
    }

    /**
     * An imported record's source fields and digest round-trip as text.
     *
     * @return void
     */
    public function testAnImportedRecordsSourceDigestRoundTripsAsText(): void
    {
        $codec     = new RowCodec;
        $finalised = new FinalisedRecord(RecordFactory::imported(origin: null), RecordFactory::IMPORTED_AT, 1, self::KEY_ID, self::HMAC);
        $row       = $codec->encode($finalised);
        $envelope  = $codec->decode($row);
        $digest    = RecordFactory::source()->sourceDigest;

        self::assertSame($digest, $row['source_digest']);
        self::assertSame(['imported', 'legacy-app', 'legacy-0042', RecordFactory::IMPORT_BATCH_ID, null], [
            $row['provenance'], $row['source_id'], $row['source_record_id'], $row['import_batch_id'], $row['origin'],
        ]);
        self::assertSame($digest, $envelope['source_digest']);
        self::assertSame(CanonicalEncoder::encode($finalised->toArray()), CanonicalEncoder::encode($envelope));
    }

    /**
     * A row decodes in table order, and keys beyond the columns are dropped.
     *
     * @return void
     */
    public function testDecodesInTableOrderAndDropsOtherKeys(): void
    {
        $codec = new RowCodec;
        $row   = array_reverse($codec->encode(self::finalised()), true) + ['extra' => 'x', 0 => 'y'];

        self::assertSame(array_keys(self::COLUMNS), array_keys($codec->decode($row)));
    }

    /**
     * Rows of `[stored time, time read back]`: each count of fractional digits.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStoredTimes(): iterable
    {
        yield from [
            'six digits' => ['2026-11-01 12:00:00.123456', '2026-11-01T12:00:00.123456Z'],
            'one digit'  => ['2026-11-01 12:00:00.1', '2026-11-01T12:00:00.100000Z'],
            'no digits'  => ['2026-11-01 12:00:00', '2026-11-01T12:00:00.000000Z'],
        ];
    }

    /**
     * Fewer fractional digits, as PostgreSQL returns, read back as six.
     *
     * @param  string  $stored
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideStoredTimes')]
    public function testDecodesTimesWithFewerFractionalDigits(string $stored, string $expected): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::finalised());

        $envelope = $codec->decode(['occurred_at' => $stored, 'recorded_at' => $stored] + $row);

        self::assertSame($expected, $envelope['occurred_at']);
        self::assertSame($expected, $envelope['recorded_at']);
    }

    /**
     * A digit-string integer reads as the integer; any other value is refused.
     *
     * @return void
     */
    public function testDecodesIntegersReturnedAsDigitStrings(): void
    {
        $codec    = new RowCodec;
        $row      = $codec->encode(self::finalised());
        $envelope = $codec->decode(['record_version' => '1', 'event_version' => '12', 'integrity_version' => '1'] + $row);

        self::assertSame(1, $envelope['record_version']);
        self::assertSame(12, $envelope['event_version']);
        self::assertSame(1, $envelope['integrity_version']);

        foreach (['01', '1e0', ' 1', '1 ', '+1', '1.0', '', 1.0, true] as $value) {
            try {
                $codec->decode(['integrity_version' => $value] + $row);
                self::fail(sprintf('Expected %s to be refused.', var_export($value, true)));
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('A stored entry\'s `integrity_version` is not an integer.', $exception->getMessage());
            }
        }
    }

    /**
     * Stored JSON decodes objects as `stdClass`, so empty objects survive.
     *
     * @return void
     */
    public function testDecodesJsonAsObjectsSoEmptyObjectsAndNumericKeysSurvive(): void
    {
        $codec    = new RowCodec;
        $row      = $codec->encode(self::finalised());
        $envelope = $codec->decode(['context' => '{"1":"x","0":"y"}', 'properties' => '{"a":{},"b":[],"0":"z"}'] + $row);

        $properties = $envelope['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertInstanceOf(\stdClass::class, $properties->a);
        self::assertSame([], get_object_vars($properties->a));
        self::assertSame([], $properties->b);
        self::assertSame('z', get_object_vars($properties)['0']);
        self::assertSame('{"0":"z","a":{},"b":[]}', CanonicalEncoder::encode($properties));
        self::assertSame('{"0":"y","1":"x"}', CanonicalEncoder::encode($envelope['context']));
    }

    /**
     * A JSON number never decodes as a string, even beyond PHP's integer range.
     *
     * @return void
     */
    public function testNeverDecodesAJsonNumberAsAString(): void
    {
        $codec    = new RowCodec;
        $row      = $codec->encode(self::finalised());
        $envelope = $codec->decode(['properties' => '{"n":9223372036854775808,"f":12.50,"i":42}'] + $row);

        $properties = $envelope['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertIsFloat($properties->n);
        self::assertIsFloat($properties->f);
        self::assertSame(42, $properties->i);
    }

    /**
     * Stored JSON decodes to a depth of 512, and deeper JSON is refused.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDecodesJsonToItsOwnDepth(): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::finalised());

        $deepest  = '{"a":' . str_repeat('[', 510) . str_repeat(']', 510) . '}';
        $envelope = $codec->decode(['properties' => $deepest] + $row);

        $properties = $envelope['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertSame($deepest, json_encode($properties, JSON_THROW_ON_ERROR, 512));

        try {
            $codec->decode(['properties' => '{"a":' . str_repeat('[', 511) . str_repeat(']', 511) . '}'] + $row);
            self::fail('Expected JSON nested beyond 512 levels to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A stored entry\'s `properties` is not JSON or null.', $exception->getMessage());
            self::assertInstanceOf(\JsonException::class, $exception->getPrevious());
        }
    }

    /**
     * Values are read as the engine returned them, never normalised.
     *
     * @return void
     */
    public function testDecodingNeverChangesAValue(): void
    {
        $codec    = new RowCodec;
        $row      = $codec->encode(self::finalised());
        $envelope = $codec->decode(['subject_id' => 'Inv_0042 ', 'user_agent' => " Mozilla\x01", 'id' => strtoupper(self::ID)] + $row);

        self::assertSame('Inv_0042 ', $envelope['subject_id']);
        self::assertSame(" Mozilla\x01", $envelope['user_agent']);
        self::assertSame(strtoupper(self::ID), $envelope['id']);
    }

    /**
     * Rows of `[column]`: every column of the entries table.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEveryColumn(): iterable
    {
        foreach (array_keys(self::COLUMNS) as $column) {
            yield $column => [$column];
        }
    }

    /**
     * A row missing any column, nullable ones included, is refused, naming it.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideEveryColumn')]
    public function testRefusesARowWithoutAColumn(string $column): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::finalised());

        unset($row[$column]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A stored entry has no `%s` column.', $column));

        $codec->decode($row);
    }

    /**
     * Rows of `[column, stored value, what it holds, previous class or null]`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string, 3: ?class-string<\Throwable>}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield from [
            'an integer in a string column'   => ['event', 42, 'a string', null],
            'null in a required column'       => ['id', null, 'a string', null],
            'null as the hmac'                => ['hmac', null, 'a string', null],
            'an integer in a nullable column' => ['reason', 42, 'a string or null', null],
            'an array in a nullable column'   => ['actor_id', ['42'], 'a string or null', null],
            'an integer as the source digest' => ['source_digest', 42, 'a string or null', null],
            'null in an integer column'       => ['record_version', null, 'an integer', null],
            'a padded integer'                => ['event_version', '01', 'an integer', null],
            'invalid JSON'                    => ['context', '{', 'JSON or null', \JsonException::class],
            'an array in a JSON column'       => ['properties', ['a' => 1], 'JSON or null', null],
            'an integer in a JSON column'     => ['properties', 42, 'JSON or null', null],
            'an ISO time'                     => ['occurred_at', '2026-11-01T12:00:00.123456Z', 'a stored time', \UnexpectedValueException::class],
            'a time that does not exist'      => ['recorded_at', '2026-02-30 00:00:00', 'a stored time', \UnexpectedValueException::class],
            'null in a time column'           => ['recorded_at', null, 'a stored time', null],
            'an integer in a time column'     => ['occurred_at', 42, 'a stored time', null],
        ];
    }

    /**
     * A value its column cannot hold is refused, keeping the cause as previous.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @param  string  $what
     * @param  ?class-string<\Throwable>  $previous
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testRefusesAValueItsColumnCannotHold(string $column, mixed $value, string $what, ?string $previous): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::finalised());

        try {
            $codec->decode([$column => $value] + $row);
            self::fail('Expected the value to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(sprintf('A stored entry\'s `%s` is not %s.', $column, $what), $exception->getMessage());
            self::assertSame($previous, $exception->getPrevious() === null ? null : $exception->getPrevious()::class);
            self::assertSame(0, $exception->getCode());
        }
    }

    /**
     * A non-UTC default time zone shifts nothing.
     *
     * @return void
     */
    public function testANonUtcDefaultTimeZoneShiftsNothing(): void
    {
        date_default_timezone_set('Pacific/Auckland');

        $codec    = new RowCodec;
        $row      = $codec->encode(self::finalised());
        $envelope = $codec->decode($row);

        self::assertSame('2026-11-01 12:00:00.123456', $row['occurred_at']);
        self::assertSame('2026-11-01 12:00:01.000001', $row['recorded_at']);
        self::assertSame(RecordFactory::OCCURRED_AT, $envelope['occurred_at']);
        self::assertSame(self::RECORDED_AT, $envelope['recorded_at']);
    }

    /**
     * A rebuilt record writes its decoded objects as objects, never as lists.
     *
     * @return void
     */
    public function testADecodedRecordEncodesItsObjectsAsObjects(): void
    {
        $context    = (object) ['route' => 'invoices.approve', 'ids' => (object) ['0' => 'a'], 'none' => new \stdClass, 'list' => [new \stdClass]];
        $properties = (object) ['amount' => '1200.00', 'lines' => [(object) ['1' => 'x', '0' => 'y']]];

        $row = (new RowCodec)->encode(self::decoded($context, $properties));

        self::assertSame('{"route":"invoices.approve","ids":{"0":"a"},"none":{},"list":[{}]}', $row['context']);
        self::assertSame('{"amount":"1200.00","lines":[{"1":"x","0":"y"}]}', $row['properties']);
    }

    /**
     * Empty maps and empty lists survive the round trip, at the top and nested.
     *
     * @return void
     */
    public function testAnEmptyMapStaysAnEmptyMap(): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::decoded(new \stdClass, (object) ['meta' => new \stdClass, 'lines' => []]));

        self::assertSame('{}', $row['context']);
        self::assertSame('{"meta":{},"lines":[]}', $row['properties']);

        $envelope = $codec->decode($row);

        self::assertEquals(new \stdClass, $envelope['context']);
        self::assertSame('{"lines":[],"meta":{}}', CanonicalEncoder::encode($envelope['properties']));
    }

    /**
     * A map with sequential numeric keys stays a map through the round trip.
     *
     * @return void
     */
    public function testAMapWithSequentialNumericKeysStaysAMap(): void
    {
        $codec = new RowCodec;
        $row   = $codec->encode(self::decoded((object) ['0' => 'a'], (object) ['0' => 'a', '1' => 'b', '2' => (object) ['0' => 'c']]));

        self::assertSame('{"0":"a"}', $row['context']);
        self::assertSame('{"0":"a","1":"b","2":{"0":"c"}}', $row['properties']);

        $envelope = $codec->decode($row);

        self::assertSame('{"0":"a"}', CanonicalEncoder::encode($envelope['context']));
        self::assertSame('{"0":"a","1":"b","2":{"0":"c"}}', CanonicalEncoder::encode($envelope['properties']));
    }

    /**
     * A rebuilt record writes lists and `null` JSON columns as given.
     *
     * @return void
     */
    public function testADecodedRecordEncodesListsAndNullsAsGiven(): void
    {
        $row = (new RowCodec)->encode(self::decoded(null, [[], 'a']));

        self::assertNull($row['context']);
        self::assertSame('[[],"a"]', $row['properties']);
    }

    /**
     * A bulk record's artifact row holds every artifacts column, in order.
     *
     * @return void
     */
    public function testTheArtifactRowHasEveryColumn(): void
    {
        $record     = RecordFactory::bundled();
        $attachment = $record->attachment;

        self::assertNotNull($attachment);

        $row = (new RowCodec)->encodeAttachment(self::finalised($record));

        self::assertSame([
            'id'           => $attachment->id,
            'entry_id'     => $record->id,
            'kind'         => 'bulk',
            'member_count' => 3,
            'digest'       => $attachment->digest,
            'members'      => $attachment->members,
            'created_at'   => '2026-11-01 12:00:01.000001',
        ], $row);
    }

    /**
     * The artifact's time is the entry's recorded time, not the occurrence.
     *
     * @return void
     */
    public function testTheArtifactsTimeIsTheEntrysRecordedTime(): void
    {
        $finalised = self::finalised(RecordFactory::bundled(), '2026-11-01T12:30:00.654321Z');
        $codec     = new RowCodec;

        self::assertSame($codec->encode($finalised)['recorded_at'], $codec->encodeAttachment($finalised)['created_at']);
        self::assertNotSame($codec->encode($finalised)['occurred_at'], $codec->encodeAttachment($finalised)['created_at']);
    }

    /**
     * A record without an attachment has no artifact row.
     *
     * @return void
     */
    public function testARecordWithoutAnAttachmentHasNoArtifactRow(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only a bulk record has an attachment to store.');

        (new RowCodec)->encodeAttachment(self::finalised());
    }

    /**
     * The record, the row, helper values and previous exceptions are sensitive.
     *
     * @return void
     */
    public function testThePayloadIsMarkedSensitive(): void
    {
        $marked = [];

        foreach ((new \ReflectionClass(RowCodec::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                if ($parameter->getAttributes(\SensitiveParameter::class) === []) {
                    continue;
                }

                $marked[] = "{$method->getName()}(\${$parameter->getName()})";
            }
        }

        self::assertSame([
            'encode($record)',
            'encodeAttachment($record)',
            'decode($row)',
            'encodeJson($value)',
            'decodeValue($value)',
            'decodeJson($value)',
            'decodeTime($value)',
            'malformed($previous)',
        ], $marked);
    }

    /**
     * A captured record rebuilt with the JSON columns given, as the codec does.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|\stdClass|null  $context
     * @param  array<array-key, mixed>|\stdClass|null  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function decoded(array|\stdClass|null $context, array|\stdClass|null $properties): FinalisedRecord
    {
        return FinalisedRecord::decoded(RecordFactory::captured(id: self::ID), self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, $context, $properties);
    }

    /**
     * A captured record, or the one given, finalised at the time given.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function finalised(?AuditRecord $record = null, string $recordedAt = self::RECORDED_AT): FinalisedRecord
    {
        return new FinalisedRecord($record ?? RecordFactory::captured(id: self::ID), $recordedAt, 1, self::KEY_ID, self::HMAC);
    }
}
