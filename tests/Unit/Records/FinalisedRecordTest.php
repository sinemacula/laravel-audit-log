<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the finalised record, its envelope and the values it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FinalisedRecord::class)]
final class FinalisedRecordTest extends TestCase
{
    /** @var string The id a captured record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A time after the activity occurred. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string A key id as a derived key's fingerprint gives it. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string Why a time that is not in the package's form is refused. */
    private const string TIME_MESSAGE = 'A finalised record\'s time must be ISO-8601 UTC with microseconds.';

    /** @var string Why a time before the activity is refused. */
    private const string BEFORE_MESSAGE = 'A finalised record cannot be recorded before the activity occurred.';

    /** @var string Why an integrity version outside its column is refused. */
    private const string VERSION_MESSAGE = 'An integrity version must be from 1 to 32767.';

    /** @var string Why a key id the column cannot hold is refused. */
    private const string KEY_ID_MESSAGE = 'A key id must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string Why a malformed HMAC is refused. */
    private const string HMAC_MESSAGE = 'An HMAC must be 64 lower-case hexadecimal characters.';

    /** @var string Why an import batch id that is not a lower-case UUID is refused. */
    private const string BATCH_MESSAGE = 'A finalised record\'s `import_batch_id` must be a lower-case UUID, the form every engine stores and returns.';

    /** @var string Why a source digest the column cannot hold is refused. */
    private const string DIGEST_MESSAGE = 'A finalised record\'s `source_digest` must be 64 lower-case hexadecimal characters.';

    /** @var string Why a UUID column's value is refused, by the column it names. */
    private const string UUID_MESSAGE = 'A finalised record\'s `%s` must be a lower-case UUID, the form every engine stores and returns.';

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
     * The finalised record carries the captured record and each of its
     * finalisation's values as given.
     *
     * @return void
     */
    public function testCarriesTheRecordAndItsFinalisation(): void
    {
        $record    = RecordFactory::captured(id: self::ID);
        $finalised = new FinalisedRecord($record, self::RECORDED_AT, 1, self::KEY_ID, self::HMAC);

        self::assertSame($record, $finalised->record);
        self::assertSame(self::ID, $finalised->record->id);
        self::assertSame(self::RECORDED_AT, $finalised->recordedAt);
        self::assertSame(1, $finalised->integrityVersion);
        self::assertSame(self::KEY_ID, $finalised->keyId);
        self::assertSame(self::HMAC, $finalised->hmac);
    }

    /**
     * The envelope is the captured record's 33 fields then the four
     * finalisation columns: the entries table, in order.
     *
     * @return void
     */
    public function testTheEnvelopeIsTheRecordThenItsFinalisationInTableOrder(): void
    {
        $record   = RecordFactory::captured(id: self::ID);
        $envelope = (new FinalisedRecord($record, self::RECORDED_AT, 7, self::KEY_ID, self::HMAC))->toArray();

        self::assertSame(self::COLUMNS, array_keys($envelope));
        self::assertSame([...$record->toArray(), 'recorded_at' => self::RECORDED_AT, 'integrity_version' => 7, 'key_id' => self::KEY_ID, 'hmac' => self::HMAC], $envelope);
    }

    /**
     * A record of the imported shape, or built by the import, is finalised with
     * its envelope kept as given.
     *
     * @return void
     */
    public function testKeepsARecordOfTheImportedShapeAsGiven(): void
    {
        $record = RecordFactory::withFields([
            'provenance'       => 'imported',
            'source_record_id' => 'legacy-0042',
            'import_batch_id'  => '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e',
            'source_digest'    => str_repeat('0f', 32),
        ]);

        $envelope = (new FinalisedRecord($record, self::RECORDED_AT, 1, self::KEY_ID, self::HMAC))->toArray();
        $imported = RecordFactory::imported();
        $import   = new FinalisedRecord($imported, RecordFactory::IMPORTED_AT, 1, self::KEY_ID, self::HMAC);
        $expected = [...$imported->toArray(), 'recorded_at' => RecordFactory::IMPORTED_AT, 'integrity_version' => 1, 'key_id' => self::KEY_ID, 'hmac' => self::HMAC];

        self::assertSame('legacy-0042', $envelope['source_record_id']);
        self::assertSame('0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e', $envelope['import_batch_id']);
        self::assertSame(str_repeat('0f', 32), $envelope['source_digest']);
        self::assertSame('imported', $envelope['provenance']);
        self::assertSame($expected, $import->toArray());
    }

    /**
     * What a destination changes in the envelope it was handed, at the top or
     * nested, stays out of the record the next destination is handed.
     *
     * @return void
     */
    public function testChangingAnEnvelopeLeavesTheRecordAsSigned(): void
    {
        $properties = (object) ['amount' => '1.00', 'lines' => [(object) ['sku' => 'a']], 'meta' => (object) ['tier' => 'gold']];
        $context    = (object) ['route' => 'invoices'];
        $finalised  = FinalisedRecord::decoded(RecordFactory::captured(), self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, $context, $properties);
        $first      = $finalised->toArray();

        self::assertInstanceOf(\stdClass::class, $first['properties']);
        self::assertInstanceOf(\stdClass::class, $first['context']);

        $first['properties']->amount        = '999.00';
        $first['properties']->lines[0]->sku = 'z';
        $first['properties']->meta->tier    = 'none';
        $first['context']->route            = 'elsewhere';

        $second = json_encode($finalised->toArray(), JSON_THROW_ON_ERROR);

        self::assertStringContainsString('"amount":"1.00"', $second);
        self::assertStringContainsString('"sku":"a"', $second);
        self::assertStringContainsString('"tier":"gold"', $second);
        self::assertStringContainsString('"route":"invoices"', $second);
    }

    /**
     * What is changed in the columns given after decoding stays out of the
     * record too, since the codec keeps no copy of its own.
     *
     * @return void
     */
    public function testChangingTheColumnsGivenLeavesTheRecordAsSigned(): void
    {
        $properties = (object) ['amount' => '1.00', 'meta' => (object) ['tier' => 'gold']];
        $finalised  = FinalisedRecord::decoded(RecordFactory::captured(), self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, null, $properties);

        $properties->amount     = '999.00';
        $properties->meta->tier = 'none';

        $envelope = json_encode($finalised->toArray(), JSON_THROW_ON_ERROR);

        self::assertStringContainsString('"amount":"1.00"', $envelope);
        self::assertStringContainsString('"tier":"gold"', $envelope);
    }

    /**
     * The copy keeps every JSON type as it was, so `{}` stays an object and a
     * numeric-key map stays a map.
     *
     * @return void
     */
    public function testTheCopyKeepsEveryJsonType(): void
    {
        $properties = (object) [
            'empty_map'  => new \stdClass,
            'empty_list' => [],
            'list'       => ['a', (object) ['b' => 1]],
            'numeric'    => (object) ['0' => 'a', '1' => 'b'],
            'nothing'    => null,
            'flag'       => true,
            'count'      => 1,
        ];
        $envelope = FinalisedRecord::decoded(RecordFactory::captured(), self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, null, $properties)->toArray();

        self::assertSame(json_encode($properties, JSON_THROW_ON_ERROR), json_encode($envelope['properties'], JSON_THROW_ON_ERROR));
        self::assertNull($envelope['context']);
    }

    /**
     * A decoded record returns its JSON columns as decoded, since the record's
     * array views cannot tell `{}` from `[]`.
     *
     * @return void
     */
    public function testADecodedRecordReturnsItsColumnsAsDecoded(): void
    {
        $record     = RecordFactory::withFields(['context' => [], 'properties' => ['a', 'b']], RecordFactory::captured(id: self::ID));
        $context    = new \stdClass;
        $properties = (object) ['0' => 'a', '1' => 'b'];

        $envelope = FinalisedRecord::decoded($record, self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, $context, $properties)->toArray();

        self::assertEquals($context, $envelope['context']);
        self::assertEquals($properties, $envelope['properties']);
        self::assertInstanceOf(\stdClass::class, $envelope['context']);
        self::assertInstanceOf(\stdClass::class, $envelope['properties']);
        self::assertSame([], $record->context);
        self::assertSame(['a', 'b'], $record->properties);
    }

    /**
     * A decoded record's columns given as lists or `null` are returned as
     * given, too, and every other column is the record's own.
     *
     * @return void
     */
    public function testADecodedRecordReturnsListsAndNullsAsGiven(): void
    {
        $record   = RecordFactory::captured(id: self::ID);
        $envelope = FinalisedRecord::decoded($record, self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, null, [[], 'x'])->toArray();

        self::assertNull($envelope['context']);
        self::assertSame([[], 'x'], $envelope['properties']);
        $others = array_fill_keys(['context', 'properties', 'recorded_at', 'integrity_version', 'key_id', 'hmac'], true);

        self::assertSame(array_diff_key($record->toArray(), $others), array_diff_key($envelope, $others));
    }

    /**
     * A decoded record's envelope keeps the 37 columns of the entries table in
     * their order.
     *
     * @return void
     */
    public function testADecodedRecordKeepsTableOrder(): void
    {
        $decoded = FinalisedRecord::decoded(RecordFactory::captured(id: self::ID), self::RECORDED_AT, 3, self::KEY_ID, self::HMAC, new \stdClass, new \stdClass);

        self::assertSame(self::COLUMNS, array_keys($decoded->toArray()));
        self::assertSame([self::RECORDED_AT, 3, self::KEY_ID, self::HMAC], array_values(array_slice($decoded->toArray(), 33)));
        self::assertSame([self::RECORDED_AT, 3, self::KEY_ID, self::HMAC], [$decoded->recordedAt, $decoded->integrityVersion, $decoded->keyId, $decoded->hmac]);
    }

    /**
     * Rows of `[fields, recorded at, integrity version, key id, hmac, the
     * message]`: one value of a decoded record that is refused, for each check.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string, 2: int, 3: string, 4: string, 5: string}>
     */
    public static function provideRefusedDecodedRecords(): iterable
    {
        $upper = strtoupper(self::ID);

        yield from [
            'a time not in the form'     => [[], '2026-11-01 12:00:01', 1, self::KEY_ID, self::HMAC, self::TIME_MESSAGE],
            'a time before the activity' => [[], '2026-11-01T11:00:00.000000Z', 1, self::KEY_ID, self::HMAC, self::BEFORE_MESSAGE],
            'an integrity version of 0'  => [[], self::RECORDED_AT, 0, self::KEY_ID, self::HMAC, self::VERSION_MESSAGE],
            'an empty key id'            => [[], self::RECORDED_AT, 1, '', self::HMAC, self::KEY_ID_MESSAGE],
            'an upper-case HMAC'         => [[], self::RECORDED_AT, 1, self::KEY_ID, strtoupper(self::HMAC), self::HMAC_MESSAGE],
            'an upper-case id'           => [['id' => $upper], self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, sprintf(self::UUID_MESSAGE, 'id')],
            'an upper-case import batch' => [['import_batch_id' => $upper], self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, sprintf(self::UUID_MESSAGE, 'import_batch_id')],
            'an upper-case digest'       => [['source_digest' => strtoupper(self::HMAC)], self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, self::DIGEST_MESSAGE],
        ];
    }

    /**
     * A decoded record is checked like any other: each value a finalised record
     * refuses is refused, with the same message.
     *
     * @param  array<string, string>  $fields
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedDecodedRecords')]
    public function testADecodedRecordIsCheckedLikeAnyOther(array $fields, string $recordedAt, int $integrityVersion, string $keyId, string $hmac, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        FinalisedRecord::decoded(RecordFactory::withFields($fields), $recordedAt, $integrityVersion, $keyId, $hmac, new \stdClass, null);
    }

    /**
     * The record and the decoded columns given to `decoded()` are marked
     * sensitive: they hold the record's values.
     *
     * @return void
     */
    public function testTheDecodedPayloadIsMarkedSensitive(): void
    {
        $parameters = (new \ReflectionMethod(FinalisedRecord::class, 'decoded'))->getParameters();
        $marked     = array_filter($parameters, static fn (\ReflectionParameter $parameter): bool => $parameter->getAttributes(\SensitiveParameter::class) !== []);
        $sensitive  = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), array_values($marked));

        self::assertSame(['record', 'context', 'properties'], $sensitive);
    }

    /**
     * The finalised record is a final, readonly value with a public
     * constructor.
     *
     * @return void
     */
    public function testIsFinalAndReadonly(): void
    {
        $reflection  = new \ReflectionClass(FinalisedRecord::class);
        $constructor = $reflection->getConstructor();

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPublic());
        self::assertSame(32767, FinalisedRecord::MAX_INTEGRITY_VERSION);
    }

    /**
     * Rows of `[recorded at]`: times that are not ISO-8601 UTC with
     * microseconds, or name a date that does not exist.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedTimes(): iterable
    {
        yield from [
            'no fraction'          => ['2026-11-01T12:00:01Z'],
            'three digits'         => ['2026-11-01T12:00:01.654Z'],
            'an offset for Z'      => ['2026-11-01T12:00:01.654321+00:00'],
            'the stored form'      => ['2026-11-01 12:00:01.654321'],
            'a date that is not'   => ['2026-11-31T12:00:01.654321Z'],
            'a trailing line feed' => ["2026-11-01T12:00:01.654321Z\n"],
            'empty'                => [''],
        ];
    }

    /**
     * Each refused time fails closed, naming the form.
     *
     * @param  string  $recordedAt
     * @return void
     */
    #[DataProvider('provideRefusedTimes')]
    public function testRefusesARecordedAtThatIsNotIsoUtcWithMicroseconds(string $recordedAt): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TIME_MESSAGE);

        self::finalise(recordedAt: $recordedAt);
    }

    /**
     * A record cannot be recorded even one microsecond before its activity
     * occurred, nor on an earlier day.
     *
     * @return void
     */
    public function testRefusesARecordedAtBeforeTheActivityOccurred(): void
    {
        foreach (['2026-11-01T12:00:00.123455Z', '2026-10-31T23:59:59.999999Z'] as $recordedAt) {
            try {
                self::finalise(recordedAt: $recordedAt);
                self::fail('Expected the time to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::BEFORE_MESSAGE, $exception->getMessage(), $recordedAt);
            }
        }
    }

    /**
     * A record may be recorded at the instant its activity occurred, or later.
     *
     * @return void
     */
    public function testAcceptsARecordedAtEqualToTheOccurrence(): void
    {
        self::assertSame(RecordFactory::OCCURRED_AT, self::finalise(recordedAt: RecordFactory::OCCURRED_AT)->recordedAt);
        self::assertSame('2026-11-01T12:00:00.123457Z', self::finalise(recordedAt: '2026-11-01T12:00:00.123457Z')->recordedAt);
    }

    /**
     * An integrity version must fit the smallint column and be at least 1: 0
     * and 32768 are refused, and both bounds are accepted.
     *
     * @return void
     */
    public function testRefusesAnIntegrityVersionOutsideItsColumn(): void
    {
        foreach ([0, -1, 32768, PHP_INT_MAX] as $version) {
            try {
                self::finalise(integrityVersion: $version);
                self::fail('Expected the integrity version to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::VERSION_MESSAGE, $exception->getMessage(), (string) $version);
            }
        }

        self::assertSame(1, self::finalise(integrityVersion: 1)->integrityVersion);
        self::assertSame(32767, self::finalise(integrityVersion: 32767)->integrityVersion);
    }

    /**
     * Rows of `[key id]`: ids the `key_id` column cannot hold, or that do not
     * start with a letter or a digit.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedKeyIds(): iterable
    {
        yield from [
            'empty'                => [''],
            '33 characters'        => [str_repeat('a', 33)],
            'a leading dot'        => ['.key'],
            'a leading hyphen'     => ['-key'],
            'a leading underscore' => ['_key'],
            'a space'              => ['key 1'],
            'a slash'              => ['key/1'],
            'a colon'              => ['key:1'],
            'non-ASCII'            => ['clé'],
            'a trailing line feed' => ["key\n"],
        ];
    }

    /**
     * Each refused key id fails closed, naming what an id may hold.
     *
     * @param  string  $keyId
     * @return void
     */
    #[DataProvider('provideRefusedKeyIds')]
    public function testRefusesAKeyIdTheColumnCannotHold(string $keyId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::KEY_ID_MESSAGE);

        self::finalise(keyId: $keyId);
    }

    /**
     * Key ids of the integrity layer's shapes and lengths are accepted.
     *
     * @return void
     */
    public function testAcceptsAKeyIdTheColumnCanHold(): void
    {
        foreach ([self::KEY_ID, str_repeat('k', 32), 'a', '0', 'Z', 'Key-2026.11_01'] as $keyId) {
            self::assertSame($keyId, self::finalise(keyId: $keyId)->keyId);
        }
    }

    /**
     * Rows of `[hmac]`: values that are not 64 lower-case hexadecimal
     * characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedHmacs(): iterable
    {
        yield from [
            'upper-case hex'       => [strtoupper(self::HMAC)],
            '63 characters'        => [substr(self::HMAC, 1)],
            '65 characters'        => [self::HMAC . '0'],
            'non-hex'              => ['g' . substr(self::HMAC, 1)],
            'a trailing line feed' => [self::HMAC . "\n"],
            'raw bytes'            => [str_repeat("\xAB", 32)],
            'empty'                => [''],
        ];
    }

    /**
     * Each refused HMAC fails closed, naming its form.
     *
     * @param  string  $hmac
     * @return void
     */
    #[DataProvider('provideRefusedHmacs')]
    public function testRefusesAMalformedHmac(string $hmac): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::HMAC_MESSAGE);

        self::finalise(hmac: $hmac);
    }

    /**
     * Rows of `[column, value]`: ids and import batch ids that are not a
     * lower-case UUID.
     *
     * @return iterable<string, array{0: 'id'|'import_batch_id', 1: string}>
     */
    public static function provideRefusedUuids(): iterable
    {
        $uuid = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

        foreach (['id', 'import_batch_id'] as $column) {
            yield from [
                "{$column} in upper case"          => [$column, strtoupper($uuid)],
                "{$column} in braces"              => [$column, '{' . $uuid . '}'],
                "{$column} with no hyphens"        => [$column, str_replace('-', '', $uuid)],
                "{$column} of 35 characters"       => [$column, substr($uuid, 0, 35)],
                "{$column} as a URN"               => [$column, 'urn:uuid:' . $uuid],
                "{$column} with a trailing feed"   => [$column, $uuid . "\n"],
                "{$column} with a non-hex digit"   => [$column, 'g' . substr($uuid, 1)],
                "{$column} with misplaced hyphens" => [$column, '0192f1c47-b8e-7c3a-9d2e-5f6a7b8c9d0e'],
                "{$column} empty"                  => [$column, ''],
            ];
        }
    }

    /**
     * An id that is not a lower-case UUID fails closed, as PostgreSQL would
     * refuse it or return it in another form.
     *
     * @param  'id'|'import_batch_id'  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedUuids')]
    public function testRefusesAnIdOrImportBatchIdThatIsNotALowerCaseUuid(string $column, string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(self::UUID_MESSAGE, $column));

        self::finalise(RecordFactory::withFields([$column => $value]));
    }

    /**
     * A captured record has no import batch, which is accepted, and an import
     * batch id that is a lower-case UUID is accepted too.
     *
     * @return void
     */
    public function testAcceptsANullOrLowerCaseImportBatchId(): void
    {
        $uuid = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

        self::assertNull(self::finalise()->record->importBatchId);
        self::assertSame($uuid, self::finalise(RecordFactory::withFields(['import_batch_id' => $uuid]))->record->importBatchId);
    }

    /**
     * Rows of `[source digest]`: values the `source_digest` column cannot hold
     * as the 64 lower-case hexadecimal characters of a digest.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedSourceDigests(): iterable
    {
        yield from [
            'empty'              => [''],
            'upper case'         => [str_repeat('AB', 32)],
            'one short'          => [str_repeat('a', 63)],
            'one long'           => [str_repeat('a', 65)],
            'not hexadecimal'    => [str_repeat('z', 64)],
            'a trailing newline' => [str_repeat('a', 64) . "\n"],
        ];
    }

    /**
     * A source digest that is not 64 lower-case hex characters fails closed, as
     * its column would not keep it comparable.
     *
     * @param  string  $sourceDigest
     * @return void
     */
    #[DataProvider('provideRefusedSourceDigests')]
    public function testRefusesASourceDigestTheColumnCannotHold(string $sourceDigest): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::DIGEST_MESSAGE);

        self::finalise(RecordFactory::withFields(['source_digest' => $sourceDigest]));
    }

    /**
     * A captured record has no source digest, which is accepted, and a digest
     * of 64 lower-case hexadecimal characters is accepted too.
     *
     * @return void
     */
    public function testAcceptsANullOrLowerCaseHexSourceDigest(): void
    {
        self::assertNull(self::finalise()->record->sourceDigest);
        self::assertSame(self::HMAC, self::finalise(RecordFactory::withFields(['source_digest' => self::HMAC]))->record->sourceDigest);
    }

    /**
     * Rows of `[fields, recorded at, integrity version, key id, hmac, the
     * message]`: two refused values and the one checked first.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string, 2: int, 3: string, 4: string, 5: string}>
     */
    public static function provideRefusalOrder(): iterable
    {
        yield from [
            'the time before the occurrence'  => [[], '', 1, self::KEY_ID, self::HMAC, self::TIME_MESSAGE],
            'the occurrence before a version' => [[], '2026-11-01T12:00:00.000000Z', 0, self::KEY_ID, self::HMAC, self::BEFORE_MESSAGE],
            'the version before the key id'   => [[], self::RECORDED_AT, 0, '', self::HMAC, self::VERSION_MESSAGE],
            'the key id before the HMAC'      => [[], self::RECORDED_AT, 1, '', '', self::KEY_ID_MESSAGE],
            'the HMAC before the id'          => [['id' => 'X'], self::RECORDED_AT, 1, self::KEY_ID, '', self::HMAC_MESSAGE],
            'the id before the import batch'  => [['id' => 'X', 'import_batch_id' => 'X'], self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, sprintf(self::UUID_MESSAGE, 'id')],
            'the import batch before digest'  => [['import_batch_id' => 'X', 'source_digest' => 'X'], self::RECORDED_AT, 1, self::KEY_ID, self::HMAC, self::BATCH_MESSAGE],
        ];
    }

    /**
     * With two refused values, the one checked first is the one named.
     *
     * @param  array<string, string>  $fields
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusalOrder')]
    public function testChecksEachValueInOrder(array $fields, string $recordedAt, int $integrityVersion, string $keyId, string $hmac, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new FinalisedRecord(RecordFactory::withFields($fields), $recordedAt, $integrityVersion, $keyId, $hmac);
    }

    /**
     * A finalised record of the record, or of a captured one, with the
     * finalisation's values given and valid ones for the rest.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  string  $recordedAt
     * @param  int  $integrityVersion
     * @param  string  $keyId
     * @param  string  $hmac
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     */
    private static function finalise(
        ?AuditRecord $record = null,
        string $recordedAt = self::RECORDED_AT,
        int $integrityVersion = 1,
        string $keyId = self::KEY_ID,
        string $hmac = self::HMAC,
    ): FinalisedRecord {
        return new FinalisedRecord($record ?? RecordFactory::captured(), $recordedAt, $integrityVersion, $keyId, $hmac);
    }
}
