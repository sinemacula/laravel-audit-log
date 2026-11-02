<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the round trip of a record through the engine the suite
 * runs against: each record is stored through the store, read back through the
 * row codec, and verified by the signer, so whatever the engine does to what it
 * stores (reordering JSON keys, dropping trailing fractional zeros, reading
 * times in a session time zone) the evidence still verifies, and an edit to it
 * does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
#[CoversClass(RowCodec::class)]
#[CoversClass(RecordSigner::class)]
final class StoredEntryRoundTripTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The application time zone before the test, restored after it. */
    private string $applicationTimezone = 'UTC';

    /** @var string The default time zone before the test, restored after it. */
    private string $defaultTimezone = 'UTC';

    /**
     * Remember the time zones, so a test may change them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->applicationTimezone = app(ConfigRepository::class)->string('app.timezone', 'UTC');
        $this->defaultTimezone     = date_default_timezone_get();
    }

    /**
     * Restore the time zones after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        app(ConfigRepository::class)->set('app.timezone', $this->applicationTimezone);
        date_default_timezone_set($this->defaultTimezone);

        parent::tearDown();
    }

    /**
     * A stored record verifies once read back.
     *
     * @return void
     */
    public function testAStoredRecordVerifiesAfterTheRoundTrip(): void
    {
        $this->assertRoundTripVerifies(RecordFactory::captured(id: self::ID));
    }

    /**
     * Nested properties whose keys MySQL's JSON reorders (by length, then
     * bytes) and numeric keys among them still verify: the canonical encoding
     * sorts the keys itself.
     *
     * @return void
     */
    public function testNestedPropertiesTheEngineReordersStillVerify(): void
    {
        $properties = [
            'zeta' => ['mm' => 1, 'a' => ['10' => 'ten', '2' => 'two'], 'zeta' => true],
            'a'    => 'first',
            'mm'   => [3, 1, 2],
            '10'   => null,
            '2'    => ['b' => 'x', 'aa' => 'y'],
        ];

        $stored = $this->assertRoundTripVerifies(RecordFactory::captured($properties, self::ID));

        self::assertSame(
            '{"10":null,"2":{"aa":"y","b":"x"},"a":"first","mm":[3,1,2],"zeta":{"a":{"10":"ten","2":"two"},"mm":1,"zeta":true}}',
            CanonicalEncoder::encode($stored['properties']),
        );
    }

    /**
     * Unicode and text that is hostile to JSON, HTML or a line-based reader
     * still verifies: a 4-byte emoji, combining marks, a quote, a backslash, a
     * closing script tag, U+2028, and keys containing `.` and `*`.
     *
     * @return void
     */
    public function testUnicodeAndHostileTextStillVerify(): void
    {
        $properties = [
            'emoji'      => "\u{1F600} \u{1F469}\u{200D}\u{1F4BB}",
            'combining'  => "e\u{0301}a\u{0308}",
            'quote'      => 'say "hello"',
            'backslash'  => 'C:\Temp\new',
            'script'     => '</script><script>alert(1)</script>',
            'separator'  => "line\u{2028}next\u{2029}end",
            'dotted.key' => ['star*key' => '*', 'a.b.c' => '.'],
        ];

        $stored = $this->assertRoundTripVerifies(RecordFactory::captured($properties, self::ID));

        self::assertEquals(json_decode((string) json_encode($properties)), $stored['properties']);
    }

    /**
     * The record's integer and float rules survive the engine: the largest safe
     * integer stays an integer, one beyond it is a decimal string, and floats
     * are their shortest decimal strings, negative zero as `"0"`.
     *
     * @return void
     */
    public function testTheIntegerAndFloatStringRulesSurvive(): void
    {
        $properties = ['safe' => 9007199254740991, 'unsafe' => 9007199254740992, 'tenth' => 0.1, 'zero' => -0.0];

        $stored = $this->assertRoundTripVerifies(RecordFactory::captured($properties, self::ID));

        self::assertEquals((object) ['safe' => 9007199254740991, 'unsafe' => '9007199254740992', 'tenth' => '0.1', 'zero' => '0'], $stored['properties']);
        $stored = $stored['properties'];

        self::assertInstanceOf(\stdClass::class, $stored);
        self::assertSame(9007199254740991, $stored->safe);
        self::assertSame('9007199254740992', $stored->unsafe);
    }

    /**
     * Both times keep all six fractional digits through the engine, trailing
     * zeros included, which PostgreSQL drops and the codec restores.
     *
     * @return void
     */
    public function testMicrosecondsSurviveIncludingTrailingZeros(): void
    {
        foreach (['123456', '100000', '000000'] as $index => $fraction) {

            $id     = sprintf('01932b4e-8a40-7000-8000-%012d', $index + 1);
            $at     = "2026-11-01 12:00:00.{$fraction}";
            $record = RecordFactory::captured(id: $id, occurredAt: "2026-11-01T12:00:00.{$fraction}Z");

            $this->store()->store($this->finaliser($at)->finalise($record));

            $stored = $this->storedRow($id);

            self::assertSame("2026-11-01T12:00:00.{$fraction}Z", $stored['occurred_at'], "The fraction .{$fraction}.");
            self::assertSame("2026-11-01T12:00:00.{$fraction}Z", $stored['recorded_at'], "The fraction .{$fraction}.");
            self::assertTrue(app(RecordSigner::class)->verifies($stored), "The fraction .{$fraction}.");
        }
    }

    /**
     * The instant reads back unchanged, and is stored as UTC, under a session
     * time zone of MySQL or PostgreSQL that is not UTC and under PHP's and the
     * application's time zone of Auckland.
     *
     * @return void
     */
    public function testTimesStayUtcUnderNonUtcSessionAndApplicationTimeZones(): void
    {
        $connection = $this->storageConnection();

        match ($connection->getDriverName()) {
            'mysql' => $connection->statement('SET time_zone = \'+05:00\''),
            'pgsql' => $connection->statement('SET TIME ZONE \'Pacific/Auckland\''),
            default => null,
        };

        app(ConfigRepository::class)->set('app.timezone', 'Pacific/Auckland');
        date_default_timezone_set('Pacific/Auckland');

        $stored = $this->assertRoundTripVerifies(RecordFactory::captured(id: self::ID));

        $raw = $connection->table(EntrySettings::table())->where('id', self::ID)->value('occurred_at');

        self::assertSame('2026-11-01T12:00:00.123456Z', $stored['occurred_at']);
        self::assertSame('2026-11-01T12:00:00.200000Z', $stored['recorded_at']);
        self::assertIsString($raw);
        self::assertStringStartsWith('2026-11-01 12:00:00.123456', $raw);
    }

    /**
     * A map with numeric keys stays a map, and an empty list stays a list,
     * through the engine.
     *
     * @return void
     */
    public function testNumericKeyMapsAndEmptyListsSurvive(): void
    {
        $properties = ['codes' => [7 => 'seven', 3 => 'three'], 'none' => [], 'nested' => ['inner' => [], 'list' => ['a', 'b']]];

        $stored = $this->assertRoundTripVerifies(RecordFactory::captured($properties, self::ID));

        self::assertSame('{"codes":{"3":"three","7":"seven"},"nested":{"inner":[],"list":["a","b"]},"none":[]}', CanonicalEncoder::encode($stored['properties']));
        $stored = $stored['properties'];

        self::assertInstanceOf(\stdClass::class, $stored);
        self::assertInstanceOf(\stdClass::class, $stored->codes);
        self::assertSame([], $stored->none);
    }

    /**
     * The stored row decodes to the finalised record: their canonical encodings
     * are equal, every column included.
     *
     * @return void
     */
    public function testTheStoredRowDecodesToTheFinalisedRecord(): void
    {
        $finalised = $this->finaliser()->finalise(RecordFactory::captured(['lines' => [['sku' => 'A-1', 'qty' => 2]], 'note' => null], self::ID));

        $this->store()->store($finalised);

        self::assertSame(CanonicalEncoder::encode($finalised->toArray()), CanonicalEncoder::encode($this->storedRow(self::ID)));
    }

    /**
     * A nested property edited in the stored row, with its HMAC left as it was,
     * fails verification.
     *
     * @return void
     */
    public function testAnEditedStoredRowFailsVerification(): void
    {
        $this->store()->store($this->finaliser()->finalise(RecordFactory::captured(['invoice' => ['amount' => '1200.00', 'currency' => 'GBP']], self::ID)));

        $this->storageConnection()->table(EntrySettings::table())->where('id', self::ID)->update(['properties' => '{"invoice":{"amount":"1.00","currency":"GBP"}}']);

        self::assertFalse(app(RecordSigner::class)->verifies($this->storedRow(self::ID)));
    }

    /**
     * Actor ids that differ only in case are two actors: each finds its own
     * entry, and both verify.
     *
     * @return void
     */
    public function testActorIdsDifferingOnlyInCaseAreDifferentActors(): void
    {
        $this->assertDistinctlyStored('actor_id', 'ABC', 'abc');
    }

    /**
     * Actor ids that differ only by a trailing space are two actors, which a
     * padding collation would compare equal.
     *
     * @return void
     */
    public function testIdsDifferingOnlyByATrailingSpaceStayDistinct(): void
    {
        $this->assertDistinctlyStored('actor_id', 'abc', 'abc ');
    }

    /**
     * Imported records whose source record ids differ only by a trailing space
     * are both stored, under the source-identity index a padding collation
     * would trip, and both verify.
     *
     * @return void
     */
    public function testSourceRecordIdsDifferingOnlyByATrailingSpaceAreBothStored(): void
    {
        $this->assertDistinctlyStored('source_record_id', 'r1', 'r1 ', ['provenance' => 'imported', 'source_id' => 'legacy-app']);
    }

    /**
     * Store the record finalised on the frozen clock, read it back and assert
     * it verifies; the decoded row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array<string, mixed>
     */
    private function assertRoundTripVerifies(AuditRecord $record): array
    {
        $finalised = $this->finaliser()->finalise($record);

        $this->store()->store($finalised);

        $stored = $this->storedRow($record->id);

        self::assertTrue(app(RecordSigner::class)->verifies($stored));
        self::assertSame($finalised->hmac, $stored['hmac']);

        return $stored;
    }

    /**
     * Store two records whose column holds the two values, and assert each is
     * its own row, found by its own value alone, and verifies.
     *
     * @param  'actor_id'|'source_record_id'  $column
     * @param  string  $one
     * @param  string  $other
     * @param  array<string, string>  $fields
     * @return void
     */
    private function assertDistinctlyStored(string $column, string $one, string $other, array $fields = []): void
    {
        $records = array_map(fn (string $value): FinalisedRecord => $this->finaliser()->finalise(RecordFactory::withFields([...$fields, $column => $value])), [$one, $other]);

        foreach ($records as $record) {
            $this->store()->store($record);
        }

        self::assertSame(2, $this->entryCount());

        foreach ($records as $index => $record) {

            $value = $index === 0 ? $one : $other;
            $found = $this->storageConnection()->table(EntrySettings::table())->where($column, $value)->pluck('id')->all();

            self::assertSame([$record->record->id], $found, "The {$column} '{$value}'.");
            self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($record->record->id)), "The {$column} '{$value}'.");
        }
    }
}
