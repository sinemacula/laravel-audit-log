<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for a stored entry: the row codec's envelope kept whole, its JSON
 * objects, numeric keys and integrity columns included; its line, which is the
 * NDJSON formatter's line of the same record; its positions and its signed
 * descriptor as stored; and the finalised record it rebuilds for a projection,
 * whose attachment is described from the descriptor and carries no members.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoredEntry::class)]
final class StoredEntryTest extends TestCase
{
    /** @var string The entry's id. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A key id as a derived key's fingerprint gives it. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /**
     * The envelope is the row codec's, whole and in table order: an empty
     * object stays an object beside an empty list, a map with numeric keys
     * stays a map, and the integrity version, key id and HMAC are kept.
     *
     * @return void
     */
    public function testTheEnvelopeIsLossless(): void
    {
        $properties = json_decode('{"0":"a","1":"b","empty":{},"none":[],"nested":{"10":{"x":1}}}', false, 512, JSON_THROW_ON_ERROR);
        $row        = self::row($properties, new \stdClass);
        $stored     = StoredEntry::fromRow($row, new RowCodec);

        self::assertSame(array_keys(RowCodec::COLUMNS), array_keys($stored->envelope));
        self::assertEquals((new RowCodec)->decode($row), $stored->envelope);
        self::assertInstanceOf(\stdClass::class, $stored->envelope['context']);
        self::assertInstanceOf(\stdClass::class, $stored->envelope['properties']);
        self::assertSame('{"0":"a","1":"b","empty":{},"none":[],"nested":{"10":{"x":1}}}', json_encode($stored->envelope['properties']));
        self::assertSame('{}', json_encode($stored->envelope['context']));
        self::assertSame(1, $stored->envelope['integrity_version']);
        self::assertSame(self::KEY_ID, $stored->envelope['key_id']);
        self::assertSame(self::HMAC, $stored->envelope['hmac']);
        self::assertStringContainsString('"context":{}', $stored->line());
        self::assertStringContainsString('"properties":{"0":"a","1":"b","empty":{},"nested":{"10":{"x":1}},"none":[]}', $stored->line());
    }

    /**
     * Rows of `[finalised record]`: a plain record and a record with each kind
     * of artifact.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord}>
     */
    public static function provideRecords(): iterable
    {
        yield from [
            'a plain record'   => [self::plain(...)],
            'a bulk operation' => [RecordFactory::finalisedBundle(...)],
            'a disclosure'     => [self::disclosure(...)],
            'an empty export'  => [self::emptyExport(...)],
        ];
    }

    /**
     * The line of a stored record is byte for byte the NDJSON formatter's line
     * of the record that was stored, and of the record it rebuilds.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     */
    #[DataProvider('provideRecords')]
    public function testTheLineIsTheNdjsonFormattersLine(\Closure $record): void
    {
        $finalised = $record();
        $stored    = StoredEntry::fromRow((new RowCodec)->encode($finalised), new RowCodec);
        $formatter = new NdjsonFormatter;

        self::assertSame($formatter->format($finalised), $stored->line());
        self::assertSame($stored->line(), $formatter->format($stored->finalised()));
        self::assertStringNotContainsString("\n", $stored->line());
    }

    /**
     * The entry's id, HMAC, key id and times are read as stored, and its
     * positions are when it occurred and when it was recorded, each with its
     * id.
     *
     * @return void
     */
    public function testPositions(): void
    {
        $stored = StoredEntry::fromRow(self::row(), new RowCodec);

        self::assertSame(self::ID, $stored->id());
        self::assertSame(self::HMAC, $stored->hmac());
        self::assertSame(self::KEY_ID, $stored->keyId());
        self::assertSame(RecordFactory::OCCURRED_AT, $stored->occurredAt());
        self::assertSame(RecordFactory::RECORDED_AT, $stored->recordedAt());
        self::assertSame([RecordFactory::OCCURRED_AT, self::ID], $stored->occurredPosition()->toArray());
        self::assertSame([RecordFactory::RECORDED_AT, self::ID], $stored->recordedPosition()->toArray());
    }

    /**
     * The descriptor is the one the entry signed, as stored, with no key added,
     * dropped or reordered; an entry without one has none.
     *
     * @return void
     */
    public function testTheDescriptorIsReadAsStored(): void
    {
        $finalised = RecordFactory::finalisedBundle(2);
        $stored    = StoredEntry::fromRow((new RowCodec)->encode($finalised), new RowCodec);
        $signed    = $finalised->record->attachment;

        self::assertNotNull($signed);
        self::assertSame(['artifact_id' => $signed->id, 'kind' => 'bulk', 'digest' => $signed->digest, 'count' => 2], $stored->descriptor());
        self::assertNull(StoredEntry::fromRow(self::row(), new RowCodec)->descriptor());
    }

    /**
     * Rows of `[properties, descriptor]`: properties that hold no descriptor,
     * and descriptors that are not maps, which are read as empty.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: ?array<array-key, mixed>}>
     */
    public static function provideOddDescriptors(): iterable
    {
        yield from [
            'a list of properties'        => ['[1,2]', null],
            'metadata that is a string'   => ['{"_audit":"manifest"}', null],
            'metadata with no manifest'   => ['{"_audit":{"note":"x"}}', null],
            'a descriptor of null'        => ['{"_audit":{"manifest":null}}', []],
            'a descriptor that is text'   => ['{"_audit":{"manifest":"x"}}', []],
            'a descriptor that is a list' => ['{"_audit":{"manifest":[1]}}', [1]],
            'a nested descriptor'         => ['{"_audit":{"manifest":{"kind":{"a":"b"}}}}', ['kind' => ['a' => 'b']]],
        ];
    }

    /**
     * A descriptor is only ever under `_audit.manifest` of a map of
     * properties; one there that is not a map reads as an empty array, which
     * no check accepts, and nested maps read as arrays.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $properties
     * @param  ?array<array-key, mixed>  $descriptor
     * @return void
     */
    #[DataProvider('provideOddDescriptors')]
    public function testADescriptorIsReadOnlyWhereItIsSigned(string $properties, ?array $descriptor): void
    {
        $row = ['properties' => $properties] + self::row();

        self::assertSame($descriptor, StoredEntry::fromRow($row, new RowCodec)->descriptor());
    }

    /**
     * The finalised record of an entry with an artifact carries an attachment
     * described from its descriptor, with no members, so it can never be
     * stored; the record's envelope is the entry's.
     *
     * @return void
     */
    public function testFinalisedCarriesADescribedAttachment(): void
    {
        $original  = self::disclosure();
        $stored    = StoredEntry::fromRow((new RowCodec)->encode($original), new RowCodec);
        $finalised = $stored->finalised();

        $attachment = $finalised->record->attachment;

        self::assertNotNull($attachment);
        self::assertFalse($attachment->isSealed());
        self::assertNull($attachment->members);
        self::assertSame($original->record->attachment?->id, $attachment->id);
        self::assertSame('disclosure', $attachment->kind);
        self::assertSame(2, $attachment->memberCount);
        self::assertTrue($attachment->describes($stored->descriptor() ?? []));
        self::assertSame($original->keyId, $finalised->keyId);
        self::assertSame($original->hmac, $finalised->hmac);
        self::assertSame($original->recordedAt, $finalised->recordedAt);
        self::assertSame($original->integrityVersion, $finalised->integrityVersion);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An attachment described from its entry carries no members and is never stored or encoded.');

        (new RowCodec)->encodeAttachment($finalised);
    }

    /**
     * The finalised record of a plain entry carries no attachment, keeps its
     * decoded objects as objects and leaves the entry's own untouched.
     *
     * @return void
     */
    public function testFinalisedOfAPlainEntryHasNone(): void
    {
        $stored    = StoredEntry::fromRow(self::row((object) ['empty' => new \stdClass], new \stdClass), new RowCodec);
        $finalised = $stored->finalised();

        self::assertNull($finalised->record->attachment);
        self::assertSame(['empty' => []], $finalised->record->properties);
        self::assertSame([], $finalised->record->context);
        self::assertInstanceOf(\stdClass::class, $finalised->toArray()['context']);
        self::assertSame($stored->line(), (new NdjsonFormatter)->format($finalised));

        $copy = $finalised->toArray()['properties'];

        self::assertInstanceOf(\stdClass::class, $copy);

        $copy->empty = 'changed';

        self::assertSame('{"empty":{}}', json_encode($stored->envelope['properties']));
    }

    /**
     * Rows of `[properties, context, exception, message]`: entries whose
     * finalised record cannot be rebuilt.
     *
     * @return iterable<string, array{0: string, 1: string, 2: class-string<\Throwable>, 3: string}>
     */
    public static function provideUnfinalisable(): iterable
    {
        $descriptor = 'A manifest descriptor is exactly a string `artifact_id`, `kind` and `digest` and an integer `count`.';

        yield from [
            'a context that is a number'      => ['{}', '5', \UnexpectedValueException::class, 'A stored entry\'s `context` is not an object, a list or null.'],
            'properties that are text'        => ['"x"', '{}', \UnexpectedValueException::class, 'A stored entry\'s `properties` is not an object, a list or null.'],
            'a descriptor that is not a map'  => ['{"_audit":{"manifest":"x"}}', '{}', \InvalidArgumentException::class, $descriptor],
            'a descriptor with a missing key' => ['{"_audit":{"manifest":{"kind":"bulk"}}}', '{}', \InvalidArgumentException::class, $descriptor],
        ];
    }

    /**
     * A JSON column a record cannot hold, or a descriptor that is not exactly
     * one, is refused, naming the column or the rule and never the value.
     *
     * @param  string  $properties
     * @param  string  $context
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnfinalisable')]
    public function testFinalisedRefusesWhatARecordCannotHold(string $properties, string $context, string $exception, string $message): void
    {
        $stored = StoredEntry::fromRow(['properties' => $properties, 'context' => $context] + self::row(), new RowCodec);

        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $stored->finalised();
    }

    /**
     * Rows of `[row, message]`: rows the row codec refuses.
     *
     * @return iterable<string, array{0: array<string, int|string|null>, 1: string}>
     */
    public static function provideMalformedRows(): iterable
    {
        $row = self::row();

        unset($row['hmac']);

        yield from [
            'a missing column'         => [$row, 'A stored entry has no `hmac` column.'],
            'an id that is not text'   => [['id' => 7] + self::row(), 'A stored entry\'s `id` is not a string.'],
            'JSON that does not parse' => [['properties' => '{'] + self::row(), 'A stored entry\'s `properties` is not JSON or null.'],
            'a time that is not one'   => [['occurred_at' => 'yesterday'] + self::row(), 'A stored entry\'s `occurred_at` is not a stored time.'],
        ];
    }

    /**
     * A row the row codec refuses is refused, naming the column.
     *
     * @param  array<string, int|string|null>  $row
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedRows')]
    public function testAMalformedRowIsRefused(array $row, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        StoredEntry::fromRow($row, new RowCodec);
    }

    /**
     * The line of an entry whose JSON holds a float is refused, since a float
     * has no canonical form; only a tampered row holds one.
     *
     * @return void
     */
    public function testALineOfAFloatIsRefused(): void
    {
        $stored = StoredEntry::fromRow(['properties' => '{"amount":1.5}'] + self::row(), new RowCodec);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A float cannot be encoded canonically; the package stores decimals as strings.');

        $stored->line();
    }

    /**
     * A plain captured record finalised at `RECORDED_AT` under the fixed key id
     * and HMAC.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function plain(): FinalisedRecord
    {
        return new FinalisedRecord(RecordFactory::captured(id: self::ID), RecordFactory::RECORDED_AT, 1, self::KEY_ID, self::HMAC);
    }

    /**
     * A signed record carrying a disclosure of two entries.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function disclosure(): FinalisedRecord
    {
        return RecordFactory::finalisedWithArtifact(ArtifactKind::DISCLOSURE, RecordFactory::canonical(ArtifactKind::DISCLOSURE, 2), 2);
    }

    /**
     * A signed record carrying the manifest of an export of no lines.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function emptyExport(): FinalisedRecord
    {
        return RecordFactory::finalisedWithArtifact(ArtifactKind::EXPORT, RecordFactory::canonical(ArtifactKind::EXPORT, 0), 0);
    }

    /**
     * A stored row of a captured record of an approved invoice, with the JSON
     * columns given as they were decoded, finalised at `RECORDED_AT` under the
     * fixed key id and HMAC.
     *
     * @param  ?\stdClass  $properties
     * @param  ?\stdClass  $context
     * @return array<string, int|string|null>
     */
    private static function row(?\stdClass $properties = null, ?\stdClass $context = null): array
    {
        $record = RecordFactory::captured(id: self::ID);

        $finalised = FinalisedRecord::decoded($record, RecordFactory::RECORDED_AT, 1, self::KEY_ID, self::HMAC, $context ?? $record->context, $properties ?? $record->properties);

        return (new RowCodec)->encode($finalised);
    }
}
