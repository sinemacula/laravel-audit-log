<?php

declare(strict_types = 1);

namespace Tests\Unit\Export;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the NDJSON formatter: the line is the record's envelope in the
 * canonical encoding, on one physical line whatever a value holds, the same
 * bytes on every call, with Unicode kept and a map of numbered keys kept a map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NdjsonFormatter::class)]
final class NdjsonFormatterTest extends TestCase
{
    /** @var string The id every record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string When every record was recorded. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /**
     * The line is the canonical encoding of the finalised record's envelope,
     * HMAC included, with no line ending.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testIsTheCanonicalEnvelope(): void
    {
        $record = self::finalised(RecordFactory::captured(id: self::ID));
        $line   = (new NdjsonFormatter)->format($record);

        self::assertSame(CanonicalEncoder::encode($record->toArray()), $line);
        // The line sorts its keys, so only the values are compared
        self::assertEquals($record->toArray(), json_decode($line, true, 512, JSON_THROW_ON_ERROR));
        self::assertStringStartsWith('{"actor_id":"42","actor_type":"user","category":"finance",', $line);
        self::assertStringEndsWith('"user_agent":"Mozilla/5.0"}', $line);
    }

    /**
     * A carriage return, a line feed and the Unicode line and paragraph
     * separators in any value are escaped inside their string, so the line is
     * one physical line, and each decodes back to what the record holds.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testIsOneLineWhateverAValueHolds(): void
    {
        $hostile = ['cr' => "a\rb", 'lf' => "a\nb", 'crlf' => "a\r\nb", 'line' => "a\u{2028}b", 'paragraph' => "a\u{2029}b"];
        $record  = self::finalised(RecordFactory::withFields(['user_agent' => "agent\r\n", 'properties' => $hostile]));
        $line    = (new NdjsonFormatter)->format($record);

        foreach (["\r", "\n", "\u{2028}", "\u{2029}"] as $separator) {
            self::assertStringNotContainsString($separator, $line);
        }

        self::assertStringContainsString('"line":"a\u2028b","paragraph":"a\u2029b"', $line);
        // The line sorts its keys, so only the values are compared
        self::assertEquals($record->toArray(), json_decode($line, true, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * The same record gives the same bytes on every call and from every
     * formatter, whatever order its maps were built in.
     *
     * @return void
     */
    public function testRepeatsByteForByte(): void
    {
        $record    = self::finalised(RecordFactory::captured(['b' => '2', 'a' => ['y' => true, 'x' => null]], self::ID));
        $reordered = self::finalised(RecordFactory::withFields(['properties' => ['a' => ['x' => null, 'y' => true], 'b' => '2']], $record->record));
        $line      = (new NdjsonFormatter)->format($record);

        self::assertSame($line, (new NdjsonFormatter)->format($record));
        self::assertSame($line, (new NdjsonFormatter)->format($reordered));
    }

    /**
     * Unicode outside the line separators is written as it is, not escaped:
     * accents, other scripts, emoji and their joined sequences.
     *
     * @return void
     */
    public function testKeepsUnicodeAsItIs(): void
    {
        $text = "Zoë 日本語 🎉 👩\u{200D}💻";
        $line = (new NdjsonFormatter)->format(self::finalised(RecordFactory::withFields(['properties' => ['note' => $text]])));

        self::assertStringContainsString('"note":"' . $text . '"', $line);
        self::assertStringNotContainsString('\u', $line);
    }

    /**
     * A map whose keys are numbers, in or out of order, stays a map with its
     * keys sorted, never a list.
     *
     * @return void
     */
    public function testAMapWithNumericKeysStaysAMap(): void
    {
        $properties = ['sparse' => [5 => 'a'], 'reversed' => [1 => 'x', 0 => 'y'], 'list' => ['p', 'q']];
        $line       = (new NdjsonFormatter)->format(self::finalised(RecordFactory::withFields(['properties' => $properties])));

        self::assertStringContainsString('"properties":{"list":["p","q"],"reversed":{"0":"y","1":"x"},"sparse":{"5":"a"}}', $line);
    }

    /**
     * A value the canonical encoding cannot hold, such as a float, is refused
     * rather than written in some other form.
     *
     * @return void
     */
    public function testRefusesAValueWithNoCanonicalForm(): void
    {
        $record = self::finalised(RecordFactory::withFields(['properties' => ['amount' => 12.5]]));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A float cannot be encoded canonically; the package stores decimals as strings.');

        (new NdjsonFormatter)->format($record);
    }

    /**
     * The record's parameter is marked sensitive, so a stack trace never holds
     * the record.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(NdjsonFormatter::class, 'format'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The record finalised, recorded a second after it occurred.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function finalised(AuditRecord $record): FinalisedRecord
    {
        return new FinalisedRecord($record, self::RECORDED_AT, 1, 'k1', self::HMAC);
    }
}
