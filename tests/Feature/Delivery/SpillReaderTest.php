<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Delivery\SpillLine;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the spill reader: it takes exactly one JSON object after
 * the marker whatever a channel's format put around it, keeps strings and
 * escapes out of the structure, numbers every line and yields only the marked
 * ones, calls an unclosed object truncated and never repairs it, and costs
 * memory for each line's own length, up to the bound, past which nothing is
 * kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SpillReader::class)]
#[CoversClass(SpillLine::class)]
final class SpillReaderTest extends TestCase
{
    /** @var string The marker every spill line holds. */
    private const string MARKER = FailureSpill::MARKER;

    /** @var int The bound the memory tests read under, in bytes. */
    private const int TEST_BOUND = 65536;

    /** @var list<string> The files each test wrote. */
    private array $files = [];

    /**
     * Remove the files the test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * Each line holding the marker gives its JSON, in order.
     *
     * @return void
     */
    public function testYieldsEachMarkedLine(): void
    {
        $lines = $this->read(self::MARKER . '{"a":1}' . "\n" . self::MARKER . '{"b":2}' . "\n");

        self::assertSame(['{"a":1}', '{"b":2}'], array_map(static fn (SpillLine $line): ?string => $line->json, $lines));
        self::assertSame([null, null], array_map(static fn (SpillLine $line): ?EnvelopeFailure => $line->failure, $lines));
    }

    /**
     * A line without the marker is another channel's and is not yielded, so it
     * is not counted anywhere.
     *
     * @return void
     */
    public function testIgnoresUnmarkedLines(): void
    {
        $lines = $this->read("a line of another channel\n{\"a\":1}\n\n" . 'audit-log:v1 {"b":2}' . "\n");

        self::assertSame([], $lines);
    }

    /**
     * A line's number counts every line of the file, the ignored ones included.
     *
     * @return void
     */
    public function testNumbersEveryLine(): void
    {
        $lines = $this->read("other\n" . self::MARKER . '{"a":1}' . "\n\nother\n" . self::MARKER . '{"b":2}' . "\n");

        self::assertSame([2, 5], array_map(static fn (SpillLine $line): int => $line->number, $lines));
    }

    /**
     * The last line of a file need not end in a newline.
     *
     * @return void
     */
    public function testALastLineWithNoNewlineIsRead(): void
    {
        $lines = $this->read(self::MARKER . '{"a":1}');

        self::assertSame('{"a":1}', $lines[0]->json);
    }

    /**
     * A channel's prefix before the marker is ignored.
     *
     * @return void
     */
    public function testExtractsFromAChannelPrefixedLine(): void
    {
        self::assertSame('{"a":1}', SpillReader::extract('[2026-11-01 12:00:00] production.CRITICAL: ' . self::MARKER . '{"a":1}' . "\n"));
    }

    /**
     * A channel's suffix after the object is ignored.
     *
     * @return void
     */
    public function testExtractsFromALineWithAChannelSuffix(): void
    {
        self::assertSame('{"a":1}', SpillReader::extract(self::MARKER . '{"a":1} [] []' . "\n"));
    }

    /**
     * Exactly one object is taken: a second after the first is not part of it.
     *
     * @return void
     */
    public function testExtractsExactlyOneValue(): void
    {
        self::assertSame('{"a":{"b":{}}}', SpillReader::extract(self::MARKER . '{"a":{"b":{}}} {"c":3}'));
    }

    /**
     * Rows of `[the line after the marker, the object it holds]`: every string
     * with something in it that would be structure outside one.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStrings(): iterable
    {
        yield from [
            'a closing brace'             => ['{"a":"}"} tail', '{"a":"}"}'],
            'an opening brace'            => ['{"a":"{"} tail', '{"a":"{"}'],
            'a brace in a key'            => ['{"}":1} tail', '{"}":1}'],
            'a brace after a nested one'  => ['{"a":{"b":"}"},"c":"}"} tail', '{"a":{"b":"}"},"c":"}"}'],
            'an escaped backslash at end' => ['{"a":"\\\"} tail', '{"a":"\\\"}'],
        ];
    }

    /**
     * A brace in a string is not structure.
     *
     * @param  string  $after
     * @param  string  $object
     * @return void
     */
    #[DataProvider('provideStrings')]
    public function testABraceInAStringIsNotStructure(string $after, string $object): void
    {
        self::assertSame($object, SpillReader::extract(self::MARKER . $after));
    }

    /**
     * An escaped quote does not end its string, so a brace after it stays in
     * the string.
     *
     * @return void
     */
    public function testAnEscapedQuoteStaysInItsString(): void
    {
        self::assertSame('{"a":"\"}"}', SpillReader::extract(self::MARKER . '{"a":"\"}"} tail'));
    }

    /**
     * The marker inside a value is only a value: extraction starts after the
     * first marker and goes on past the second.
     *
     * @return void
     */
    public function testAMarkerInAValueIsNotAMarker(): void
    {
        $object = '{"a":"' . self::MARKER . '{}","b":2}';

        self::assertSame($object, SpillReader::extract(self::MARKER . $object . ' tail'));
    }

    /**
     * A line with no marker holds no object.
     *
     * @return void
     */
    public function testAnUnmarkedLineExtractsNothing(): void
    {
        self::assertNull(SpillReader::extract('{"a":1}'));
    }

    /**
     * Rows of `[the line after the marker]`: objects left open, each of which
     * ends in a different state of the scan, and none of which is repaired.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTruncatedLines(): iterable
    {
        yield from [
            'an opening brace alone' => ['{'],
            'in the structure'       => ['{"a":1,'],
            'in a nested object'     => ['{"a":{"b":1}'],
            'in a string'            => ['{"a":"b'],
            'in an escape'           => ['{"a":"b\\'],
            'a brace in the string'  => ['{"a":"}'],
            'at the marker'          => [''],
            'at the marker, newline' => ["\n"],
            'at the marker, CRLF'    => ["\r\n"],
        ];
    }

    /**
     * An object left open is truncated, holds no JSON, and is never repaired.
     *
     * @param  string  $after
     * @return void
     */
    #[DataProvider('provideTruncatedLines')]
    public function testATruncatedLineIsTruncated(string $after): void
    {
        $lines = $this->read('prefix ' . self::MARKER . $after);

        self::assertCount(1, $lines);
        self::assertNull($lines[0]->json);
        self::assertSame(EnvelopeFailure::TRUNCATED, $lines[0]->failure);
    }

    /**
     * What follows the marker must start `{`: anything else is no object, and
     * is malformed, not truncated.
     *
     * @return void
     */
    public function testSomethingOtherThanAnObjectIsMalformed(): void
    {
        $lines = $this->read(self::MARKER . "[1,2]\n" . self::MARKER . ' {"a":1}' . "\n");

        self::assertSame([EnvelopeFailure::MALFORMED, EnvelopeFailure::MALFORMED], array_map(static fn (SpillLine $line): ?EnvelopeFailure => $line->failure, $lines));
        self::assertNull($lines[0]->json);
        self::assertNull(SpillReader::extract(self::MARKER . '[1,2]'));
    }

    /**
     * A line ten times the bound holding the marker is truncated, the reader
     * goes on to the next line, and the peak stays far below what holding the
     * line would cost: protects against a reader that accumulates the remainder
     * or reads the whole line before it checks the bound.
     *
     * @return void
     */
    public function testAnOverlongLineIsTruncatedWithoutBeingHeld(): void
    {
        $path = $this->overlongFile(self::MARKER . '{"a":"');

        $reader = new SpillReader(self::TEST_BOUND);

        // Everything the reading needs is loaded before the baseline is taken
        iterator_to_array($reader->lines($this->file('')), false);

        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();
        $lines  = iterator_to_array($reader->lines($path), false);
        $growth = memory_get_peak_usage() - $before;

        self::assertLessThan(4 * (self::TEST_BOUND + SpillReader::FRAMING_BYTES), $growth);
        self::assertCount(2, $lines);
        self::assertSame([1, null, EnvelopeFailure::TRUNCATED], [$lines[0]->number, $lines[0]->json, $lines[0]->failure]);
        self::assertSame([2, '{"next":1}', null], [$lines[1]->number, $lines[1]->json, $lines[1]->failure]);
    }

    /**
     * A line past the bound with no marker in what is held is ignored, and the
     * next line is still read and numbered: protects against a marker search
     * made on the remainder, which is not kept.
     *
     * @return void
     */
    public function testAnOverlongLineWithoutTheMarkerIsIgnored(): void
    {
        $lines = iterator_to_array((new SpillReader(self::TEST_BOUND))->lines($this->overlongFile('other channel ')), false);

        self::assertCount(1, $lines);
        self::assertSame([2, '{"next":1}'], [$lines[0]->number, $lines[0]->json]);
    }

    /**
     * Rows of `[the line's length, whether it is past the bound]`: one byte
     * short of the bound and exactly at it, each without a newline. The bound
     * is the test's plus the framing allowance.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideLengthsAroundTheBound(): iterable
    {
        $bound = 8192 + SpillReader::FRAMING_BYTES;

        yield from [
            'one byte short' => [$bound - 1, false],
            'at the bound'   => [$bound, true],
        ];
    }

    /**
     * A line that reaches the bound is past it, however well-formed; a shorter
     * one is whole.
     *
     * @param  int  $length
     * @param  bool  $past
     * @return void
     */
    #[DataProvider('provideLengthsAroundTheBound')]
    public function testTheBoundIsInclusive(int $length, bool $past): void
    {
        $open = self::MARKER . '{"a":"';
        $line = $open . str_repeat('x', $length - strlen($open) - 2) . '"}';

        $lines = iterator_to_array((new SpillReader(8192))->lines($this->file($line)), false);

        self::assertSame($length, strlen($line));
        self::assertCount(1, $lines);
        self::assertSame($past ? EnvelopeFailure::TRUNCATED : null, $lines[0]->failure);
        self::assertSame($past ? null : substr($line, strlen(self::MARKER)), $lines[0]->json);
    }

    /**
     * The reading stops as soon as a line reaches the bound, so a line that
     * reaches it on a chunk's last byte is past it even though its newline is
     * in the next chunk: protects against one chunk more being held.
     *
     * @return void
     */
    public function testAChunkEndingAtTheBoundStopsTheReading(): void
    {
        $chunk = SpillReader::FRAMING_BYTES - 1;
        $bound = 3 * $chunk;
        $open  = self::MARKER . '{"a":"';
        $line  = $open . str_repeat('x', $bound - strlen($open)) . '"}' . "\n";

        $lines = iterator_to_array((new SpillReader($bound - SpillReader::FRAMING_BYTES))->lines($this->file($line)), false);

        self::assertCount(1, $lines);
        self::assertSame(EnvelopeFailure::TRUNCATED, $lines[0]->failure);
    }

    /**
     * Under the real bound, reading many short lines costs memory for those
     * lines: protects against giving `fgets()` the bound, which allocates about
     * 200 MB for each line whatever its length.
     *
     * @return void
     */
    public function testAShortLineCostsMemoryForItsOwnLengthOnly(): void
    {
        $line   = self::MARKER . '{"amount":"1200.00"}' . "\n";
        $reader = new SpillReader;
        $path   = $this->file(str_repeat($line, 1000));

        // Everything the reading needs is loaded before the baseline is taken
        iterator_to_array($reader->lines($this->file($line)), false);

        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();
        $count  = 0;

        foreach ($reader->lines($path) as $read) {
            $count += $read->json === null ? 0 : 1;
        }

        $growth = memory_get_peak_usage() - $before;

        self::assertSame(1000, $count);
        self::assertLessThan(16 * (strlen($line) + SpillReader::FRAMING_BYTES), $growth);
    }

    /**
     * A line longer than a chunk comes back whole, even with its marker across
     * the first two chunks.
     *
     * @return void
     */
    public function testALineSplitAcrossChunksIsWhole(): void
    {
        $object = '{"a":"' . str_repeat('x', 3 * SpillReader::FRAMING_BYTES) . '"}';
        $prefix = str_repeat('p', SpillReader::FRAMING_BYTES - 5);

        $lines = $this->read($prefix . self::MARKER . $object . " [] []\n" . self::MARKER . '{"b":2}' . "\n");

        self::assertSame($object, $lines[0]->json);
        self::assertSame([2, '{"b":2}'], [$lines[1]->number, $lines[1]->json]);
    }

    /**
     * A bundle's line, framed by a channel's prefix and suffix and longer than
     * several chunks, is taken whole: the bundle's one object, its attachment
     * and its record together, which the codec decodes to the record and its
     * attachment, and the next line is read as its own.
     *
     * @return void
     */
    public function testABundleLineIsExtractedWhole(): void
    {
        $record   = RecordFactory::finalisedBundle(200);
        $envelope = EnvelopeCodec::envelopeOf($record);
        $line     = FailureSpill::line($envelope);

        self::assertGreaterThan(2 * SpillReader::FRAMING_BYTES, strlen($line));

        $lines = $this->read('[2026-11-01 12:00:00] production.CRITICAL: ' . $line . " [] []\n" . self::MARKER . '{"b":2}' . "\n");

        self::assertCount(2, $lines);
        self::assertSame([1, null], [$lines[0]->number, $lines[0]->failure]);
        self::assertSame(substr($line, strlen(self::MARKER)), $lines[0]->json);
        self::assertSame(CanonicalEncoder::encode($envelope), $lines[0]->json);
        self::assertSame([2, '{"b":2}'], [$lines[1]->number, $lines[1]->json]);

        $decoded = app(EnvelopeCodec::class)->decode($lines[0]->json, $record->record->id);

        self::assertSame($record->hmac, $decoded->hmac);
        self::assertEquals($record->record->attachment, $decoded->record->attachment);
    }

    /**
     * A path that cannot be read is refused as soon as it is asked for, before
     * the first line is, naming the path.
     *
     * @return void
     */
    public function testAnUnreadablePathIsRefused(): void
    {
        $path = sys_get_temp_dir() . '/audit-log-no-such-spill-file.log';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The spill file [%s] cannot be read.', $path));

        (new SpillReader)->lines($path);
    }

    /**
     * A directory is not a file that can be read.
     *
     * @return void
     */
    public function testADirectoryIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new SpillReader)->lines(sys_get_temp_dir());
    }

    /**
     * An empty file has no lines.
     *
     * @return void
     */
    public function testAnEmptyFileHasNoLines(): void
    {
        self::assertSame([], $this->read(''));
    }

    /**
     * The reader's lines from a file holding the contents.
     *
     * @param  string  $contents
     * @return list<\SineMacula\Laravel\AuditLog\Delivery\SpillLine>
     */
    private function read(string $contents): array
    {
        return iterator_to_array((new SpillReader)->lines($this->file($contents)), false);
    }

    /**
     * A file holding the contents, removed when the test ends.
     *
     * @param  string  $contents
     * @return string
     */
    private function file(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * A file whose first line starts with the head and runs to ten times the
     * test's bound, written in pieces so the test holds none of it, and whose
     * second line is a marked one.
     *
     * @param  string  $head
     * @return string
     */
    private function overlongFile(string $head): string
    {
        $path   = $this->file($head);
        $handle = fopen($path, 'ab');

        self::assertIsResource($handle);

        for ($piece = 0; $piece < 160; $piece++) {
            fwrite($handle, str_repeat('x', 4096));
        }

        fwrite($handle, "\n" . self::MARKER . '{"next":1}' . "\n");
        fclose($handle);

        return $path;
    }
}
