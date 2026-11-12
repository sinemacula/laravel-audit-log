<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Load budget for formatters and the spill reader: work and memory grow
 * linearly with the record, and a spill line costs memory in line with its own
 * length.
 *
 * Each large measurement is compared with a small one in this process. CPU time
 * is not asserted under Xdebug coverage, and no coverage is claimed, since
 * mutants these slow tests cover would be skipped as timeouts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class FormatterLoadTest extends PerformanceContractTestCase
{
    /** @var string The memory limit the tests run under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int How many bytes the small record's properties hold: 1 MiB. */
    private const int SMALL_BYTES = 1048576;

    /** @var int How many bytes the large record's properties hold: 10 MiB. */
    private const int LARGE_BYTES = 10485760;

    /** @var int Bytes each property's value holds, so the record has many keys and long values. */
    private const int FIELD_BYTES = 1024;

    /** @var int Most work the large record may cost over the small: linear is ten times, quadratic a hundred. */
    private const int MAX_WORK_RATIO = 35;

    /** @var int Most memory the large record may take over the small: linear is ten times, quadratic a hundred. */
    private const int MAX_MEMORY_RATIO = 20;

    /** @var int Runs each CPU measurement takes the least of, since noise only slows a run. */
    private const int ROUNDS = 5;

    /** @var int Line copies a read may hold at once: the line growing, the next chunk's copy and the object taken out. */
    private const int MAX_LINE_COPIES = 4;

    /** @var int What reading any line holds beyond the line itself, in bytes. */
    private const int READER_OVERHEAD = 262144;

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /** @var list<string> The files the test wrote. */
    private array $files = [];

    /**
     * Raise the memory limit, so a record fails the assertion rather than the
     * engine's limit.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Remove the files and restore the memory limit as far as the process
     * allows: a limit below what it still holds is refused.
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

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));

        parent::tearDown();
    }

    /**
     * Rows of `[formatter class, whether its line holds the properties]`, one
     * per shipped formatter.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter>, 1: bool}>
     */
    public static function provideFormatters(): iterable
    {
        yield from [
            'NDJSON' => [NdjsonFormatter::class, true],
            'OCSF'   => [OcsfFormatter::class, true],
            'CEF'    => [CefFormatter::class, false],
        ];
    }

    /**
     * Formatting a 10 MiB record costs CPU time and memory in line with a 1 MiB
     * one, and its line holds the whole record.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter>  $class
     * @param  bool  $holdsTheProperties
     * @return void
     */
    #[DataProvider('provideFormatters')]
    public function testFormattingIsLinearInTheRecord(string $class, bool $holdsTheProperties): void
    {
        $formatter = app($class);
        $small     = $this->finalisedOf(self::SMALL_BYTES);
        $large     = $this->finalisedOf(self::LARGE_BYTES);

        $line = $formatter->format($large);

        self::assertSame(0, preg_match('/[\r\n]/', $line));
        self::assertSame($holdsTheProperties, strlen($line) >= self::LARGE_BYTES);

        unset($line);

        self::assertLessThanOrEqual(
            self::MAX_MEMORY_RATIO * max(self::peakGrowthOf($formatter, $small), self::SMALL_BYTES),
            self::peakGrowthOf($formatter, $large),
            'The memory of formatting a large record is not in line with a small one.',
        );

        if (self::isCollectingCoverage()) {
            return;
        }

        $floor = self::leastCpu(static fn () => hash('sha256', str_repeat('x', intdiv(self::SMALL_BYTES, 4))));

        self::assertLessThanOrEqual(
            self::MAX_WORK_RATIO * max(self::leastCpu(static fn () => $formatter->format($small)), $floor),
            self::leastCpu(static fn () => $formatter->format($large)),
            'The work of formatting a large record is not in line with a small one.',
        );
    }

    /**
     * Rows of `[bytes in the record]`: a line of every length up to the largest
     * this test formats.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideLineLengths(): iterable
    {
        yield from [
            'a short line' => [0],
            '1 MiB'        => [self::SMALL_BYTES],
            '10 MiB'       => [self::LARGE_BYTES],
        ];
    }

    /**
     * Reading a spill line grows the peak by a few copies of that line, however
     * long a line may be.
     *
     * @param  int  $bytes
     * @return void
     */
    #[DataProvider('provideLineLengths')]
    public function testTheSpillReadsNoMoreThanItsLineHolds(int $bytes): void
    {
        $line = FailureSpill::line($this->finalisedOf($bytes)->toArray());
        $path = $this->fileOf($line . "\n");

        $length = strlen($line);

        unset($line);

        [$lines, $growth] = self::readingOf(new SpillReader, $path);

        self::assertCount(1, $lines);
        self::assertSame($length - strlen(FailureSpill::MARKER), strlen((string) $lines[0]->json));
        self::assertLessThanOrEqual(self::MAX_LINE_COPIES * $length + self::READER_OVERHEAD, $growth, sprintf('Reading a line of %d bytes grew the peak by %d.', $length, $growth));
    }

    /**
     * Each line is read for its own length: many short lines cost what one
     * does.
     *
     * @return void
     */
    public function testManyShortLinesCostWhatOneDoes(): void
    {
        $line  = FailureSpill::line($this->finalisedOf(0)->toArray());
        $count = (int) ceil(self::LARGE_BYTES / strlen($line));

        $path = $this->fileOf(str_repeat($line . "\n", $count));

        $reader  = new SpillReader;
        $lengths = 0;

        memory_reset_peak_usage();

        $before = memory_get_usage();

        foreach ($reader->lines($path) as $read) {
            $lengths += strlen((string) $read->json);
        }

        $growth = memory_get_peak_usage() - $before;

        self::assertSame($count * (strlen($line) - strlen(FailureSpill::MARKER)), $lengths);
        self::assertLessThanOrEqual(self::MAX_LINE_COPIES * strlen($line) + self::READER_OVERHEAD, $growth);
    }

    /**
     * A line past the bound holds only the bound, is counted as truncated, and
     * the next line is read.
     *
     * @return void
     */
    public function testALinePastTheBoundHoldsOnlyTheBound(): void
    {
        $path = $this->fileOf(FailureSpill::MARKER . '{"a":"' . str_repeat('x', self::LARGE_BYTES) . "\"}\n" . FailureSpill::MARKER . "{}\n");

        [$lines, $growth] = self::readingOf(new SpillReader(self::SMALL_BYTES), $path);

        self::assertCount(2, $lines);
        self::assertSame(EnvelopeFailure::TRUNCATED, $lines[0]->failure);
        self::assertSame('{}', $lines[1]->json);
        self::assertLessThanOrEqual(self::MAX_LINE_COPIES * self::SMALL_BYTES + self::READER_OVERHEAD, $growth);
    }

    /**
     * A line past the bound with no marker costs the bound too, and is ignored.
     *
     * @return void
     */
    public function testALinePastTheBoundWithNoMarkerHoldsOnlyTheBound(): void
    {
        [$lines, $growth] = self::readingOf(new SpillReader(self::SMALL_BYTES), $this->fileOf(str_repeat('x', self::LARGE_BYTES) . "\n"));

        self::assertSame([], $lines);
        self::assertLessThanOrEqual(self::MAX_LINE_COPIES * self::SMALL_BYTES + self::READER_OVERHEAD, $growth);
    }

    /**
     * Reading a 10 MiB line takes CPU time in line with a 1 MiB one, whatever
     * its chunks.
     *
     * @return void
     */
    public function testReadingALineIsLinearInTheLine(): void
    {
        if (self::isCollectingCoverage()) {
            self::markTestSkipped('Xdebug slows every line by an order of magnitude, so this would be measuring Xdebug.');
        }

        $reader = new SpillReader;
        $small  = $this->fileOf(FailureSpill::line($this->finalisedOf(self::SMALL_BYTES)->toArray()) . "\n");
        $large  = $this->fileOf(FailureSpill::line($this->finalisedOf(self::LARGE_BYTES)->toArray()) . "\n");

        self::assertLessThanOrEqual(
            self::MAX_WORK_RATIO * self::leastCpu(static fn () => iterator_to_array($reader->lines($small), false)),
            self::leastCpu(static fn () => iterator_to_array($reader->lines($large), false)),
            'The work of reading a long line is not in line with a short one.',
        );
    }

    /**
     * A finalised record of many short keys with long values holding the bytes
     * given, with a `%`, a line break and non-ASCII to escape. It is built
     * around the capture, which would cut it to its budget.
     *
     * @param  int  $bytes
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalisedOf(int $bytes): FinalisedRecord
    {
        $value      = str_pad("100% of\nthe café ", self::FIELD_BYTES, 'x');
        $properties = [];

        for ($index = 0; $index < intdiv($bytes, self::FIELD_BYTES); $index++) {
            $properties[sprintf('field_%06d', $index)] = $value;
        }

        return app(RecordFinaliser::class)->finalise(RecordFactory::withFields(['properties' => $properties === [] ? null : $properties]));
    }

    /**
     * Write the contents to a file of its own, removed with the test.
     *
     * @param  string  $contents
     * @return string
     */
    private function fileOf(string $contents): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'audit-load-');

        $this->files[] = $path;

        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * How much formatting the record grows the peak by, in bytes; the peak is
     * reset first, since it never otherwise falls.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditFormatter  $formatter
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return int
     */
    private static function peakGrowthOf(AuditFormatter $formatter, FinalisedRecord $record): int
    {
        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        $formatter->format($record);

        return memory_get_peak_usage() - $before;
    }

    /**
     * What the reader takes from the file, each line held in turn, and how much
     * reading it grows the peak by, in bytes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\SpillReader  $reader
     * @param  string  $path
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Delivery\SpillLine>, 1: int}
     */
    private static function readingOf(SpillReader $reader, string $path): array
    {
        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        /** @var list<\SineMacula\Laravel\AuditLog\Delivery\SpillLine> $lines */
        $lines = iterator_to_array($reader->lines($path), false);

        return [$lines, memory_get_peak_usage() - $before];
    }

    /**
     * The least CPU time the work takes over a few runs, in nanoseconds.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function leastCpu(\Closure $work): int
    {
        $least = PHP_INT_MAX;

        for ($round = 0; $round < self::ROUNDS; $round++) {
            $started = self::cpuNanoseconds();

            $work();

            $least = min($least, self::cpuNanoseconds() - $started);
        }

        return $least;
    }
}
