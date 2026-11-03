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
 * Load contract for what handles a whole record at once: a formatter's work and
 * memory grow in line with the record, and a spill file is read in memory that
 * follows each line's own length, never the longest a line may be.
 *
 * Nothing here is held to an absolute limit: each large measurement is compared
 * with a small one taken in this process, so a slow machine slows both. A
 * formatter that does not walk the record takes next to no time to measure, so
 * the small side is never less than what hashing a quarter of the small
 * record's bytes takes, and never less than the small record's bytes in memory.
 * A ratio far below quadratic growth and well above linear growth catches a
 * pass that is not linear, and not a noisy neighbour. CPU time is not asserted
 * while Xdebug collects coverage, which slows every line by an order of
 * magnitude, so it would be measuring Xdebug.
 *
 * The peak is reset before each measurement, because within a process it never
 * otherwise falls, and the memory limit is raised for the test, because it is
 * often no more than these records need, and the assertion should be what fails
 * rather than the engine's limit.
 *
 * It claims no coverage because its records are among the slowest things in the
 * suite: a mutant whose covering tests included them would be skipped as taking
 * too long rather than run, so the classes they pass through would go without a
 * mutation check. Their behaviour is pinned by their own tests.
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

    /** @var int How many bytes each property holds, its key apart, so the record has many keys and long values. */
    private const int FIELD_BYTES = 1024;

    /** @var int How much more work the large record may cost than the small: linear growth is ten times, and quadratic a hundred. */
    private const int MAX_WORK_RATIO = 35;

    /** @var int How much more memory the large record may take than the small: linear growth is ten times, and quadratic a hundred. */
    private const int MAX_MEMORY_RATIO = 20;

    /** @var int How many runs each CPU measurement takes the least of, since a run can only be slowed by what else is happening. */
    private const int ROUNDS = 5;

    /** @var int How many lines' worth of bytes a read may hold at once: the line being grown, the next chunk's copy of it, and the object taken out of it. */
    private const int MAX_LINE_COPIES = 4;

    /** @var int What reading any line holds beyond the line itself, in bytes: a chunk and the reader's own objects, for a line of any length. */
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
     * Remove the files the test wrote, and restore the memory limit, as far as
     * what the process still holds allows: the pages a record scattered may not
     * all go back at once, and a limit below them is refused with a warning. An
     * unlimited process stays so.
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
     * Rows of `[formatter class, whether its line holds the properties]`: each
     * formatter the package ships.
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
     * Formatting a 10 MiB record takes CPU time and memory in line with
     * formatting a 1 MiB one, and the line it gives holds the whole record, so
     * what was measured is the walk of it, for each formatter whose line holds
     * the properties.
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
     * Reading a spill line grows the peak by a few copies of that line and no
     * more, a short line by next to nothing, however long a line may be, so a
     * file of short lines never claims the bound of each.
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
     * Each line of a file is read for its own length: many short lines cost
     * what one does, since each is let go before the next, and the peak never
     * reaches the file's size.
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
     * A line past the bound holds the bound and no more: its remainder is
     * skipped without being kept, the line is counted as truncated, and the
     * line after it is read.
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
     * Reading a 10 MiB line takes CPU time in line with reading a 1 MiB one,
     * measured in this process, whatever the chunks it is read in.
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
     * A finalised record whose properties hold the bytes given, as many short
     * keys with long values, holding what a formatter has to escape: a `%`, a
     * line break and a character beyond ASCII. It is built around the capture,
     * since capture would cut it to its budget, and is signed once.
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
     * How much formatting the record grows the peak by, in bytes.
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

    /**
     * The CPU time this process has used, user and system together: waiting for
     * a core on a busy machine or runner uses none of it.
     *
     * @return int
     */
    private static function cpuNanoseconds(): int
    {
        $usage = getrusage();

        assert(is_array($usage));

        return ($usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec'])  * 1000000000
            + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) * 1000;
    }

    /**
     * Whether Xdebug is collecting coverage in this process.
     *
     * @return bool
     */
    private static function isCollectingCoverage(): bool
    {
        return function_exists('xdebug_info') && in_array('coverage', xdebug_info('mode'), true);
    }
}
