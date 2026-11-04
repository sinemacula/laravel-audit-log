<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportFile;
use Tests\TestCase;

/**
 * Feature tests for reading an import file: its streamed SHA-256, its lines by
 * their numbers in the file, blank lines skipped, an over-long line rejected
 * without being held, a line across the reads' blocks read whole, and the
 * digest of what the lines' read read, known once it has ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportFile::class)]
final class ImportFileTest extends TestCase
{
    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Remove the files this test wrote.
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
     * The digest is the SHA-256 of the file's bytes, as lower-case hex, read
     * whole whatever its size.
     *
     * @return void
     */
    public function testTheDigestIsTheFilesSha256(): void
    {
        $content = str_repeat("{\"line\":\"x\"}\n", 200000);
        $path    = $this->file($content);

        self::assertGreaterThan(ImportFile::READ_BYTES, strlen($content));
        self::assertSame(hash('sha256', $content), (new ImportFile($path))->sha256());
        self::assertSame(hash('sha256', ''), (new ImportFile($this->file('')))->sha256());
    }

    /**
     * A line longer than the limit is rejected by its number, and what is read
     * of it is never held whole: reading a line of 16 MiB under a limit of 1
     * KiB costs far less memory than the line, and the lines either side of it
     * are read as they are.
     *
     * @return void
     */
    public function testAnOverlongLineIsRejectedWithoutBuffering(): void
    {
        $long = 16 * 1048576;
        $path = $this->file("first\n");

        $handle = fopen($path, 'ab');

        assert($handle !== false);

        for ($written = 0; $written < $long; $written += ImportFile::READ_BYTES) {
            fwrite($handle, str_repeat('x', ImportFile::READ_BYTES));
        }

        fwrite($handle, "\nlast\n");
        fclose($handle);

        memory_reset_peak_usage();

        $baseline = memory_get_peak_usage();
        $lines    = iterator_to_array((new ImportFile($path))->lines(1024));
        $grown    = memory_get_peak_usage() - $baseline;

        self::assertSame([1 => 'first', 2 => ImportRejection::OVERSIZED_LINE, 3 => 'last'], $lines);
        self::assertLessThan(intdiv($long, 4), $grown, 'The over-long line was held whole.');
    }

    /**
     * A line of exactly the limit is read, one byte more is rejected, and a
     * carriage return before the line feed is neither kept nor counted.
     *
     * @return void
     */
    public function testTheLimitIsTheLinesBytesWithoutItsLineEnd(): void
    {
        $exact = str_repeat('a', 1024);
        $over  = str_repeat('b', 1025);
        $path  = $this->file($exact . "\r\n" . $over . "\n" . $exact . "\n" . $over . "\r\n");

        $lines = iterator_to_array((new ImportFile($path))->lines(1024));

        self::assertSame([1 => $exact, 2 => ImportRejection::OVERSIZED_LINE, 3 => $exact, 4 => ImportRejection::OVERSIZED_LINE], $lines);
    }

    /**
     * Blank lines, empty or of spaces and tabs only, are skipped, and the lines
     * around them keep their numbers in the file; a last line without a line
     * feed is read.
     *
     * @return void
     */
    public function testBlankLinesAreSkipped(): void
    {
        $path = $this->file("\none\n\n \t \r\ntwo\r\n\nthree");

        self::assertSame([2 => 'one', 5 => 'two', 7 => 'three'], iterator_to_array((new ImportFile($path))->lines(1024)));
        self::assertSame([], iterator_to_array((new ImportFile($this->file("\n\n")))->lines(1024)));
    }

    /**
     * A line that crosses the boundary between two reads is read whole.
     *
     * @return void
     */
    public function testALineAcrossTwoReadsIsReadWhole(): void
    {
        $first  = str_repeat('a', ImportFile::READ_BYTES - 3);
        $second = 'bcdefgh';
        $path   = $this->file($first . "\n" . $second . "\n");

        self::assertSame([1 => $first, 2 => $second], iterator_to_array((new ImportFile($path))->lines(ImportFile::READ_BYTES)));

        $across = str_repeat('c', ImportFile::READ_BYTES + 10);

        self::assertSame([1 => $across], iterator_to_array((new ImportFile($this->file($across)))->lines(ImportFile::READ_BYTES * 2)));
    }

    /**
     * The read digest is the SHA-256 of what the lines' read read, blank and
     * over-long lines included: the file's own digest when it did not change,
     * and the changed bytes' when it did.
     *
     * @return void
     */
    public function testTheReadDigestFollowsWhatWasRead(): void
    {
        $content = "one\n\n" . str_repeat('x', 2048) . "\ntwo\n";
        $path    = $this->file($content);
        $file    = new ImportFile($path);
        $first   = $file->sha256();

        iterator_to_array($file->lines(1024));

        self::assertSame($first, $file->readDigest());

        file_put_contents($path, "one\nTWO\n");

        iterator_to_array($file->lines(1024));

        self::assertSame(hash('sha256', "one\nTWO\n"), $file->readDigest());
        self::assertNotSame($first, $file->readDigest());
    }

    /**
     * The read digest is unknown before the lines are read, and while a read of
     * them has not ended, even once it has begun.
     *
     * @return void
     */
    public function testTheReadDigestIsUnknownUntilTheLinesAreRead(): void
    {
        $file = new ImportFile($this->file("one\ntwo\n"));

        foreach ($file->lines(1024) as $text) {
            self::assertSame('one', $text);

            break;
        }

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An import file\'s read digest is known only once its lines have all been read.');

        $file->readDigest();
    }

    /**
     * A limit of no bytes is refused.
     *
     * @return void
     */
    public function testALimitOfNoBytesIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The longest line an import reads must be at least 1 byte.');

        iterator_to_array((new ImportFile($this->file("one\n")))->lines(0));
    }

    /**
     * A file that cannot be opened is refused, naming the path.
     *
     * @return void
     */
    public function testAFileThatCannotBeOpenedIsRefused(): void
    {
        $path = $this->file('') . '.missing';

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('The import file `%s` could not be opened for reading.', $path));

        (new ImportFile($path))->sha256();
    }

    /**
     * Write a file of the content given, and return its path.
     *
     * @param  string  $content
     * @return string
     */
    private function file(string $content): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'import-file-');

        file_put_contents($path, $content);

        $this->files[] = $path;

        return $path;
    }
}
