<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;

/**
 * Reads a spill file line by line, and takes from each line that holds the
 * spill marker the one JSON object after it, whatever a channel's format put
 * around it.
 *
 * A line is read in chunks, so memory follows each line's own length, up to the
 * bound: PHP allocates the whole length given to `fgets()` before it reads, so
 * asking for the bound at once would claim about 200 MB for every line, a short
 * one included. A line that reaches the bound without a newline is truncated
 * when the bytes held hold the marker and ignored otherwise, and its remainder
 * is skipped without being kept.
 *
 * A line without the marker is ignored and not counted, since a shared channel
 * holds other lines, but every line has its number. The reader never parses and
 * never repairs: an object left unclosed is truncated, and what the object
 * holds is the codec's to judge.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpillReader
{
    /** @var int Bytes read at a time, and what a channel's format may add to a line beyond its envelope. */
    public const int FRAMING_BYTES = 4096;

    /**
     * Constructor.
     *
     * @param  int  $maxEncodedBytes
     */
    public function __construct(

        /** The longest envelope a line may hold as it is encoded there, in bytes. */
        private int $maxEncodedBytes = EnvelopeCodec::MAX_ENCODED_BYTES,
    ) {}

    /**
     * The file's lines that hold the marker, in order, with what the reader
     * took from each; refused at once when the path cannot be read. The file
     * closes with the last reference to the reading, so however it ends.
     *
     * @param  string  $path
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Delivery\SpillLine, void, void>
     *
     * @throws \InvalidArgumentException
     */
    public function lines(string $path): \Generator
    {
        $handle = is_file($path) && is_readable($path) ? fopen($path, 'rb') : false;

        if ($handle === false) {
            throw new \InvalidArgumentException(sprintf('The spill file [%s] cannot be read.', $path));
        }

        return $this->read(static fn (): false|string => fgets($handle, self::FRAMING_BYTES));
    }

    /**
     * The one JSON object after the first marker in the line, ignoring whatever
     * follows it: `null` when there is no marker, when what follows the marker
     * does not start `{`, and when the object is never closed. Strings, escapes
     * and depth are tracked and nothing is parsed.
     *
     * @param  string  $line
     * @return ?string
     */
    public static function extract(#[\SensitiveParameter] string $line): ?string
    {
        $start = self::afterMarker($line);

        if ($start === null || substr($line, $start, 1) !== '{') {
            return null;
        }

        $end = self::closingBrace($line, $start);

        return $end === null ? null : substr($line, $start, $end - $start + 1);
    }

    /**
     * Read the chunks to their end, yielding each line that holds the marker.
     *
     * @param  \Closure(): (false|string)  $next
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Delivery\SpillLine, void, void>
     */
    private function read(#[\SensitiveParameter] \Closure $next): \Generator
    {
        $number = 0;

        while (($chunk = $next()) !== false) {

            $number++;

            $line = $this->lineFrom($next, $chunk, $number);

            if ($line === null) {
                continue;
            }

            yield $line;
        }
    }

    /**
     * What the reader takes from the line the chunk starts: `null` when the
     * line holds no marker.
     *
     * @param  \Closure(): (false|string)  $next
     * @param  string  $chunk
     * @param  int  $number
     * @return ?\SineMacula\Laravel\AuditLog\Delivery\SpillLine
     */
    private function lineFrom(#[\SensitiveParameter] \Closure $next, #[\SensitiveParameter] string $chunk, int $number): ?SpillLine
    {
        $line  = $this->held($next, $chunk);
        $start = self::afterMarker($line);

        if (!str_ends_with($line, "\n") && strlen($line) >= $this->maxEncodedBytes + self::FRAMING_BYTES) {
            self::skipRemainder($next);

            return $start === null ? null : new SpillLine($number, null, EnvelopeFailure::TRUNCATED);
        }

        if ($start === null) {
            return null;
        }

        $json = self::extract($line);

        return $json === null ? new SpillLine($number, null, self::failureOf($line, $start)) : new SpillLine($number, $json, null);
    }

    /**
     * The line the chunk starts, read a chunk at a time until a newline, the
     * end of the file or the bound.
     *
     * @param  \Closure(): (false|string)  $next
     * @param  string  $chunk
     * @return string
     */
    private function held(#[\SensitiveParameter] \Closure $next, #[\SensitiveParameter] string $chunk): string
    {
        $bound = $this->maxEncodedBytes + self::FRAMING_BYTES;
        $line  = $chunk;

        while (!str_ends_with($line, "\n") && strlen($line) < $bound) {

            $more = $next();

            if ($more === false) {
                break;
            }

            $line .= $more;
        }

        return $line;
    }

    /**
     * Skip the rest of a line past the bound, a chunk at a time, keeping none
     * of it.
     *
     * @param  \Closure(): (false|string)  $next
     * @return void
     */
    private static function skipRemainder(#[\SensitiveParameter] \Closure $next): void
    {
        while (($chunk = $next()) !== false) {
            if (str_ends_with($chunk, "\n")) {
                return;
            }
        }
    }

    /**
     * Why no object could be taken after the marker: malformed when something
     * other than an object follows it, and truncated when an object is left
     * unclosed or the line ends at the marker.
     *
     * @param  string  $line
     * @param  int  $start
     * @return \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure
     */
    private static function failureOf(#[\SensitiveParameter] string $line, int $start): EnvelopeFailure
    {
        return in_array(substr($line, $start, 1), ['{', "\n", "\r", ''], true) ? EnvelopeFailure::TRUNCATED : EnvelopeFailure::MALFORMED;
    }

    /**
     * The offset just past the first marker in the line, or `null` when it has
     * none.
     *
     * @param  string  $line
     * @return ?int
     */
    private static function afterMarker(#[\SensitiveParameter] string $line): ?int
    {
        $marker = strpos($line, FailureSpill::MARKER);

        return $marker === false ? null : $marker + strlen(FailureSpill::MARKER);
    }

    /**
     * The offset of the brace that closes the object opening at the offset
     * given, hopping over everything that is not structure, or `null` when it
     * is never closed.
     *
     * @param  string  $line
     * @param  int  $offset
     * @return ?int
     */
    private static function closingBrace(#[\SensitiveParameter] string $line, int $offset): ?int
    {
        $depth  = 0;
        $length = strlen($line);

        while ($offset < $length) {

            $offset += strcspn($line, '{}"', $offset);
            $byte = $line[$offset]                 ?? '';
            $depth += ['{' => 1, '}' => -1][$byte] ?? 0;

            if ($byte === '}' && $depth === 0) {
                return $offset;
            }

            $offset = ($byte === '"' ? self::closingQuote($line, $offset + 1) ?? $length : $offset) + 1;
        }

        return null;
    }

    /**
     * The offset of the quote that closes the string whose content starts at
     * the offset given, stepping over each escape, or `null` when it is never
     * closed.
     *
     * @param  string  $line
     * @param  int  $offset
     * @return ?int
     */
    private static function closingQuote(#[\SensitiveParameter] string $line, int $offset): ?int
    {
        $length = strlen($line);

        while ($offset < $length) {

            $offset += strcspn($line, '"\\', $offset);

            if ($offset < $length && $line[$offset] === '"') {
                return $offset;
            }

            $offset += 2;
        }

        return null;
    }
}
