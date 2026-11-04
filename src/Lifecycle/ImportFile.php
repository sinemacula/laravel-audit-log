<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;

/**
 * An import file read as an import reads it: its SHA-256 first, streamed, and
 * then its lines, hashing again as they are read, so a file that changed
 * between the two reads is told by its two digests.
 *
 * Both reads take the file a mebibyte at a time. A line is yielded by its line
 * number in the file, from 1, without its line feed or a carriage return before
 * it; a blank line, empty or of spaces and tabs only, is skipped and never
 * yielded. A line longer than the most bytes given is yielded as
 * `OVERSIZED_LINE` and never held whole: what is read of it past the limit is
 * dropped as it is read, so a line of any length costs no more memory than the
 * limit and one read. The read digest covers every byte read, the skipped and
 * the oversized lines included, and is known only once the lines have all been
 * read.
 *
 * It holds the read digest once the lines are read, so it is made for one
 * import.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ImportFile
{
    /** @var int Bytes taken by one read: a mebibyte. */
    public const int READ_BYTES = 1048576;

    /** @var ?string The SHA-256 of what the lines' read read, once it has ended. */
    private ?string $readDigest = null;

    /**
     * Constructor.
     *
     * @param  string  $path
     */
    public function __construct(

        /** The file read. */
        private readonly string $path,
    ) {}

    /**
     * The file's SHA-256, as lower-case hex, read a mebibyte at a time.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function sha256(): string
    {
        $hash = hash_init('sha256');

        foreach ($this->blocks() as $block) {
            hash_update($hash, $block);
        }

        return hash_final($hash);
    }

    /**
     * The file's lines, each by its line number: its text, or `OVERSIZED_LINE`
     * for one longer than the most bytes given; blank lines are skipped. Once
     * the generator has ended, `readDigest()` is the SHA-256 of what it read.
     *
     * @param  int  $maxBytes
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|string>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function lines(int $maxBytes): \Generator
    {
        self::checkMaxBytes($maxBytes);

        $this->readDigest = null;

        $hash  = hash_init('sha256');
        $state = ['number' => 1, 'buffer' => '', 'oversized' => false];

        foreach ($this->blocks() as $block) {
            hash_update($hash, $block);

            yield from self::linesIn($block, $state, $maxBytes);
        }

        yield from self::emit($state['number'], $state['buffer'], $state['oversized'], $maxBytes);

        $this->readDigest = hash_final($hash);
    }

    /**
     * The SHA-256 of what the lines' read read, as lower-case hex: known only
     * once that read has ended.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function readDigest(): string
    {
        return $this->readDigest ?? throw new \LogicException('An import file\'s read digest is known only once its lines have all been read.');
    }

    /**
     * The file's bytes, a mebibyte at a time, the last block shorter; the file
     * is closed once they are read, or once the reader stops.
     *
     * @return \Generator<int, string>
     *
     * @throws \UnexpectedValueException
     */
    private function blocks(): \Generator
    {
        $handle = @fopen($this->path, 'rb');

        if ($handle === false) {
            throw new \UnexpectedValueException(sprintf('The import file `%s` could not be opened for reading.', $this->path));
        }

        try {
            while (!feof($handle)) {
                $block = fread($handle, self::READ_BYTES);

                if ($block === false) {
                    throw new \UnexpectedValueException(sprintf('The import file `%s` could not be read.', $this->path));
                }

                yield $block;
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * The lines the block ends, each by its line number, carrying the line it
     * leaves unfinished, its number and whether it is oversized, in the state
     * given, to the next block.
     *
     * @param  string  $block
     * @param  array{number: int, buffer: string, oversized: bool}  $state
     * @param  int  $maxBytes
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|string>
     */
    private static function linesIn(#[\SensitiveParameter] string $block, #[\SensitiveParameter] array &$state, int $maxBytes): \Generator
    {
        foreach (self::split($block) as [$piece, $ends]) {
            [$state['buffer'], $state['oversized']] = self::append($state['buffer'], $state['oversized'], $piece, $maxBytes);

            if (!$ends) {
                continue;
            }

            yield from self::emit($state['number'], $state['buffer'], $state['oversized'], $maxBytes);

            $state = ['number' => $state['number'] + 1, 'buffer' => '', 'oversized' => false];
        }
    }

    /**
     * Refuse a longest line of no bytes.
     *
     * @param  int  $maxBytes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkMaxBytes(int $maxBytes): void
    {
        if ($maxBytes >= 1) {
            return;
        }

        throw new \InvalidArgumentException('The longest line an import reads must be at least 1 byte.');
    }

    /**
     * The block's pieces between its line feeds, each with whether a line feed
     * ends it: every piece but the last does.
     *
     * @param  string  $block
     * @return list<array{0: string, 1: bool}>
     */
    private static function split(#[\SensitiveParameter] string $block): array
    {
        $pieces = explode("\n", $block);
        $last   = count($pieces) - 1;

        return array_map(static fn (string $piece, int $index): array => [$piece, $index < $last], $pieces, array_keys($pieces));
    }

    /**
     * The line so far with the piece added, unless that makes it longer than
     * the most bytes given and a carriage return: it is then oversized, and
     * nothing more of it is held.
     *
     * @param  string  $buffer
     * @param  bool  $oversized
     * @param  string  $piece
     * @param  int  $maxBytes
     * @return array{0: string, 1: bool}
     */
    private static function append(#[\SensitiveParameter] string $buffer, bool $oversized, #[\SensitiveParameter] string $piece, int $maxBytes): array
    {
        if ($oversized || strlen($buffer) + strlen($piece) > $maxBytes + 1) {
            return ['', true];
        }

        return [$buffer . $piece, false];
    }

    /**
     * The line, by its number: its text without a carriage return before its
     * line feed, `OVERSIZED_LINE` for one longer than the most bytes given once
     * that carriage return is set aside, or nothing for a blank one.
     *
     * @param  int  $number
     * @param  string  $buffer
     * @param  bool  $oversized
     * @param  int  $maxBytes
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|string>
     */
    private static function emit(int $number, #[\SensitiveParameter] string $buffer, bool $oversized, int $maxBytes): \Generator
    {
        if (str_ends_with($buffer, "\r")) {
            $buffer = substr($buffer, 0, -1);
        }

        if ($oversized || strlen($buffer) > $maxBytes) {
            yield $number => ImportRejection::OVERSIZED_LINE;

            return;
        }

        if (trim($buffer, " \t") === '') {
            return;
        }

        yield $number => $buffer;
    }
}
