<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;

/**
 * An import file read twice, hashed each time, so a file that changed between
 * the reads is caught; made for one import.
 *
 * An oversized line is never held whole, so memory stays bounded by the limit.
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

    /** @var ?string The SHA-256 of the lines' read, once it has ended. */
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
     * The file's lower-case hex SHA-256.
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
     * The non-blank lines by line number, `OVERSIZED_LINE` past the limit;
     * `readDigest()` is known once the generator ends.
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
     * The lower-case hex SHA-256 of the lines' read, once it has ended.
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
     * The file's bytes a mebibyte at a time, closing it once the reader stops.
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
     * The lines the block ends, carrying its unfinished line to the next block
     * in `$state`.
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
     * The block's pieces between line feeds, each with whether one ends it.
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
     * The line so far with the piece added, or oversized and emptied once it
     * passes the limit plus a carriage return.
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
     * The line without a trailing carriage return, `OVERSIZED_LINE` past the
     * limit, or nothing when blank.
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
