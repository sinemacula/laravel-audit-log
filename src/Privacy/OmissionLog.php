<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * What one capture removed from a record: a count, and the first 32
 * already-masked paths in sorted order so the list is order-independent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OmissionLog
{
    /** @var int Most paths the log gives. */
    public const int MAX_PATHS = 32;

    /** @var int Longest path kept, in bytes once encoded, without its quotes. */
    public const int MAX_PATH_BYTES = 128;

    /** @var string What a longer path is remembered as. */
    private const string TOO_LONG = '*';

    /** @var int How many bytes of a path's encoding are its quotes. */
    private const int QUOTE_BYTES = 2;

    /** @var int How many branches were removed. */
    private int $count = 0;

    /** @var array<array-key, string> The paths as a set, each its own value since PHP makes a numeric key an integer. */
    private array $paths = [];

    /**
     * Count one removed branch and remember its masked path.
     *
     * @param  string  $maskedPath
     * @return void
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public function add(string $maskedPath): void
    {
        $encoded = json_encode($maskedPath, CanonicalEncoder::JSON_FLAGS);
        $path    = strlen($encoded) - self::QUOTE_BYTES > self::MAX_PATH_BYTES ? self::TOO_LONG : $maskedPath;

        $this->paths[$path] = $path;

        $this->addCount(1);
    }

    /**
     * Count removed branches with no path to remember; the count saturates so
     * it never overflows into a float.
     *
     * @param  int  $branches
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function addCount(int $branches): void
    {
        if ($branches < 0) {
            throw new \InvalidArgumentException('An omission count cannot be negative.');
        }

        $this->count += min($branches, PHP_INT_MAX - $this->count);
    }

    /**
     * What was removed, as a count and the first 32 paths sorted bytewise;
     * `null` when nothing was.
     *
     * @return ?array{count: int, paths: list<string>}
     */
    public function toArray(): ?array
    {
        if ($this->count === 0) {
            return null;
        }

        $paths = $this->paths;

        usort($paths, strcmp(...));

        return ['count' => $this->count, 'paths' => array_slice($paths, 0, self::MAX_PATHS)];
    }
}
