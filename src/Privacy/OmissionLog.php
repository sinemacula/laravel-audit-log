<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * What one capture removed from a record: how many branches, and the masked
 * paths of the first 32 in sorted order, so the list stays small enough to fit
 * the byte budget and does not depend on the order paths were added.
 *
 * It holds masked paths only, never a value. It trusts what it is given to be
 * masked already, and bounds only its length: a path of more than 128 bytes
 * once encoded is remembered as `*`.
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

    /** @var array<array-key, string> The paths, as a set, each its own value: PHP makes a numeric key an integer, and the value stays a string. */
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
     * Count removed branches that have no path to remember, such as the
     * collisions past those carried. The count stops at the largest integer, so
     * a diagnostic can never overflow into a float and fail the write.
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
     * What was removed, as a count and the first 32 paths sorted bytewise, each
     * a string; `null` when nothing was.
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
