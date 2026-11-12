<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

/**
 * The envelope version a record is stored in, and the versions this release
 * reads; old rows are never rewritten and a newer version never guessed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordVersion
{
    /** @var int The envelope version every captured record carries. */
    public const int CURRENT = 1;

    /** @var list<int> Envelope versions this release reads. */
    public const array SUPPORTED = [1];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The version a stored record was read back with, when this release reads
     * it.
     *
     * @param  int  $version
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    public static function check(int $version): int
    {
        if (!in_array($version, self::SUPPORTED, true)) {
            throw new \UnexpectedValueException(sprintf('Record version %d is not supported by this release.', $version));
        }

        return $version;
    }
}
