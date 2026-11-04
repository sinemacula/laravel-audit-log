<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

/**
 * Thrown when the storage and the maintenance connections do not reach one
 * installation: the maintenance connection reads no installation id, or reads
 * another than the storage connection does. A lifecycle operation is refused
 * before it takes its lock, because its deletions and journal rows would land
 * in another database than the entries and seals they describe. The message
 * names no id and no connection setting's value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InstallationMismatchException extends \RuntimeException
{
    /**
     * The maintenance connection reads no installation id, so it does not reach
     * the database the storage connection wrote one to.
     *
     * @return self
     */
    public static function absent(): self
    {
        return new self('The maintenance connection reaches no installation id; it must reach the storage connection\'s database.');
    }

    /**
     * The two connections read different installation ids, so they reach
     * different databases.
     *
     * @return self
     */
    public static function mismatched(): self
    {
        return new self('The storage and maintenance connections reach different installations.');
    }
}
