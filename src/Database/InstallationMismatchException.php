<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

/**
 * Thrown when the maintenance connection does not reach the storage
 * connection's installation; the message names no id or connection setting.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InstallationMismatchException extends \RuntimeException
{
    /**
     * The maintenance connection reads no installation id.
     *
     * @return self
     */
    public static function absent(): self
    {
        return new self('The maintenance connection reaches no installation id; it must reach the storage connection\'s database.');
    }

    /**
     * The two connections read different installation ids.
     *
     * @return self
     */
    public static function mismatched(): self
    {
        return new self('The storage and maintenance connections reach different installations.');
    }
}
