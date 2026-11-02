<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;

/**
 * Reported, never thrown, when a field encrypter throws or returns something
 * other than an envelope: the value is dropped and diagnosed, and the record is
 * still written.
 *
 * It names only the encrypter's class. It can hold no previous exception,
 * because the constructor takes none and only `for()` can call it: what the
 * encrypter threw could hold the plaintext in its message. An application names
 * this class to filter, route or alert on the report.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FieldEncryptionFailedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     */
    private function __construct(string $message)
    {
        parent::__construct($message);
    }

    /**
     * The exception for an encrypter that failed. `get_debug_type()` names an
     * anonymous class by what it implements, never by the file it is in. The
     * encrypter is marked sensitive so this frame of the trace does not carry
     * an object that may hold key material.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return self
     */
    public static function for(#[\SensitiveParameter] FieldEncrypter $encrypter): self
    {
        return new self(sprintf('The field encrypter %s failed, so the value was dropped.', get_debug_type($encrypter)));
    }
}
