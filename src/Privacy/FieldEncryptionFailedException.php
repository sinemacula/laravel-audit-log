<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;

/**
 * Reported, never thrown, when a field encrypter fails; it names only the
 * encrypter's class and chains nothing, as the cause could hold the plaintext.
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
     * The exception for a failed encrypter, marked sensitive since it may hold
     * key material; `get_debug_type()` never names a file.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return self
     */
    public static function for(#[\SensitiveParameter] FieldEncrypter $encrypter): self
    {
        return new self(sprintf('The field encrypter %s failed, so the value was dropped.', get_debug_type($encrypter)));
    }
}
