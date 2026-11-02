<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The field encrypter the package binds by default: it holds no key for any
 * owner, so every encrypted field, owned note and encrypted address is dropped
 * and diagnosed rather than stored in plaintext.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NoFieldEncrypter implements FieldEncrypter
{
    /**
     * No envelope, because no owner has a key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @return null
     */
    #[\Override]
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext): null
    {
        return null;
    }
}
