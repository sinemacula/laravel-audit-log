<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The field encrypter that never encrypts, so every encrypted field is dropped,
 * never stored in plaintext; earlier keys can still be erased.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoFieldEncrypter implements FieldEncrypter
{
    /**
     * No envelope, because no owner has a key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return null
     */
    #[\Override]
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): null
    {
        return null;
    }
}
