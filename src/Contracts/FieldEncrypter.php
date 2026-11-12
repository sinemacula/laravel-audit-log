<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Field encrypter contract: seals a value under its owner's key, so destroying
 * the owner's keys erases the value.
 *
 * A fresh encrypter serves each record; it may keep the current entry's keys
 * and drops them on another entry. It should mark its plaintext parameter
 * `#[\SensitiveParameter]`, which this contract cannot pass on.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldEncrypter
{
    /**
     * The plaintext sealed as an envelope of `v`, the version from 1, `k`, the
     * key id and never the key, and `c`, the ciphertext, both strings non-empty
     * clean text; `null` when the owner has no key.
     *
     * The plaintext is the value's canonical JSON, at most 1024 bytes, and the
     * envelope must be bound to the context's entry, path and log. A thrown
     * exception is discarded unreported, since its message could hold the
     * plaintext.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return ?array{v: int, k: string, c: string}
     *
     * @throws \Throwable
     */
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): ?array;
}
