<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Field encrypter contract: the seam that seals a value under the key of the
 * person or thing that owns it, for the fields a definition encrypts, the notes
 * that have an owner and the addresses the `encrypt` IP mode stores.
 *
 * The package binds `Privacy\NoFieldEncrypter`, which holds no key for anyone,
 * so until an application or an adapter rebinds the contract every encrypted
 * value is dropped and diagnosed, and never stored in plaintext. An
 * implementation must keep no state between calls, and should mark its own
 * plaintext parameter `#[\SensitiveParameter]`, since an attribute on this
 * contract does not reach it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldEncrypter
{
    /**
     * The plaintext sealed under the owner's key, as an envelope of exactly
     * three parts: `v`, the envelope's version, from 1; `k`, the id of the key,
     * never the key itself; and `c`, the ciphertext. Both strings must be
     * non-empty clean text, as they are stored and signed as given. `null`
     * means the owner has no key.
     *
     * Anything else returned is a failure, and so is anything thrown. The value
     * is dropped and diagnosed, the failure is reported naming only this class,
     * and a thrown exception is discarded and never reported, because its
     * message could hold the plaintext. After a failure the package asks for no
     * more envelopes for that record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @return ?array{v: int, k: string, c: string}
     *
     * @throws \Throwable
     */
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext): ?array;
}
