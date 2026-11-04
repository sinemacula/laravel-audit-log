<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;

/**
 * Field reader contract: the seam that reads an encrypted fragment of an entry
 * when the entry is shown, whether a property holding an encryption envelope,
 * an owned note or an IP address stored under the `encrypt` mode.
 *
 * The package binds `Privacy\SealedFieldReader`, which reads nothing and
 * answers `encrypted`. A decrypting reader an application or an adapter binds
 * answers the value, `erased` once the owner's keys are destroyed, or
 * `unreadable`. An implementation must keep no state between calls, must never
 * answer with the ciphertext, and should mark its own field parameter
 * `#[\SensitiveParameter]`, since an attribute on this contract does not reach
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldReader
{
    /**
     * The reading of the fragment: `FieldReading::revealed()` with its value,
     * or `FieldReading::sealed()` with `encrypted`, `erased` or `unreadable`.
     *
     * Anything thrown is contained: the fragment is shown as `unreadable`, the
     * failure is reported once per entry naming only this class, and what was
     * thrown is discarded, because its message could hold the plaintext.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField  $field
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldReading
     *
     * @throws \Throwable
     */
    public function read(#[\SensitiveParameter] EncryptedField $field): FieldReading;
}
