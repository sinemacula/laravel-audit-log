<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Field reader contract: the seam that reads the encrypted fragments of a page
 * of entries when the page is shown, whether a property holding an encryption
 * envelope, an owned note or an IP address stored under the `encrypt` mode.
 *
 * It is reached only under a scope granted `revealingEncryptedFields()`, once
 * for each page, with every fragment of the page's entries whose rows verified
 * their signature; under any other scope every fragment is shown as `encrypted`
 * and no reader is asked. The package binds `Privacy\SubjectKeyFieldReader`,
 * which opens what `Privacy\SubjectKeyEncrypter` sealed and answers each
 * fragment's typed value, `erased` once the owner's keys are destroyed, or
 * `unreadable`. An application that never decrypts in PHP binds
 * `Privacy\SealedFieldReader`, which reads nothing and answers `encrypted`,
 * whatever a scope grants. A reader an application or an adapter binds in their
 * place answers in the same terms. An implementation must keep no state between
 * calls, hold no key beyond the call, must never answer with a ciphertext, and
 * should mark its own fields parameter `#[\SensitiveParameter]`, since an
 * attribute on this contract does not reach it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldReader
{
    /**
     * The reading of each fragment, in the order given and as many:
     * `FieldReading::revealed()` with its value, or `FieldReading::sealed()`
     * with `encrypted`, `erased` or `unreadable`.
     *
     * Anything thrown, and an answer of another count or holding anything but
     * readings, costs every fragment of the page, each shown as `unreadable`:
     * the failure is reported once for the page naming only this class, and
     * what was thrown is discarded, because its message could hold the
     * plaintext.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading>
     *
     * @throws \Throwable
     */
    public function readAll(#[\SensitiveParameter] array $fields): array;
}
