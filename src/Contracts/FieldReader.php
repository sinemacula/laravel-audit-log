<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Field reader contract: reads a page's encrypted fragments when it is shown,
 * asked only under a scope granted `revealingEncryptedFields()`.
 *
 * An implementation keeps no state, holds no key beyond the call, never answers
 * with a ciphertext, and should mark its fields parameter
 * `#[\SensitiveParameter]`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldReader
{
    /**
     * The reading of each fragment, in order and as many: revealed with its
     * value, or sealed as `encrypted`, `erased` or `unreadable`.
     *
     * A throw or a malformed answer shows the whole page `unreadable`, and what
     * was thrown is discarded, since it could hold plaintext.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading>
     *
     * @throws \Throwable
     */
    public function readAll(#[\SensitiveParameter] array $fields): array;
}
