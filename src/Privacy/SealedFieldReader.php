<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * The field reader that opens nothing and reads nothing of the fields it is
 * given, so every encrypted fragment of a page is shown as `encrypted`, even
 * under a scope that reveals them.
 *
 * Binding it as `Contracts\FieldReader` is the way to choose never to decrypt
 * in PHP, whatever a policy grants. It reads no key, so what is shown is always
 * the envelope's presence, never its value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SealedFieldReader implements FieldReader
{
    /**
     * Each fragment, in the order given, kept sealed as `encrypted`, whatever
     * it holds.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading>
     */
    #[\Override]
    public function readAll(#[\SensitiveParameter] array $fields): array
    {
        return array_map(static fn (): FieldReading => FieldReading::sealed(FieldState::ENCRYPTED), $fields);
    }
}
