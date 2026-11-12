<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * The field reader that opens nothing, so every encrypted fragment shows as
 * `encrypted` whatever a policy grants.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SealedFieldReader implements FieldReader
{
    /**
     * Each fragment, in the order given, kept sealed as `encrypted`.
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
