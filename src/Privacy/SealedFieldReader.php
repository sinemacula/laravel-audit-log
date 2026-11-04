<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * The field reader the package binds: it opens nothing and reads nothing of the
 * field it is given, so every encrypted fragment of an entry is shown as
 * `encrypted` until an application binds a reader that decrypts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealedFieldReader implements FieldReader
{
    /**
     * The fragment, kept sealed as `encrypted`, whatever it holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField  $field
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldReading
     */
    #[\Override]
    public function read(#[\SensitiveParameter] EncryptedField $field): FieldReading
    {
        return FieldReading::sealed(FieldState::ENCRYPTED);
    }
}
