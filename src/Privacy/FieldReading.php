<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * What a field reader answers for an encrypted fragment: the revealed value, or
 * the state that keeps it sealed, never a ciphertext.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FieldReading
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $state
     * @param  array<array-key, mixed>|scalar|null  $value
     */
    private function __construct(

        /** Why the fragment stays sealed; `null` when its value was revealed. */
        public ?FieldState $state,

        /** The value revealed; `null` when the fragment stays sealed. */
        #[\SensitiveParameter]
        public array|bool|float|int|string|null $value,
    ) {}

    /**
     * A reading that keeps the fragment sealed, for the reason given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $state
     * @return self
     */
    public static function sealed(FieldState $state): self
    {
        return new self($state, null);
    }

    /**
     * A reading that reveals the fragment's value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|scalar|null  $value
     * @return self
     */
    public static function revealed(#[\SensitiveParameter] array|bool|float|int|string|null $value): self
    {
        return new self(null, $value);
    }

    /**
     * What an entry shows in the fragment's place: the state's marker, or the
     * revealed value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>|scalar|null
     */
    public function display(): array|bool|float|int|string|null
    {
        return $this->state === null ? $this->value : $this->state->marker();
    }
}
