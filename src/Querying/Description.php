<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * An entry summarised for a person; its properties are the display view, where
 * an encrypted fragment is a value or a marker, never a ciphertext.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<array-key, mixed>|string|null>
 */
final readonly class Description implements Arrayable
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $title
     * @param  string  $code
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @param  array<array-key, mixed>  $properties
     *
     * @internal
     */
    public function __construct(

        /** The code's title, or the code itself when untranslated. */
        public string $title,

        /** The event code naming what happened. */
        public string $code,

        /** How the activity ended. */
        public Outcome $outcome,

        /** Why it failed or was denied; `null` when none or concealed. */
        public ?string $reason,

        /** The entry's properties, for display. */
        #[\SensitiveParameter]
        public array $properties,
    ) {}

    /**
     * The description with its outcome as its value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<string, array<array-key, mixed>|string|null>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'title'      => $this->title,
            'code'       => $this->code,
            'outcome'    => $this->outcome->value,
            'reason'     => $this->reason,
            'properties' => $this->properties,
        ];
    }
}
