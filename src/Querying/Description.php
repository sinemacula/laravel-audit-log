<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * An entry of the trail as a sentence-sized summary for a person: the title of
 * its code, the code itself, how the activity ended, why it failed or was
 * denied unless its record concealed that, and its properties for display.
 *
 * The title is plain text from the translations, never a sentence with stored
 * values put into it; the properties are the entry's display view, in which
 * every encrypted fragment is a value or a marker, never a ciphertext.
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

        /** The code's title in the locale asked for, the fallback locale's, or the code itself. */
        public string $title,

        /** The event code naming what happened. */
        public string $code,

        /** How the activity ended. */
        public Outcome $outcome,

        /** Why it failed or was denied; `null` when none was given or its record concealed it. */
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
