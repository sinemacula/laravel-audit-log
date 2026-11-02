<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

/**
 * What a record stores once it has been minimised: its properties, its context
 * and its IP address, and nothing raw. Diagnostics of what was removed travel
 * inside `properties._audit.omitted`, so this value has no field of its own for
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Minimised
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $properties
     * @param  ?array<array-key, mixed>  $context
     * @param  ?string  $ip
     */
    public function __construct(

        /** The properties to store, with the package's metadata last; `null` when there are none. */
        #[\SensitiveParameter]
        public ?array $properties,

        /** The context to store; `null` when there is none. */
        #[\SensitiveParameter]
        public ?array $context,

        /** The IP address to store, in the configured mode; `null` when there is none. */
        #[\SensitiveParameter]
        public ?string $ip,
    ) {}
}
