<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Who is reading: the original for the policy alone, and its reference, which
 * the read's record and cursor are bound to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Viewer
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $original
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $reference
     */
    private function __construct(

        /** The viewer as the application gave it, for the access policy. */
        #[\SensitiveParameter]
        public Authenticatable|Reference $original,

        /** The viewer's reference, as capture references a user. */
        public Reference $reference,
    ) {}

    /**
     * The viewer, referenced as capture references a user; never anonymous.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(#[\SensitiveParameter] Authenticatable|Reference $viewer): self
    {
        $reference = $viewer instanceof Reference ? $viewer : UserReference::of($viewer);

        if ($reference === null) {
            $message = 'A viewer must be a model with a key, an authenticatable user with a string or integer identifier,'
                . ' or a reference; it is never read as anonymous.';

            throw new \InvalidArgumentException($message);
        }

        return new self($viewer, $reference);
    }
}
