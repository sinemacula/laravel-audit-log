<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * One spill line as the reader found it: its number in the file, and either the
 * one JSON object it holds, not yet parsed or verified, or why the reader could
 * not take one from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpillLine
{
    /**
     * Constructor.
     *
     * @param  int  $number
     * @param  ?string  $json
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     */
    public function __construct(

        /** The line's number in the file, from 1, with every line of the file counted. */
        public int $number,

        /** The one JSON object the line holds, or `null` when the reader could not take one. */
        #[\SensitiveParameter]
        public ?string $json,

        /** Why the reader could not take a JSON object from the line, or `null` when it did. */
        public ?EnvelopeFailure $failure,
    ) {}
}
