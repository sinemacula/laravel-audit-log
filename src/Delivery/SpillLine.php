<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * One spill line as the reader found it: its number, and either its unparsed
 * JSON object or why none could be taken.
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

        /** The line's number in the file, from 1, every line counted. */
        public int $number,

        /** The line's JSON object, or `null` when none could be taken. */
        #[\SensitiveParameter]
        public ?string $json,

        /** Why no JSON object could be taken, or `null` when one was. */
        public ?EnvelopeFailure $failure,
    ) {}
}
