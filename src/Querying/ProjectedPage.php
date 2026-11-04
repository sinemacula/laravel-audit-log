<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * The entries a page shows, as the projector made them from the stored entries,
 * in their order, and what the page disclosed of their encrypted fragments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProjectedPage
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\TrailEntry>  $entries
     * @param  \SineMacula\Laravel\AuditLog\Querying\FieldDisclosure  $fields
     */
    public function __construct(

        /** The entries shown, in the order of the stored entries. */
        #[\SensitiveParameter]
        public array $entries,

        /** What the page disclosed of the entries' encrypted fragments. */
        public FieldDisclosure $fields,
    ) {}
}
