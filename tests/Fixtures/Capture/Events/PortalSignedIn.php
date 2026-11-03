<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * A user signed in to the portal: an event class mapped on its own, whose
 * subclass reaches its mapping as a parent class mapping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
readonly class PortalSignedIn
{
    /**
     * Constructor.
     *
     * @param  string  $user
     * @param  string  $secret
     */
    public function __construct(

        /** The id of the user who signed in. */
        public string $user = '42',

        /** A value the event carries that no record, report or event may hold. */
        #[\SensitiveParameter]
        public string $secret = 's3cr3t',
    ) {}
}
