<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * A user signed in to the portal: an event that is both a portal event and an
 * account event, so a mapping of each interface applies to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignedInToPortal implements AccountEvent, PortalEvent
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

    /**
     * The id of the account signed in to: the user's own.
     *
     * @return string
     */
    #[\Override]
    public function accountId(): string
    {
        return $this->user;
    }

    /**
     * The id of the user who signed in.
     *
     * @return string
     */
    #[\Override]
    public function userId(): string
    {
        return $this->user;
    }
}
