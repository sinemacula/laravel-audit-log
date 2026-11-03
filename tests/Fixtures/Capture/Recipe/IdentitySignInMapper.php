<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Recipe;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * The extending guide's recipe mapper, `App\Audit\IdentitySignInMapper`, whose
 * text from its class declaration to its end is the guide's own: it records
 * each sign-in of another package's guard as `identity.signed_in`, by the user
 * and on them, correlated with the attempt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentitySignInMapper implements EventMapper
{
    /**
     * The sign-in, by the user who signed in and on them, correlated with the
     * attempt it completed; any other event is skipped.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        if (!$event instanceof UserSignedIn) {
            return null;
        }

        return $record->event('identity.signed_in')
            ->by($event->user)
            ->on($event->user)
            ->correlatedWith('identity:' . $event->attemptId);
    }
}
