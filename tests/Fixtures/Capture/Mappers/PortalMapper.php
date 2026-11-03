<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;

/**
 * A well-behaved mapper of portal events: it names its own code, the user the
 * event is about as the subject, and returns the builder it was given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PortalMapper implements EventMapper
{
    /** @var string The code it records. */
    public const string CODE = 'portal.signed_in';

    /** @var string The type of the subject it records. */
    public const string SUBJECT_TYPE = 'user';

    /**
     * The sign-in, on the user the event names.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): PendingRecord
    {
        return $record->event(self::CODE)->on(Reference::of(self::SUBJECT_TYPE, self::userOf($event)));
    }

    /**
     * The id of the user the event is about, or `0` for an event that names
     * none.
     *
     * @param  object  $event
     * @return string
     */
    private static function userOf(#[\SensitiveParameter] object $event): string
    {
        return match (true) {
            $event instanceof PortalEvent    => $event->userId(),
            $event instanceof PortalSignedIn => $event->user,
            default                          => '0',
        };
    }
}
