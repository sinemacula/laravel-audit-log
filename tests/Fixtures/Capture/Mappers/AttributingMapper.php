<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Capture\Events\PortalEvent;

/**
 * A mapper that names the portal user as the actor, or no actor for a portal
 * sign-in, and its own tenant, so a contributor or the signed-in user has
 * nothing left to fill.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttributingMapper implements EventMapper
{
    /** @var string The code it records. */
    public const string CODE = 'portal.provisioned';

    /** @var string The id of the tenant it records. */
    public const string TENANT = 'organisation-mapped';

    /**
     * The provisioning, by the event's user or no one, within the mapper's
     * tenant.
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
        $actor = $event instanceof PortalEvent ? Reference::of('user', $event->userId()) : null;

        return $record->event(self::CODE)->by($actor)->forTenant(Reference::of('organisation', self::TENANT));
    }
}
