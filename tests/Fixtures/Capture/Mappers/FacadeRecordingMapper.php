<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that records through the facade before returning the builder it was
 * given, which a write while a mapper runs refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FacadeRecordingMapper implements EventMapper
{
    /**
     * The builder, once it has tried to record through the facade.
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
        AuditLog::record(PortalMapper::CODE);

        return $record->event(PortalMapper::CODE);
    }
}
