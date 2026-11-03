<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that asks for its record to be fail-closed, which a capture never
 * is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailClosedMapper implements EventMapper
{
    /**
     * The builder, made fail-closed.
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
        return $record->event(PortalMapper::CODE)->failClosed();
    }
}
