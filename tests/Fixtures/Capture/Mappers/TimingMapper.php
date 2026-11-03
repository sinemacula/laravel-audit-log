<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that chooses its record's timing, the immediate one a capture would
 * use anyway, which only the capture decides.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TimingMapper implements EventMapper
{
    /**
     * The builder, timed.
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
        return $record->event(PortalMapper::CODE)->immediately();
    }
}
