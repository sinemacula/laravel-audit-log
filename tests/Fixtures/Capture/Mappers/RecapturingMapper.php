<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that captures the event it is mapping again, through the facade,
 * before returning the builder it was given. It counts its runs, and refuses to
 * run inside itself, so a capture that recursed fails rather than running
 * without end.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecapturingMapper implements EventMapper
{
    /** @var int How many times it has been asked to map an event. */
    public int $calls = 0;

    /**
     * The builder, once the event has been captured again.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): PendingRecord
    {
        if (++$this->calls > 1) {
            throw new \LogicException('The mapper ran inside its own mapping.');
        }

        AuditLog::capture($event);

        return $record->event(PortalMapper::CODE);
    }
}
