<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that dispatches the event it is mapping again; it counts its runs
 * and refuses to run inside itself, so a recursing capture fails instead of
 * looping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RedispatchingMapper implements EventMapper
{
    /** @var int How many times it has been asked to map an event. */
    public int $calls = 0;

    /**
     * The builder, once the event has been dispatched again.
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

        Event::dispatch($event);

        return $record->event(PortalMapper::CODE);
    }
}
