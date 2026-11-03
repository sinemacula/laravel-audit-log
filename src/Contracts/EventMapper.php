<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Event mapper contract: translates an event the application or an integration
 * dispatches into the record of what happened, so the event is captured without
 * the code that dispatched it recording anything.
 *
 * A mapper is registered at boot with `AuditLog::map()`, for an event's class
 * or for a parent class or interface of it. It is resolved from the container
 * for each capture and must keep no state between calls. It receives a builder
 * with no recorder, whose `record()` is a `\LogicException`, and never records
 * anything itself, through that builder or through the facade, since an
 * explicit record while a mapper runs is refused: the capture writes the
 * builder the mapper returns. What the mapper sets off is captured as it would
 * be anywhere else, so a watched model it saves or a Gate check it denies is
 * recorded by its own capture, while capturing or dispatching the event it is
 * mapping again writes nothing.
 *
 * A mapper sets at least the code, with `event()`, and the fields it translates
 * from the event. It names the code itself and never derives one from the
 * event's class, so renaming the class never changes the trail. It returns the
 * same builder, or `null` to skip the event. It must not choose a timing,
 * `failClosed()` or `transactional()`, since a capture decides how it is
 * written. Anything else, a mapper that throws among it, is a contained capture
 * failure: nothing is written, the failure is reported without the event's
 * values, `Events\AuditCaptureFailed` is dispatched, and the code that
 * dispatched the event goes on.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventMapper
{
    /**
     * The record the event describes: the builder given, with its code and the
     * fields translated from the event set, or `null` when the event is not to
     * be recorded.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord;
}
