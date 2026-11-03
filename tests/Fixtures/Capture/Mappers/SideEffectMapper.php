<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use Tests\Fixtures\Capture\Models\PlainLine;

/**
 * A mapper whose own work sets off other activity before it returns the builder
 * it was given: it saves a line and asks the Gate an ability no guest is
 * allowed, each of which is captured on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SideEffectMapper implements EventMapper
{
    /** @var string The ability it asks the Gate, which no guest is allowed. */
    public const string ABILITY = 'approve-portal-session';

    /**
     * The builder, once a line has been saved and the ability denied.
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
        PlainLine::query()->create(['description' => 'Set off by a mapper', 'quantity' => 1]);

        Gate::allows(self::ABILITY);

        return $record->event(PortalMapper::CODE);
    }
}
