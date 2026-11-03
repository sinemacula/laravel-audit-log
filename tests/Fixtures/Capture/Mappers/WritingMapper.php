<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that writes a record of its own through the container's record
 * pipeline before returning the builder it was given, which a write while a
 * mapper runs refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WritingMapper implements EventMapper
{
    /**
     * The builder, once it has tried to write another.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): PendingRecord
    {
        Container::getInstance()->make(RecordPipeline::class)->write((new PendingRecord)->event(PortalMapper::CODE));

        return $record->event(PortalMapper::CODE);
    }
}
