<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * A mapper that throws, with a message holding a value of the event, which no
 * report or event of the failed capture may carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ThrowingMapper implements EventMapper
{
    /** @var string The value of the event its message holds. */
    public const string SECRET = 's3cr3t';

    /**
     * Nothing: the mapper fails.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        throw new \RuntimeException(sprintf('The portal sign-in could not be mapped with %s.', self::SECRET));
    }
}
