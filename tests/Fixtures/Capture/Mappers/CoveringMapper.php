<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * A mapper of a bulk operation: it names its own code and covers the users the
 * operation touched, one of them twice, so the capture writes one entry with a
 * manifest of each user once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CoveringMapper implements EventMapper
{
    /** @var string The code it records. */
    public const string CODE = 'portal.users_suspended';

    /** @var list<string> The ids of the users it covers, each once. */
    public const array USERS = ['7', '8', '9'];

    /**
     * The suspension, covering every user it touched.
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
        $users = array_map(static fn (string $id): Reference => Reference::of('user', $id), [...self::USERS, self::USERS[0]]);

        return $record->event(self::CODE)->covering($users);
    }
}
