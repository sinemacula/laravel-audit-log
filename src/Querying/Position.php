<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * A place in the trail's order: a time, as an instant in the package's form,
 * and the id of an entry at that time, a lower-case UUID. A page cursor holds
 * the occurrence time of the last entry shown, and an export's keyset the time
 * an entry was recorded; the two together order entries of one microsecond.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Position
{
    /** @var string Pattern of an entry id: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * Constructor.
     *
     * @param  string  $time
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The time, an instant in the package's form. */
        public string $time,

        /** The id of an entry at that time, a lower-case UUID. */
        public string $id,
    ) {
        if (!StoredTime::isInstant($time) || preg_match(self::UUID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException('A position must be an instant in the package\'s form, such as 2026-11-01T12:00:00.123456Z, and a lower-case UUID.');
        }
    }

    /**
     * The position as its time and its id.
     *
     * @return array{0: string, 1: string}
     */
    public function toArray(): array
    {
        return [$this->time, $this->id];
    }
}
