<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

/**
 * A value as the value normaliser leaves it, with the paths of the first 32 map
 * keys that collided once cleaned and how many collided in all. A path holds
 * raw cleaned keys, so it must be masked before it is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Normalised
{
    /** @var int Most collision paths kept. */
    public const int MAX_COLLISIONS = 32;

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|bool|int|string|null  $value
     * @param  list<list<int|string>>  $collisions
     * @param  int  $collisionCount
     */
    public function __construct(

        /** The value, made only of strings, integers, booleans, `null`, lists and maps. */
        #[\SensitiveParameter]
        public array|bool|int|string|null $value,

        /** Concrete paths of the keys that collided, segment by segment, first 32. */
        #[\SensitiveParameter]
        public array $collisions = [],

        /** How many keys collided in all. */
        public int $collisionCount = 0,
    ) {}
}
