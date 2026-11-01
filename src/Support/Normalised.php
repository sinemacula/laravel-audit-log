<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

/**
 * A value as the value normaliser leaves it, made only of strings, integers,
 * booleans, `null`, lists and maps, with the diagnostics of the map keys that
 * collided once cleaned: the schema path of each of the first 32, in the order
 * they were met, and how many collided in all. A diagnostic never holds a
 * value.
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
     * @param  list<string>  $collisions
     * @param  int  $collisionCount
     */
    public function __construct(

        /** The value, made only of strings, integers, booleans, `null`, lists and maps. */
        public array|bool|int|string|null $value,

        /** Schema paths of the keys that collided, first 32. */
        public array $collisions = [],

        /** How many keys collided in all. */
        public int $collisionCount = 0,
    ) {}
}
