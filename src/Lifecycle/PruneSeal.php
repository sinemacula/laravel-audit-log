<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;

/**
 * A seal a prune has authenticated: its envelope, its stored digest, and its
 * members, each entry id with the HMAC it was sealed with, in member order.
 *
 * Member order is the entry ids as canonical lower-case UUID strings, sorted
 * bytewise in PHP, never by an engine's collation, so a member's position is
 * the same wherever it is computed, and a prune record's bitmap sets the bit at
 * that position. `PruneSeals::load()` alone builds one, once the seal's digest,
 * log, signature and membership have each been checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneSeal
{
    /** @var list<string> The members' entry ids, sorted bytewise. */
    public array $memberIds;

    /** @var array<string, int> Each member's position in member order, by its entry id. */
    private array $positions;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $envelope
     * @param  string  $digest
     * @param  array<string, string>  $members
     */
    public function __construct(

        /** The seal's envelope, as its row stores it. */
        #[\SensitiveParameter]
        public SealEnvelope $envelope,

        /** The seal's digest, recomputed and equal to the one stored. */
        public string $digest,

        /** The HMAC each member was sealed with, by its entry id. */
        #[\SensitiveParameter]
        private array $members,
    ) {
        $ids = array_keys($members);

        usort($ids, strcmp(...));

        $this->memberIds = $ids;
        $this->positions = array_flip($ids);
    }

    /**
     * Whether the seal holds the entry as a member.
     *
     * @param  string  $id
     * @return bool
     */
    public function hasMember(string $id): bool
    {
        return isset($this->positions[$id]);
    }

    /**
     * The member's position in member order, from 0.
     *
     * @param  string  $id
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function positionOf(string $id): int
    {
        return $this->positions[$id] ?? throw self::notAMember();
    }

    /**
     * The HMAC the member was sealed with.
     *
     * @param  string  $id
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function memberHmac(string $id): string
    {
        return $this->members[$id] ?? throw self::notAMember();
    }

    /**
     * The refusal of an entry the seal does not hold.
     *
     * @return \InvalidArgumentException
     */
    private static function notAMember(): \InvalidArgumentException
    {
        return new \InvalidArgumentException('The entry is not a member of the seal.');
    }
}
