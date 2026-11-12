<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * The streamed SHA-256 of each exported id and a line feed, in file order; only
 * ids are hashed, since every format carries one, so it checks any format.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MembershipDigest
{
    /** @var \HashContext The running SHA-256 of the ids added so far. */
    private \HashContext $hash;

    /** @var ?string The digest, once it is taken. */
    private ?string $digest = null;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->hash = hash_init('sha256');
    }

    /**
     * Add the next exported entry's id, followed by a line feed.
     *
     * @param  string  $id
     * @return void
     *
     * @throws \LogicException
     */
    public function add(string $id): void
    {
        if ($this->digest !== null) {
            throw new \LogicException('A membership digest takes no id once it has been taken.');
        }

        hash_update($this->hash, $id . "\n");
    }

    /**
     * The hex digest, taken on the first call and kept; no id is added after.
     *
     * @return string
     */
    public function digest(): string
    {
        return $this->digest ??= hash_final($this->hash);
    }
}
