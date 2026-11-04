<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * The membership digest of an export, streamed: the lower-case hex SHA-256 of
 * each exported entry's id followed by a line feed, in the order the file holds
 * them, ascending by recorded time and then id. Only the ids are hashed, since
 * every format carries an entry's id on its line, so the one digest checks an
 * export in any format; the order is bound because the ids are hashed in it.
 *
 * Nothing is kept but the running hash, so an export of any size is digested in
 * constant memory. The set of no ids digests to the SHA-256 of no bytes. The
 * digest is taken once: it is kept for every later call, and an id added after
 * it is refused.
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
     * The digest of every id added, as 64 lower-case hexadecimal characters,
     * taken on the first call and kept for every later one.
     *
     * @return string
     */
    public function digest(): string
    {
        return $this->digest ??= hash_final($this->hash);
    }
}
