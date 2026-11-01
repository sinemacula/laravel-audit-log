<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * When the pending record is written, and whether a failed write throws.
 *
 * A record has exactly one timing. `afterCommit()` defers the write until the
 * selected transaction's outermost commit and drops it on that transaction's
 * rollback, writing now when none is open; without a connection it selects the
 * innermost pending transaction on any connection, and a name pins that
 * connection. `immediately()` writes now. `transactional()` writes inside the
 * open transaction on the connection, the storage connection by default, atomic
 * with it: it needs that transaction, and a connection other than the storage
 * connection needs the outbox on it. Those conditions are checked when the
 * record is written. A second, different timing is refused; the same one again
 * changes nothing. Without a timing the recorder applies the default: after
 * commit for an explicit record, immediately for a captured one.
 *
 * `failClosed()` makes a failed write throw, so returning means the insert
 * succeeded; it is written immediately unless it is transactional, and never
 * after commit, whichever is called first.
 *
 * The methods sit in a trait only so the builder stays within the number of
 * methods one class may declare; they are `PendingRecord`'s public surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ChoosesDelivery
{
    /** @var int Longest connection name, in characters. */
    private const int CONNECTION_MAX_CHARACTERS = 64;

    /** @var ?\SineMacula\Laravel\AuditLog\Records\Enums\Timing When the record is written, once chosen. */
    private ?Timing $timing = null;

    /** @var ?string The connection the timing is pinned to, if any. */
    private ?string $connection = null;

    /** @var bool Whether a failed write throws. */
    private bool $failClosed = false;

    /**
     * Write the record after the selected transaction's outermost commit, and
     * drop it on that transaction's rollback; write it now when none is open.
     * Without a connection the innermost pending transaction on any connection
     * is selected; a name pins that connection. A fail-closed record is never
     * written after commit.
     *
     * @param  ?string  $connection
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function afterCommit(?string $connection = null): self
    {
        $this->assertUsable();

        if ($this->failClosed) {
            self::refuseAfterCommit();
        }

        return $this->time(Timing::AFTER_COMMIT, $connection);
    }

    /**
     * Write the record now, inside a savepoint when the storage connection has
     * an open transaction, which isolates a failed write but does not make the
     * record durable before that transaction commits.
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function immediately(): self
    {
        $this->assertUsable();

        return $this->time(Timing::IMMEDIATE, null);
    }

    /**
     * Write the record inside the open transaction on the connection, the
     * storage connection by default, atomic with it. The transaction must be
     * open, and a connection other than the storage connection must hold the
     * outbox; both are checked when the record is written. A failed write
     * always throws, and the caller must not catch it and commit.
     *
     * @param  ?string  $connection
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function transactional(?string $connection = null): self
    {
        $this->assertUsable();

        return $this->time(Timing::TRANSACTIONAL, $connection);
    }

    /**
     * Make a failed write throw, so returning means the insert succeeded; it is
     * durable once any enclosing transaction on the storage connection commits.
     * The record is written immediately unless it is transactional, and never
     * after commit. Calling it again changes nothing.
     *
     * @return self
     *
     * @throws \LogicException
     */
    public function failClosed(): self
    {
        $this->assertUsable();

        if ($this->timing === Timing::AFTER_COMMIT) {
            self::refuseAfterCommit();
        }

        $this->failClosed = true;

        return $this;
    }

    /**
     * Set the timing and its connection, refusing a second, different one; the
     * same timing on the same connection again changes nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function time(Timing $timing, ?string $connection): self
    {
        if ($connection !== null) {
            self::checkIdentifier($connection, self::CONNECTION_MAX_CHARACTERS, 'A connection name');
        }

        $this->checkTiming($timing, $connection);

        $this->timing     = $timing;
        $this->connection = $connection;

        return $this;
    }

    /**
     * Refuse a timing other than the one already set, in mode or connection.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private function checkTiming(Timing $timing, ?string $connection): void
    {
        if ($this->timing !== null && ($this->timing !== $timing || $this->connection !== $connection)) {
            throw new \LogicException(sprintf('A record has one timing, and this one is already `%s`.', $this->timing->value));
        }
    }

    /**
     * Refuse to write a fail-closed record after commit.
     *
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuseAfterCommit(): never
    {
        throw new \LogicException('A fail-closed record is written immediately or transactionally, never after commit.');
    }
}
