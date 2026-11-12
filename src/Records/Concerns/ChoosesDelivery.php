<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Concerns;

use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * When the pending record is written, and whether a failed write throws; a
 * trait only to keep `PendingRecord` within the method-count limit.
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
     * Write the record after the selected transaction's outermost commit and
     * drop it on its rollback, or now when none is open; `null` selects the
     * innermost pending transaction on any connection.
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
            self::refuseDeferred();
        }

        return $this->time(Timing::AFTER_COMMIT, $connection);
    }

    /**
     * Write the record once the outermost transaction on its connection commits
     * or rolls back, or now when none is open. Held in memory, it is lost if
     * the process dies and waits when Laravel fires no rollback event.
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function afterTransaction(): self
    {
        $this->assertUsable();

        if ($this->failClosed) {
            self::refuseDeferred();
        }

        return $this->time(Timing::AFTER_TRANSACTION, null);
    }

    /**
     * Write the record now, in a savepoint when the storage connection has a
     * transaction, which isolates a failed write but is not durable before it
     * commits.
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
     * Write the record atomically inside the open transaction on the
     * connection, the storage connection by default; a failed write always
     * throws and must not be caught and committed.
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
     * never deferred and needs a durable store or the outbox.
     *
     * @return self
     *
     * @throws \LogicException
     */
    public function failClosed(): self
    {
        $this->assertUsable();

        if ($this->timing === Timing::AFTER_COMMIT || $this->timing === Timing::AFTER_TRANSACTION) {
            self::refuseDeferred();
        }

        $this->failClosed = true;

        return $this;
    }

    /**
     * Set the timing and its connection, refusing a second, different one.
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
     * Refuse to defer a fail-closed record.
     *
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuseDeferred(): never
    {
        throw new \LogicException('A fail-closed record is written immediately or transactionally, never after commit or after the transaction.');
    }
}
