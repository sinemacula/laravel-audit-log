<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;

/**
 * The settings under `audit-log.delivery.`, read and validated on every call. A
 * missing setting takes its default; a malformed one, an explicit `null`
 * included, throws naming the key, never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliverySettings
{
    /** @var string Prefix of every delivery setting's key. */
    private const string PREFIX = 'audit-log.delivery.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by key. */
    private const array NUMBERS = [
        'outbox.lease_seconds'   => [300, 30, 86400],
        'outbox.max_attempts'    => [10, 1, 1000],
        'outbox.backoff_seconds' => [60, 1, 3600],
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * How a record reaches its store: `sync` unless configured otherwise.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode
     *
     * @throws \InvalidArgumentException
     */
    public function mode(): DeliveryMode
    {
        $mode = $this->config->get(self::PREFIX . 'mode', DeliveryMode::SYNC->value);

        return (is_string($mode) ? DeliveryMode::tryFrom($mode) : null)
            ?? throw new \InvalidArgumentException('`audit-log.delivery.mode` must be `sync` or `outbox`.');
    }

    /**
     * How long a drain's claim on an outbox row lasts before another drain may
     * take the row, in seconds, from 30 to 86400.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function leaseSeconds(): int
    {
        return $this->number('outbox.lease_seconds');
    }

    /**
     * How many attempts an outbox row gets before it is failed, from 1 to 1000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return $this->number('outbox.max_attempts');
    }

    /**
     * How long the first retry of an outbox row waits, in seconds, from 1 to
     * 3600; each later retry doubles it, up to an hour.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function backoffSeconds(): int
    {
        return $this->number('outbox.backoff_seconds');
    }

    /**
     * Read every delivery setting, the delivery tables and the outbox
     * connection included, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->mode();
        $this->leaseSeconds();
        $this->maxAttempts();
        $this->backoffSeconds();

        DeliveryTables::outboxConnection();
        DeliveryTables::outboxTable();
        DeliveryTables::deliveriesTable();
    }

    /**
     * The numeric setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $setting): int
    {
        [$default, $least, $most] = self::NUMBERS[$setting];

        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }
}
