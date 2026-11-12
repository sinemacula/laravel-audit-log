<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * The failure settings, read and validated on every call; a malformed one fails
 * closed naming its key, never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailureSettings
{
    /** @var string The mode's full key. */
    private const string MODE = 'audit-log.failure.mode';

    /** @var string The log channel's full key. */
    private const string LOG_CHANNEL = 'audit-log.failure.log_channel';

    /** @var int Longest channel name, in characters. */
    private const int MAX_CHANNEL_CHARACTERS = 64;

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
     * What a failed write does to the recording code, `report` by default.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode
     *
     * @throws \InvalidArgumentException
     */
    public function mode(): FailureMode
    {
        $mode = $this->config->get(self::MODE, FailureMode::REPORT->value);

        return (is_string($mode) ? FailureMode::tryFrom($mode) : null)
            ?? throw new \InvalidArgumentException(sprintf('`%s` must be `report` or `throw`.', self::MODE));
    }

    /**
     * The spill line's log channel, or `null` for the default channel.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function logChannel(): ?string
    {
        $channel = $this->config->get(self::LOG_CHANNEL);

        if ($channel === null || $channel === '') {
            return null;
        }

        if (!is_string($channel) || mb_strlen($channel, 'UTF-8') > self::MAX_CHANNEL_CHARACTERS) {
            $message = '`%s` must be a channel name of 1 to %d characters, or null or empty for the default channel.';

            throw new \InvalidArgumentException(sprintf($message, self::LOG_CHANNEL, self::MAX_CHANNEL_CHARACTERS));
        }

        return $channel;
    }

    /**
     * Read every failure setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->mode();
        $this->logChannel();
    }
}
