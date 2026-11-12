<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;

/**
 * Reaches a log channel's own logger past Laravel's wrapper, so shared context
 * and `MessageLogged` listeners never see a line that holds a whole record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DirectLog
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The channel's underlying logger, or the channel itself when it is not
     * Laravel's wrapper.
     *
     * @param  \Illuminate\Log\LogManager  $logs
     * @param  ?string  $channel
     * @return \Psr\Log\LoggerInterface
     */
    public static function channel(LogManager $logs, ?string $channel): LoggerInterface
    {
        $logger = $logs->channel($channel);

        return $logger instanceof Logger ? $logger->getLogger() : $logger;
    }
}
