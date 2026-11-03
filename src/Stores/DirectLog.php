<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;

/**
 * Reaches a log channel's own logger, past Laravel's wrapper, for a line that
 * holds a whole record or a line another system parses.
 *
 * Laravel's wrapper merges `Log::shareContext()` into every record and hands
 * every message to each `MessageLogged` listener, so an error tracker
 * collecting breadcrumbs would hold the record beside a failure report meant to
 * be free of it, and a format printing `%context%` would carry the shared
 * context into a line. The channel's handlers and formatter still run.
 * Laravel's `Context` reaches the underlying logger through its processor, as
 * `extra`, and only a format printing `%extra%` shows it.
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
