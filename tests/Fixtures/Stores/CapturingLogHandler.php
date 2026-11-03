<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use Monolog\Handler\AbstractHandler;
use Monolog\LogRecord;

/**
 * A Monolog handler that hands every record it sees to a callback and lets it
 * pass on, whatever its level, so a test can read what reached a channel's own
 * handlers rather than what Laravel's wrapper told its listeners.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CapturingLogHandler extends AbstractHandler
{
    /**
     * Constructor.
     *
     * @param  \Closure(\Monolog\LogRecord): void  $capture
     */
    public function __construct(

        /** What every record is handed to. */
        private readonly \Closure $capture,
    ) {
        parent::__construct();
    }

    /**
     * Hand the record to the callback, and let it pass on.
     *
     * @param  \Monolog\LogRecord  $record
     * @return bool
     */
    #[\Override]
    public function handle(LogRecord $record): bool
    {
        ($this->capture)($record);

        return false;
    }
}
