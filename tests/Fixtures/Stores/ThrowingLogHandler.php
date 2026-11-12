<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\LogRecord;

/**
 * A Monolog handler that fails every write with a `\RuntimeException` holding
 * `self::SECRET`, standing for a full disk or an unreachable log server.
 *
 * A test sets the message through `handler_with`, so one Laravel reads as a
 * deadlock or lost connection fails the channel as one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingLogHandler extends AbstractProcessingHandler
{
    /** @var string The value every failure's message holds. */
    public const string SECRET = 's3cr3t';

    /**
     * Constructor.
     *
     * @param  string  $message
     */
    public function __construct(

        /** What every failure's message starts with, before the secret. */
        private readonly string $message = 'The log is unreachable',
    ) {
        parent::__construct();
    }

    /**
     * The configuration of a `monolog` driver channel that writes through this
     * handler, with the message given.
     *
     * @param  string  $message
     * @return array{driver: string, handler: class-string<self>, handler_with: array{message: string}}
     */
    public static function channel(string $message = 'The log is unreachable'): array
    {
        return ['driver' => 'monolog', 'handler' => self::class, 'handler_with' => ['message' => $message]];
    }

    /**
     * Fail the write, with the secret in the message.
     *
     * @param  \Monolog\LogRecord  $record
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    protected function write(LogRecord $record): void
    {
        throw new \RuntimeException($this->message . ': ' . self::SECRET);
    }
}
