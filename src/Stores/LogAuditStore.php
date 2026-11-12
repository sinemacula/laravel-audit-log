<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Log\LogManager;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that writes each record as one `info` line to a log channel:
 * the marker `audit-log:v1 `, then the formatter's projection.
 *
 * Not durable and joins no transaction; a retried record is written again, and
 * a bulk record is never handed to it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LogAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var string What every line starts with, so Monolog never reads it as JSON. */
    public const string MARKER = 'audit-log:v1 ';

    /** @var array<string, string> The line breaks a formatter may leave, each with its escape. */
    private const array LINE_BREAKS = ["\r" => '\r', "\n" => '\n', "\u{2028}" => '\u2028', "\u{2029}" => '\u2029'];

    /** @var string A `%` that opens a token of Monolog's `LineFormatter`: a field, alone or with a dotted key. */
    private const string LINE_FORMATTER_TOKEN = '/%(?=(?:message|context|extra|level|level_name|channel|datetime)[.%])/';

    /** @var string What a `%` opening a token is written as. */
    private const string ENCODED_PERCENT = '%25';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Log\LogManager  $logs
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditFormatter  $formatter
     * @param  ?string  $channel
     */
    public function __construct(

        /** The log manager the channel is resolved from. */
        private LogManager $logs,

        /** The formatter that projects each record as one line. */
        private AuditFormatter $formatter,

        /** The channel the lines are written to, or `null` for the default channel. */
        private ?string $channel = null,
    ) {}

    /**
     * Write the record's projection as one line, after the marker, at `info`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $line = strtr($this->formatter->format($record), self::LINE_BREAKS);

        DirectLog::channel($this->logs, $this->channel)->info(self::MARKER . preg_replace(self::LINE_FORMATTER_TOKEN, self::ENCODED_PERCENT, $line));
    }

    /**
     * Whether a return is durable: never, since a handler may buffer or drop
     * the line.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return false;
    }

    /**
     * Whether a write joins a transaction on the connection: never.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return false;
    }

    /**
     * Whether the store keeps attachments: never, since its projection would
     * lose the members.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return false;
    }
}
