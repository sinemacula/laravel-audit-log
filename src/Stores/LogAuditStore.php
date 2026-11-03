<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Log\LogManager;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that writes each record as one line, at `info`, to a log
 * channel: the formatter's projection of the record, after the marker
 * `audit-log:v1 `.
 *
 * The marker keeps a line from starting with `{` or `[`, which Monolog's
 * `LineFormatter` would otherwise read as JSON whose escaped line breaks it
 * turns back into real ones when inline line breaks are allowed. A carriage
 * return, a line feed or a Unicode line or paragraph separator a formatter left
 * in its line, breaking its own promise, is escaped, so a record is always one
 * physical line. The line reaches the channel's own logger, past Laravel's
 * wrapper, so no shared log context joins it and no `MessageLogged` listener
 * receives it, and every `%` that would open one of `LineFormatter`'s tokens is
 * written as `%25`, because that formatter substitutes them inside a message
 * after it has placed it, without any escaping for CEF or JSON, so a value
 * holding `%context%` could otherwise import a field or a physical line. A
 * failure of the channel propagates.
 *
 * It is not durable, since a log handler may buffer, drop or rotate a line
 * after it returns, and it joins no transaction. The store contract's clause
 * that a record is stored at most once is waived for it: a log line cannot be
 * taken back or deduplicated, so a retried record is written again. It keeps no
 * attachment: its line is a projection of the record, which would lose a bulk
 * operation's members, so a bulk record is never handed to it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LogAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var string What every line starts with, its trailing space included. */
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
     * Whether a return is a durable acknowledgement: never, since a log handler
     * may buffer or drop a line after it returns.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return false;
    }

    /**
     * Whether a write joins a transaction on the connection: never, since a
     * line written stays written whatever the transaction does.
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
     * Whether the store keeps a record's attachment with its entry: never,
     * since its line is a projection that would lose the members.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return false;
    }
}
