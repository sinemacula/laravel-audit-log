<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Log\LogManager;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Writes a record whose write failed to the configured log channel, as one line
 * at `critical` that `audit-log:replay` can read back: the marker
 * `audit-log-spill:v1 `, then the record's envelope in the canonical encoding.
 *
 * A finalised record is spilled with its integrity fields, so a replay can
 * verify it; a record that failed before it was finalised is spilled with
 * `unsigned` set and no signature, and a replay leaves it. Every `%` in the
 * envelope is written as the JSON escape `\u0025`, which decodes to the same
 * value, because Monolog's `LineFormatter` rewrites a `%token%` in its output
 * even after the message is substituted; the HMAC is over decoded values, so
 * the line still verifies. The canonical encoding escapes every line break
 * inside its strings, so a line is one physical line whatever the record holds.
 * The line goes to the channel's own logger, past Laravel's wrapper, so no
 * shared log context joins it and no `MessageLogged` listener receives the
 * record, which would otherwise land beside the report that follows it. It is
 * never truncated, and a failure of the channel propagates to the caller, which
 * isolates it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailureSpill
{
    /** @var string What every spill line starts with, its trailing space included. */
    public const string MARKER = 'audit-log-spill:v1 ';

    /** @var string The JSON escape every `%` is written as: six bytes, a backslash, `u`, `0`, `0`, `2`, `5`. */
    private const string ESCAPED_PERCENT = '\u0025';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Log\LogManager  $logs
     * @param  \SineMacula\Laravel\AuditLog\Stores\FailureSettings  $settings
     */
    public function __construct(

        /** The log manager the channel is resolved from. */
        private LogManager $logs,

        /** The settings that name the channel. */
        private FailureSettings $settings,
    ) {}

    /**
     * Spill the finalised record with its integrity fields.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function spillFinalised(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $this->write($record->toArray());
    }

    /**
     * Spill a record that was never finalised, marked `unsigned`, with no
     * integrity fields.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function spillUnsigned(#[\SensitiveParameter] AuditRecord $record): void
    {
        $this->write(['unsigned' => true, ...$record->toArray()]);
    }

    /**
     * The spill line of the envelope: the marker, then its canonical encoding
     * with every `%` escaped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function line(#[\SensitiveParameter] array $envelope): string
    {
        return self::MARKER . str_replace('%', self::ESCAPED_PERCENT, CanonicalEncoder::encode($envelope));
    }

    /**
     * Write the envelope's line to the configured channel's own logger at
     * `critical`, with no context.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    private function write(#[\SensitiveParameter] array $envelope): void
    {
        DirectLog::channel($this->logs, $this->settings->logChannel())->critical(self::line($envelope));
    }
}
