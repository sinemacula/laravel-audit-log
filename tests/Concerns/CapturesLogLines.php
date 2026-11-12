<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Log;
use Monolog\LogRecord;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use Tests\Fixtures\Stores\CapturingLogHandler;
use Tests\Fixtures\Stores\CapturingLogManager;

/**
 * Captures every message any log channel writes, at a handler behind the
 * channel's own, so it sees what bypasses Laravel's wrapper and `MessageLogged`
 * listeners; a channel that fails captures nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CapturesLogLines
{
    /** @var list<\Illuminate\Log\Events\MessageLogged> The messages logged since capturing last began, oldest first. */
    private array $loggedMessages = [];

    /** @var list<\Closure(\Illuminate\Log\Events\MessageLogged): void> What each captured message is also handed to, as it is written. */
    private array $logLineListeners = [];

    /** @var bool Whether the capturing handler is in place. */
    private bool $capturingLogLines = false;

    /**
     * Start capturing afresh, putting the handler in place on first use.
     *
     * @return void
     */
    protected function captureLogLines(): void
    {
        $this->loggedMessages = [];

        if ($this->capturingLogLines) {
            return;
        }

        $this->capturingLogLines = true;

        $manager = new CapturingLogManager(app());

        $manager->captureWith(new CapturingLogHandler(function (LogRecord $record): void {
            $logged = new MessageLogged(strtolower($record->level->name), $record->message, $record->context);

            $this->loggedMessages[] = $logged;

            foreach ($this->logLineListeners as $listener) {
                $listener($logged);
            }
        }));

        app()->instance('log', $manager);

        Log::clearResolvedInstance('log');
    }

    /**
     * Hand each message to the listener as it is written, capturing from here
     * on if nothing is yet.
     *
     * @param  \Closure(\Illuminate\Log\Events\MessageLogged): void  $listener
     * @return void
     */
    protected function onLogLine(\Closure $listener): void
    {
        if (!$this->capturingLogLines) {
            $this->captureLogLines();
        }

        $this->logLineListeners[] = $listener;
    }

    /**
     * Every message logged since capturing began, oldest first.
     *
     * @return list<\Illuminate\Log\Events\MessageLogged>
     */
    protected function loggedMessages(): array
    {
        return $this->loggedMessages;
    }

    /**
     * The spill lines logged since capturing began, oldest first: each message
     * that starts with the spill marker.
     *
     * @return list<string>
     */
    protected function spillLines(): array
    {
        return $this->linesMarked(FailureSpill::MARKER);
    }

    /**
     * The log store's lines logged since capturing began, oldest first: each
     * message that starts with the log store's marker.
     *
     * @return list<string>
     */
    protected function logStoreLines(): array
    {
        return $this->linesMarked(LogAuditStore::MARKER);
    }

    /**
     * The messages logged since capturing began that start with the marker,
     * oldest first.
     *
     * @param  string  $marker
     * @return list<string>
     */
    private function linesMarked(string $marker): array
    {
        $lines = array_map(static fn (MessageLogged $logged): string => $logged->message, $this->loggedMessages);

        return array_values(array_filter($lines, static fn (string $line): bool => str_starts_with($line, $marker)));
    }
}
