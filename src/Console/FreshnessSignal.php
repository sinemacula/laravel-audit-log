<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

/**
 * One signal of `audit-log:check --freshness`: what it watches, its status, how
 * old what it last recorded is and how old it may grow, each in seconds, and
 * whether it is a problem.
 *
 * A status is `ok`, `stale`, `failed`, `never_run` or `not_applicable`. A stale
 * or failed signal is always a problem, and one that never ran is a problem
 * only when its run is scheduled and the log's oldest entry is older than its
 * limit. An age or a limit the signal has none of is `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessSignal
{
    /** @var string What it last recorded is within its limit. */
    public const string OK = 'ok';

    /** @var string What it last recorded is older than its limit. */
    public const string STALE = 'stale';

    /** @var string What it last recorded says it failed. */
    public const string FAILED = 'failed';

    /** @var string It has recorded nothing. */
    public const string NEVER_RUN = 'never_run';

    /** @var string Nothing is configured for it to watch. */
    public const string NOT_APPLICABLE = 'not_applicable';

    /**
     * Constructor.
     *
     * @param  string  $signal
     * @param  string  $status
     * @param  ?int  $ageSeconds
     * @param  ?int  $limitSeconds
     * @param  bool  $problem
     */
    public function __construct(

        /** What the signal watches: `sealing`, `sweep`, `verification`, `retention`, `anchoring` or `outbox`. */
        public string $signal,

        /** The status, one of the constants above. */
        public string $status,

        /** How old what it last recorded is, in seconds, or `null` when it has recorded nothing. */
        public ?int $ageSeconds,

        /** How old what it records may grow, in seconds, or `null` when it has no limit. */
        public ?int $limitSeconds,

        /** Whether the signal fails the run. */
        public bool $problem,
    ) {}

    /**
     * The signal as a line of text: its name, its status and, when it has them,
     * its age and its limit.
     *
     * @return string
     */
    public function line(): string
    {
        $parts = [
            ...($this->ageSeconds === null ? [] : [sprintf('age %ds', $this->ageSeconds)]),
            ...($this->limitSeconds === null ? [] : [sprintf('limit %ds', $this->limitSeconds)]),
        ];

        return sprintf('[freshness] %s: %s', $this->signal, $this->status) . ($parts === [] ? '' : ' (' . implode(', ', $parts) . ')');
    }

    /**
     * The signal's closed list of fields, for `--json`.
     *
     * @return array{signal: string, status: string, age_seconds: ?int, limit_seconds: ?int}
     */
    public function toArray(): array
    {
        return [
            'signal'        => $this->signal,
            'status'        => $this->status,
            'age_seconds'   => $this->ageSeconds,
            'limit_seconds' => $this->limitSeconds,
        ];
    }
}
