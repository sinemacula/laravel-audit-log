<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

/**
 * One signal of `audit-log:check --freshness`: its status, its age and limit in
 * seconds, and whether it fails the run.
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
     * @param  ?string  $cause
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

        /** Why it failed without a run to judge, naming the class of what was thrown and never its message, or `null`. */
        public ?string $cause = null,
    ) {}

    /**
     * The signal as a line of text, with its age, limit and cause when it has
     * them.
     *
     * @return string
     */
    public function line(): string
    {
        $parts = [
            ...($this->ageSeconds === null ? [] : [sprintf('age %ds', $this->ageSeconds)]),
            ...($this->limitSeconds === null ? [] : [sprintf('limit %ds', $this->limitSeconds)]),
            ...($this->cause === null ? [] : [$this->cause]),
        ];

        return sprintf('[freshness] %s: %s', $this->signal, $this->status) . ($parts === [] ? '' : ' (' . implode(', ', $parts) . ')');
    }

    /**
     * The signal's fields for `--json`, without its cause.
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
