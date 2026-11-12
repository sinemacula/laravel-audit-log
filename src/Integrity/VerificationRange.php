<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The seals one verification covers: the whole log, or a range checked against
 * the head the run observes. Only the whole log is complete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationRange
{
    /** @var string Why an end of the range that is not a sequence is refused, by the option that gives it. */
    private const string NOT_A_SEQUENCE = 'The --%s option must be an integer from 1 to %d.';

    /** @var string Why an end of the range past the head is refused, by the option that gives it. */
    private const string BEYOND_THE_HEAD = '--%s is beyond the head of the log, seal %d.';

    /**
     * Constructor.
     *
     * @param  ?int  $from
     * @param  ?int  $to
     */
    public function __construct(

        /** The sequence of the first seal to verify, or `null` for the first of the chain. */
        public ?int $from = null,

        /** The sequence of the last seal to verify, or `null` for the head the run observes. */
        public ?int $to = null,
    ) {}

    /**
     * The whole log: every seal from the first to the head the run observes.
     *
     * @return self
     */
    public static function whole(): self
    {
        return new self;
    }

    /**
     * Whether the range is the whole log: neither end is given.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->from === null && $this->to === null;
    }

    /**
     * The first and last sequence to verify, against the head the run observed;
     * a log with no seal is the empty range from 1 to 0.
     *
     * @param  ?int  $head
     * @return array{0: int, 1: int}
     *
     * @throws \InvalidArgumentException
     */
    public function bounds(?int $head): array
    {
        self::checkSequence('from', $this->from);
        self::checkSequence('to', $this->to);

        if ($this->from !== null && $this->to !== null && $this->from > $this->to) {
            throw new \InvalidArgumentException('--from must not be after --to.');
        }

        if ($head === null) {
            return $this->isComplete() ? [1, 0] : throw new \InvalidArgumentException('The log has no seal to verify in a range.');
        }

        self::checkWithin('to', $this->to, $head);
        self::checkWithin('from', $this->from, $head);

        return [$this->from ?? 1, $this->to ?? $head];
    }

    /**
     * Refuse an end of the range that is given and is not a sequence, naming
     * the option that gives it.
     *
     * @param  'from'|'to'  $option
     * @param  ?int  $sequence
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkSequence(string $option, ?int $sequence): void
    {
        if ($sequence !== null && $sequence < 1) {
            throw new \InvalidArgumentException(sprintf(self::NOT_A_SEQUENCE, $option, PHP_INT_MAX));
        }
    }

    /**
     * Refuse an end of the range that is given and is beyond the head, naming
     * the option that gives it and the head.
     *
     * @param  'from'|'to'  $option
     * @param  ?int  $sequence
     * @param  int  $head
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkWithin(string $option, ?int $sequence, int $head): void
    {
        if ($sequence !== null && $sequence > $head) {
            throw new \InvalidArgumentException(sprintf(self::BEYOND_THE_HEAD, $option, $head));
        }
    }
}
