<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Thrown when the last seal or the journal's head is not safe to chain onto. It
 * names the finding and the last seal's id, never an entry's value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SealChainException extends \UnexpectedValueException
{
    /** @var string The message when the last seal's stored digest disagrees with its fields. */
    private const string HEAD_MESSAGE = 'The last seal\'s stored digest does not match its fields, so no seal is chained onto it; run audit-log:verify.';

    /** @var string The message when the last seal belongs to another log id. */
    private const string LOG_MESSAGE = 'The last seal belongs to another log id, so no seal is chained onto it; the log id must not change once a seal exists.';

    /** @var string The message when the lifecycle journal's last row cannot be read. */
    private const string JOURNAL_MESSAGE = 'The lifecycle journal\'s last row has a malformed sequence or HMAC, so no seal commits to it; run audit-log:verify.';

    /** @var string The message when the lifecycle journal's head is behind the last seal's commitment to it. */
    private const string BEHIND_MESSAGE = 'The lifecycle journal\'s head is behind the last seal\'s commitment to it, so no seal commits to it; run audit-log:verify.';

    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  ?string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     */
    private function __construct(

        // Why no seal is chained onto the last one.
        string $message,

        /** The id of the last seal, which no seal is chained onto, or `null` when the journal's head is refused. */
        public readonly ?string $sealId,

        /** The finding the refusal gives. */
        public readonly Finding $finding,
    ) {
        parent::__construct($message);
    }

    /**
     * The exception for a last seal whose stored digest is not the digest of
     * its fields.
     *
     * @param  string  $sealId
     * @return self
     */
    public static function forHead(string $sealId): self
    {
        return new self(self::HEAD_MESSAGE, $sealId, Finding::SEAL_DIGEST);
    }

    /**
     * The exception for a last seal that belongs to another log id.
     *
     * @param  string  $sealId
     * @return self
     */
    public static function forLog(string $sealId): self
    {
        return new self(self::LOG_MESSAGE, $sealId, Finding::LOG_MISMATCH);
    }

    /**
     * The exception for a journal whose last row cannot be read.
     *
     * @return self
     */
    public static function forJournal(): self
    {
        return new self(self::JOURNAL_MESSAGE, null, Finding::JOURNAL_MALFORMED);
    }

    /**
     * The exception for a journal whose head is behind the last seal's
     * commitment, so its tail was removed or replaced.
     *
     * @param  string  $sealId
     * @return self
     */
    public static function forJournalBehind(string $sealId): self
    {
        return new self(self::BEHIND_MESSAGE, $sealId, Finding::JOURNAL_COMMITMENT);
    }
}
