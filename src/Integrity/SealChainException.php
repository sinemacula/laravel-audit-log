<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Thrown when sealing refuses to chain onto the last seal: its stored digest is
 * not the digest of its fields, so extending it would build on a seal that has
 * been altered, or it belongs to another log id, so one chain would mix two. It
 * is thrown too when the lifecycle journal's last row cannot be read, since a
 * seal never commits to a row it cannot name, and when the journal's head is
 * behind the last seal's commitment, since commitments never run backwards.
 * Each is evidence for verification to report, not a failure to retry.
 *
 * It names the last seal's id, when the refusal is of the last seal, and the
 * finding it gives, and never carries another exception, so nothing it holds
 * can reach an entry.
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
     * The exception for a lifecycle journal whose last row has a sequence or an
     * HMAC that cannot be read, which names no value of the row.
     *
     * @return self
     */
    public static function forJournal(): self
    {
        return new self(self::JOURNAL_MESSAGE, null, Finding::JOURNAL_MALFORMED);
    }

    /**
     * The exception for a lifecycle journal whose head is behind the last
     * seal's commitment to it: a lower sequence, none at all, or another row at
     * the committed sequence, so its tail was removed or replaced.
     *
     * @param  string  $sealId
     * @return self
     */
    public static function forJournalBehind(string $sealId): self
    {
        return new self(self::BEHIND_MESSAGE, $sealId, Finding::JOURNAL_COMMITMENT);
    }
}
