<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Thrown when sealing refuses to chain onto the last seal: its stored digest is
 * not the digest of its fields, so extending it would build on a seal that has
 * been altered, or it belongs to another log id, so one chain would mix two.
 * Either is evidence for verification to report, not a failure to retry.
 *
 * It names the last seal's id and the finding it gives, and never carries
 * another exception, so nothing it holds can reach an entry.
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

    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     */
    private function __construct(

        // Why no seal is chained onto the last one.
        string $message,

        /** The id of the last seal, which no seal is chained onto. */
        public readonly string $sealId,

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
}
