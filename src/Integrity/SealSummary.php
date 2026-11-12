<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The tuple an anchor binds for one seal. Its digest covers every immutable
 * field, so binding it binds the whole seal and its link to the one before.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SealSummary
{
    /** @var int The version of the summary every anchor binds. */
    public const int VERSION = 1;

    /**
     * Constructor.
     *
     * @param  string  $logId
     * @param  int  $sequence
     * @param  string  $sealId
     * @param  string  $sealDigest
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The log the seal belongs to. */
        public string $logId,

        /** The seal's place in the chain, at least 1. */
        public int $sequence,

        /** The seal's id, a lower-case UUID. */
        public string $sealId,

        /** The seal's digest, 64 lower-case hex. */
        public string $sealDigest,
    ) {
        if (preg_match(SealEnvelope::LOG_ID_PATTERN, $logId) !== 1) {
            throw new \InvalidArgumentException('A seal summary\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if ($sequence < 1) {
            throw new \InvalidArgumentException('A seal summary\'s `sequence` must be at least 1.');
        }

        if (preg_match(SealEnvelope::UUID_PATTERN, $sealId) !== 1) {
            throw new \InvalidArgumentException('A seal summary\'s `seal_id` must be a lower-case UUID.');
        }

        if (preg_match(SealEnvelope::DIGEST_PATTERN, $sealDigest) !== 1) {
            throw new \InvalidArgumentException('A seal summary\'s `seal_digest` must be 64 lower-case hexadecimal characters.');
        }
    }

    /**
     * The summary of the seal under a digest the caller recomputed from its
     * fields.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(SealEnvelope $seal, string $digest): self
    {
        return new self($seal->logId, $seal->sequence, $seal->id, $digest);
    }

    /**
     * The summary under its canonical keys, as an anchor stores it.
     *
     * @return array{v: int, log_id: string, sequence: int, seal_id: string, seal_digest: string}
     */
    public function toArray(): array
    {
        return [
            'v'           => self::VERSION,
            'log_id'      => $this->logId,
            'sequence'    => $this->sequence,
            'seal_id'     => $this->sealId,
            'seal_digest' => $this->sealDigest,
        ];
    }

    /**
     * Whether the other summary binds the same tuple.
     *
     * @param  self  $other
     * @return bool
     */
    public function isSameAs(self $other): bool
    {
        return $this->logId      === $other->logId
            && $this->sequence   === $other->sequence
            && $this->sealId     === $other->sealId
            && $this->sealDigest === $other->sealDigest;
    }
}
