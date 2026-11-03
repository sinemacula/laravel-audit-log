<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The signed evidence that a seal's entries were pruned on purpose: the log,
 * the seal's id and digest, how many members it holds, the id of the prune
 * operation and when it ran, and the signature that binds them.
 *
 * The signature is HMAC-SHA256 under the seal key of the ring key it names,
 * over a label distinct from a seal's and the digest of every other field, so a
 * record proves one prune of exactly one seal and is never mistaken for a
 * seal's signature. A lifecycle journal implements `PruneLedger` with it.
 * Verification checks the signature and every bound field against the seal, and
 * a missing entry counts as pruned only when both hold; a record never excuses
 * a seal that fails on its own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneRecord
{
    /** @var int The version of the record every prune is signed under. */
    public const int VERSION = 1;

    /** @var string What a refused digest field must be, after its name. */
    private const string DIGEST = ' must be 64 lower-case hexadecimal characters.';

    /** @var string What a refused UUID field must be, after its name. */
    private const string UUID = ' must be a lower-case UUID.';

    /** @var string What a refused log id must be. */
    private const string LOG_ID = 'A prune record\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string What a refused key id must be. */
    private const string KEY_ID = 'A prune record\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /**
     * Constructor.
     *
     * @param  string  $logId
     * @param  string  $sealId
     * @param  string  $sealDigest
     * @param  int  $memberCount
     * @param  string  $operationId
     * @param  string  $prunedAt
     * @param  string  $keyId
     * @param  string  $signature
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The log the pruned seal belongs to. */
        public string $logId,

        /** The id of the seal whose entries were pruned. */
        public string $sealId,

        /** The digest of the seal whose entries were pruned. */
        public string $sealDigest,

        /** How many members the seal holds, from 1 to `SealEnvelope::MAX_MEMBERS`. */
        public int $memberCount,

        /** The id of the prune operation, a lower-case UUID. */
        public string $operationId,

        /** When the prune ran, ISO-8601 UTC with microseconds. */
        public string $prunedAt,

        /** The id of the ring key whose seal key signs the record. */
        public string $keyId,

        /** HMAC-SHA256, lower-case hex, over the digest of every other field. */
        public string $signature,
    ) {
        self::check(preg_match(SealEnvelope::LOG_ID_PATTERN, $logId) === 1, self::LOG_ID);
        self::check(preg_match(SealEnvelope::UUID_PATTERN, $sealId) === 1, 'A prune record\'s `seal_id`' . self::UUID);
        self::check(preg_match(SealEnvelope::DIGEST_PATTERN, $sealDigest) === 1, 'A prune record\'s `seal_digest`' . self::DIGEST);
        self::check($memberCount >= 1 && $memberCount <= SealEnvelope::MAX_MEMBERS, 'A prune record\'s `member_count` must be from 1 to 50000.');
        self::check(preg_match(SealEnvelope::UUID_PATTERN, $operationId) === 1, 'A prune record\'s `operation_id`' . self::UUID);
        self::check(StoredTime::isInstant($prunedAt), 'A prune record\'s `pruned_at` must be ISO-8601 UTC with microseconds.');
        self::check(preg_match(IntegrityKey::ID_PATTERN, $keyId) === 1, self::KEY_ID);
        self::check(preg_match(SealEnvelope::DIGEST_PATTERN, $signature) === 1, 'A prune record\'s `signature`' . self::DIGEST);
    }

    /**
     * The fields the signature covers, each under its canonical key: every
     * field but the signature. The order is irrelevant: the canonical encoding
     * sorts the keys.
     *
     * @return array{v: int, log_id: string, seal_id: string, seal_digest: string, member_count: int, operation_id: string, pruned_at: string, key_id: string}
     */
    public function toArray(): array
    {
        return [
            'v'            => self::VERSION,
            'log_id'       => $this->logId,
            'seal_id'      => $this->sealId,
            'seal_digest'  => $this->sealDigest,
            'member_count' => $this->memberCount,
            'operation_id' => $this->operationId,
            'pruned_at'    => $this->prunedAt,
            'key_id'       => $this->keyId,
        ];
    }

    /**
     * The record's digest: SHA-256, in hex, over the canonical encoding of the
     * fields the signature covers, the signature left out.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function digest(): string
    {
        return hash('sha256', CanonicalEncoder::encode($this->toArray()));
    }

    /**
     * Refuse a field that does not hold, with the reason given.
     *
     * @param  bool  $holds
     * @param  string  $message
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function check(bool $holds, string $message): void
    {
        if (!$holds) {
            throw new \InvalidArgumentException($message);
        }
    }
}
