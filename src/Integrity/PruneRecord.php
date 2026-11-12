<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Signed evidence that some of a seal's entries were pruned on purpose. Its
 * HMAC is over a label distinct from a seal's, and a record never excuses a
 * seal that fails on its own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneRecord
{
    /** @var int The version of the record every prune is signed under. */
    public const int VERSION = 2;

    /** @var list<string> The fields of a stored record, the signature included, in the order of the constructor. */
    private const array FIELDS = ['log_id', 'seal_id', 'seal_digest', 'member_count', 'pruned', 'pruned_count', 'operation_id', 'pruned_at', 'key_id', 'signature'];

    /** @var list<string> The fields of a stored record that hold an integer. */
    private const array INTEGERS = ['member_count', 'pruned_count'];

    /** @var string What a refused digest field must be, after its name. */
    private const string DIGEST = ' must be 64 lower-case hexadecimal characters.';

    /** @var string What a refused UUID field must be, after its name. */
    private const string UUID = ' must be a lower-case UUID.';

    /** @var string What a refused log id must be. */
    private const string LOG_ID = 'A prune record\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string What a refused key id must be. */
    private const string KEY_ID = 'A prune record\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string What a refused member count must be. */
    private const string MEMBER_COUNT = 'A prune record\'s `member_count` must be from 1 to ' . SealEnvelope::MAX_MEMBERS . '.';

    /** @var string What a refused prune time must be. */
    private const string PRUNED_AT = 'A prune record\'s `pruned_at` must be ISO-8601 UTC with microseconds.';

    /** @var string What a refused bitmap must be. */
    private const string PRUNED = 'A prune record\'s `pruned` must be the canonical base64url bitmap of its `member_count` members.';

    /** @var string What a refused count must be. */
    private const string PRUNED_COUNT = 'A prune record\'s `pruned_count` must be the number of members its bitmap sets, at least 1.';

    /** @var string The bitmap's bytes, decoded once. */
    private string $bitmap;

    /**
     * Constructor.
     *
     * @param  string  $logId
     * @param  string  $sealId
     * @param  string  $sealDigest
     * @param  int  $memberCount
     * @param  string  $pruned
     * @param  int  $prunedCount
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

        /** The bitmap of the members this prune deleted, strict base64url of `ceil(memberCount / 8)` bytes. */
        public string $pruned,

        /** How many members the bitmap sets, at least 1. */
        public int $prunedCount,

        /** The id of the prune operation, a lower-case UUID. */
        public string $operationId,

        /** When the prune ran, ISO-8601 UTC with microseconds. */
        public string $prunedAt,

        /** The id of the ring key whose seal key signs the record. */
        public string $keyId,

        /** HMAC-SHA256, lower-case hex, over the digest of every other field. */
        public string $signature,
    ) {
        $problem = self::problemOf([$logId, $sealId, $sealDigest, $memberCount, $pruned, $prunedCount, $operationId, $prunedAt, $keyId, $signature]);

        if ($problem !== null) {
            throw new \InvalidArgumentException($problem);
        }

        $this->bitmap = PruneBitmap::decode($pruned, $memberCount);
    }

    /**
     * The record stored as its fields, the signature among them, as the ledger
     * reads it back: `v` must be 2, and every field must be there, of its type
     * and well formed, else the record cannot be read, naming the field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromArray(array $fields): self
    {
        if (($fields['v'] ?? null) !== self::VERSION) {
            throw new \UnexpectedValueException(sprintf('A stored prune record must be of version %d.', self::VERSION));
        }

        if (array_diff(array_map(strval(...), array_keys($fields)), ['v', ...self::FIELDS]) !== []) {
            throw new \UnexpectedValueException('A stored prune record must hold no field but those of its version.');
        }

        $values  = self::valuesOf($fields);
        $problem = self::problemOf($values);

        if ($problem !== null) {
            throw new \UnexpectedValueException($problem);
        }

        return new self(...$values);
    }

    /**
     * The fields the signature covers: every field but the signature.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{v: int, log_id: string, seal_id: string, seal_digest: string, member_count: int, pruned: string, pruned_count: int, operation_id: string, pruned_at: string, key_id: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'v'            => self::VERSION,
            'log_id'       => $this->logId,
            'seal_id'      => $this->sealId,
            'seal_digest'  => $this->sealDigest,
            'member_count' => $this->memberCount,
            'pruned'       => $this->pruned,
            'pruned_count' => $this->prunedCount,
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
     * The positions of the members this prune deleted, in member order.
     *
     * @return list<int>
     */
    public function positions(): array
    {
        return PruneBitmap::positions($this->bitmap, $this->memberCount);
    }

    /**
     * Whether this prune deleted the member at the position, in member order:
     * `false` for a position the seal does not hold.
     *
     * @param  int  $position
     * @return bool
     */
    public function covers(int $position): bool
    {
        return PruneBitmap::isSet($this->bitmap, $position);
    }

    /**
     * The values of a stored record's fields, in the order of the constructor,
     * each refused unless it is there and of its type, naming the field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return array{0: string, 1: string, 2: string, 3: int, 4: string, 5: int, 6: string, 7: string, 8: string, 9: string}
     *
     * @throws \UnexpectedValueException
     */
    private static function valuesOf(array $fields): array
    {
        $values = [];

        foreach (self::FIELDS as $field) {
            $value   = $fields[$field] ?? null;
            $integer = in_array($field, self::INTEGERS, true);

            if ($integer ? !is_int($value) : !is_string($value)) {
                throw new \UnexpectedValueException(sprintf('A stored prune record\'s `%s` must be %s.', $field, $integer ? 'an integer' : 'text'));
            }

            $values[] = $value;
        }

        /** @var array{0: string, 1: string, 2: string, 3: int, 4: string, 5: int, 6: string, 7: string, 8: string, 9: string} */
        return $values;
    }

    /**
     * Why the fields, in the order of the constructor, are refused: the first
     * that is not well formed, or `null` when every one is.
     *
     * @param  array{0: string, 1: string, 2: string, 3: int, 4: string, 5: int, 6: string, 7: string, 8: string, 9: string}  $values
     * @return ?string
     */
    private static function problemOf(array $values): ?string
    {
        [$logId, $sealId, $sealDigest, $memberCount, $pruned, $prunedCount, $operationId, $prunedAt, $keyId, $signature] = $values;

        $bitmap = self::bitmapOf($pruned, $memberCount);
        $holds  = [
            self::LOG_ID                                     => preg_match(SealEnvelope::LOG_ID_PATTERN, $logId)      === 1,
            'A prune record\'s `seal_id`' . self::UUID       => preg_match(SealEnvelope::UUID_PATTERN, $sealId)       === 1,
            'A prune record\'s `seal_digest`' . self::DIGEST => preg_match(SealEnvelope::DIGEST_PATTERN, $sealDigest) === 1,
            self::MEMBER_COUNT                               => $memberCount >= 1 && $memberCount <= SealEnvelope::MAX_MEMBERS,
            self::PRUNED                                     => $bitmap !== null,
            self::PRUNED_COUNT                               => $bitmap !== null && $prunedCount >= 1 && PruneBitmap::count($bitmap) === $prunedCount,
            'A prune record\'s `operation_id`' . self::UUID  => preg_match(SealEnvelope::UUID_PATTERN, $operationId)                 === 1,
            self::PRUNED_AT                                  => StoredTime::isInstant($prunedAt),
            self::KEY_ID                                     => preg_match(IntegrityKey::ID_PATTERN, $keyId)         === 1,
            'A prune record\'s `signature`' . self::DIGEST   => preg_match(SealEnvelope::DIGEST_PATTERN, $signature) === 1,
        ];

        return array_keys($holds, false, true)[0] ?? null;
    }

    /**
     * The bytes of the stored bitmap over the members, or `null` when it is not
     * their one canonical bitmap.
     *
     * @param  string  $pruned
     * @param  int  $memberCount
     * @return ?string
     */
    private static function bitmapOf(string $pruned, int $memberCount): ?string
    {
        try {
            return PruneBitmap::decode($pruned, $memberCount);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }
}
