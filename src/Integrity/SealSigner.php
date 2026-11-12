<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Signs and verifies seals and prune records under a key derived from a ring
 * key by HKDF, so a row's HMAC is never a seal's signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealSigner
{
    /** @var string HKDF info of every seal key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:seal:v1';

    /** @var string What a seal's signature covers before the seal digest. */
    public const string SEAL_LABEL = "audit-log:seal:v1\n";

    /** @var string What a prune record's signature covers before the record's digest. */
    public const string PRUNE_LABEL = "audit-log:prune:v2\n";

    /** @var int Length of every seal key, in bytes. */
    private const int SEAL_KEY_BYTES = 32;

    /** @var string The signature a prune record is built with before it is signed; never stored. */
    private const string UNSIGNED = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose signing key signs and whose keys verify. */
        private KeyRing $keys,
    ) {}

    /**
     * The seal key of a ring key's secret, as 32 raw bytes.
     *
     * @param  string  $secret
     * @return string
     */
    public static function sealKey(#[\SensitiveParameter] string $secret): string
    {
        return hash_hkdf('sha256', $secret, self::SEAL_KEY_BYTES, self::DERIVATION_INFO, '');
    }

    /**
     * The id of the ring's signing key, which a new seal names.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function signingKeyId(): string
    {
        return $this->keys->signingKey()->id;
    }

    /**
     * The seal's signature, under the seal key of the ring key the envelope
     * names, which need not be the current one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return string
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function sign(SealEnvelope $seal): string
    {
        return self::signature(self::SEAL_LABEL, $seal->digest(), $this->keys->key($seal->keyId));
    }

    /**
     * Whether the signature is the seal's, under the key the envelope names; a
     * malformed signature or an unknown key is refused instead.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $signature
     * @return bool
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function verifies(SealEnvelope $seal, string $signature): bool
    {
        self::checkSignature($signature);

        return hash_equals(self::signature(self::SEAL_LABEL, $seal->digest(), $this->keys->key($seal->keyId)), $signature);
    }

    /**
     * The prune record of the members of a seal the bitmap sets, signed under
     * the seal key of the ring's signing key.
     *
     * @param  string  $logId
     * @param  string  $sealId
     * @param  string  $sealDigest
     * @param  int  $memberCount
     * @param  string  $pruned
     * @param  int  $prunedCount
     * @param  string  $operationId
     * @param  string  $prunedAt
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     *
     * @SuppressWarnings("php:S107")
     */
    public function signPrune(
        string $logId,
        string $sealId,
        string $sealDigest,
        int $memberCount,
        string $pruned,
        int $prunedCount,
        string $operationId,
        string $prunedAt,
    ): PruneRecord {
        $key = $this->keys->signingKey();

        // Built unsigned first, so its fields are checked and its digest taken
        $unsigned  = new PruneRecord($logId, $sealId, $sealDigest, $memberCount, $pruned, $prunedCount, $operationId, $prunedAt, $key->id, self::UNSIGNED);
        $signature = self::signature(self::PRUNE_LABEL, $unsigned->digest(), $key);

        return new PruneRecord($logId, $sealId, $sealDigest, $memberCount, $pruned, $prunedCount, $operationId, $prunedAt, $key->id, $signature);
    }

    /**
     * Whether the prune record's signature matches, under the key the record
     * names; an unknown key is refused instead.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return bool
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function verifiesPrune(PruneRecord $record): bool
    {
        return hash_equals(self::signature(self::PRUNE_LABEL, $record->digest(), $this->keys->key($record->keyId)), $record->signature);
    }

    /**
     * HMAC-SHA256, as lower-case hex, of the label and the digest under the
     * seal key of the ring key given.
     *
     * @param  string  $label
     * @param  string  $digest
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @return string
     */
    private static function signature(string $label, string $digest, #[\SensitiveParameter] IntegrityKey $key): string
    {
        return hash_hmac('sha256', $label . $digest, self::sealKey($key->secret()));
    }

    /**
     * Refuse a stored signature that is not 64 lower-case hex: no key could
     * have made it.
     *
     * @param  string  $signature
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function checkSignature(string $signature): void
    {
        if (preg_match(SealEnvelope::DIGEST_PATTERN, $signature) !== 1) {
            throw new \UnexpectedValueException('A seal\'s `signature` must be 64 lower-case hexadecimal characters.');
        }
    }
}
