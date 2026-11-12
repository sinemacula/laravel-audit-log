<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The keyed fingerprint an owner is named by in the journal: HMAC-SHA256 of its
 * type and id under a key of its own derived by HKDF. Anyone with the ring and
 * the owner's reference can recompute it, so it is personal data while
 * linkable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnerFingerprint
{
    /** @var string HKDF info of every fingerprint key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:owner:v1';

    /** @var int Length of every fingerprint key, in bytes. */
    private const int KEY_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose signing key fingerprints and whose keys reproduce a fingerprint. */
        private KeyRing $keys,
    ) {}

    /**
     * The fingerprint key of a ring key's secret, as 32 raw bytes.
     *
     * @param  string  $secret
     * @return string
     */
    public static function key(#[\SensitiveParameter] string $secret): string
    {
        return hash_hkdf('sha256', $secret, self::KEY_BYTES, self::DERIVATION_INFO, '');
    }

    /**
     * The id of the ring's signing key, and the owner's fingerprint under it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return array{0: string, 1: string}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function of(#[\SensitiveParameter] Reference $owner): array
    {
        $key = $this->keys->signingKey();

        return [$key->id, self::fingerprint($owner, $key)];
    }

    /**
     * The owner's fingerprint under the ring key with the id.
     *
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return string
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function under(string $keyId, #[\SensitiveParameter] Reference $owner): string
    {
        return self::fingerprint($owner, $this->keys->key($keyId));
    }

    /**
     * HMAC-SHA256, as lower-case hex, of the owner's canonical encoding under
     * the fingerprint key of the ring key given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function fingerprint(#[\SensitiveParameter] Reference $owner, #[\SensitiveParameter] IntegrityKey $key): string
    {
        return hash_hmac('sha256', CanonicalEncoder::encode([$owner->type, $owner->id]), self::key($key->secret()));
    }
}
