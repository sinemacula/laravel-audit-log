<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The integrity keys, rebuilt from the settings on every call. An explicit ring
 * is exactly its keys and never falls back to `app.key`; otherwise each key is
 * derived by HKDF from `app.key`, which signs, or `app.previous_keys`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyRing
{
    /** @var string HKDF info of every derived key. */
    private const string DERIVATION_INFO = 'sinemacula/audit-log:integrity:v1';

    /** @var string Message the derived key id fingerprints. */
    private const string KEY_ID_LABEL = 'audit-log:key-id';

    /** @var int Length of every derived secret, in bytes. */
    private const int DERIVED_SECRET_BYTES = 32;

    /** @var int Hex characters of the fingerprint a derived key id keeps. */
    private const int FINGERPRINT_LENGTH = 16;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegritySettings  $settings
     */
    public function __construct(

        /** The settings the ring is built from on every call. */
        private IntegritySettings $settings,
    ) {}

    /**
     * The key that signs: the current key of an explicit ring, or the key
     * derived from `app.key`.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function signingKey(): IntegrityKey
    {
        $current = $this->settings->currentKeyId();

        if ($current === null) {
            return self::derive($this->settings->applicationKeys()[0]);
        }

        return $this->explicitKey($current);
    }

    /**
     * The ring's key with the id, signing or verifying only; malformed settings
     * fail closed before any lookup.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function key(string $id): IntegrityKey
    {
        if ($this->settings->currentKeyId() !== null) {
            return $this->explicitKey($id);
        }

        foreach ($this->settings->applicationKeys() as $applicationKey) {

            $key = self::derive($applicationKey);

            if ($key->id === $id) {
                return $key;
            }
        }

        throw UnknownKeyException::forKey($id);
    }

    /**
     * The key of the explicit ring with the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function explicitKey(string $id): IntegrityKey
    {
        foreach ($this->settings->explicitKeys() as $keyId => $secret) {
            if ((string) $keyId === $id) {
                return new IntegrityKey($id, $secret);
            }
        }

        throw UnknownKeyException::forKey($id);
    }

    /**
     * The key derived from an application key: its secret is HKDF-SHA256 of the
     * key's bytes under the derivation info, and its id the fingerprint of that
     * secret.
     *
     * @param  string  $applicationKey
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey
     *
     * @throws \InvalidArgumentException
     */
    private static function derive(#[\SensitiveParameter] string $applicationKey): IntegrityKey
    {
        $secret = hash_hkdf('sha256', $applicationKey, self::DERIVED_SECRET_BYTES, self::DERIVATION_INFO, '');
        $id     = 'd' . substr(hash_hmac('sha256', self::KEY_ID_LABEL, $secret), 0, self::FINGERPRINT_LENGTH);

        return new IntegrityKey($id, $secret);
    }
}
