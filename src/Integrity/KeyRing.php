<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The integrity keys rows are signed and verified with, rebuilt from the
 * settings on every call and never cached.
 *
 * With an explicit ring (`audit-log.integrity.keys`), the ring is exactly those
 * keys and `audit-log.integrity.current` signs; `app.key` and
 * `app.previous_keys` are then never read, so a malformed explicit ring fails
 * closed and never falls back to them. Without one, `app.key` and each of
 * `app.previous_keys` are derived by HKDF-SHA256 under one info string: the key
 * derived from `app.key` signs, and the others verify only. A derived key's id
 * is `d` and the first 16 hex characters of a fingerprint of its secret, so a
 * rotated `app.key` gets a new id and the older rows keep theirs.
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

    /** @var string Prefix of every derived key id. */
    private const string DERIVED_ID_PREFIX = 'd';

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
     * The key of the ring with the id, signing or verifying only. Malformed
     * settings fail closed with the settings' `InvalidArgumentException` before
     * any key is looked up.
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
        $id     = self::DERIVED_ID_PREFIX . substr(hash_hmac('sha256', self::KEY_ID_LABEL, $secret), 0, self::FINGERPRINT_LENGTH);

        return new IntegrityKey($id, $secret);
    }
}
