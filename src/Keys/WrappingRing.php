<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

/**
 * The wrapping keys owners' data keys are wrapped and unwrapped with, rebuilt
 * from the settings on every call and never cached.
 *
 * Without an explicit ring, `app.key` and each of `app.previous_keys` are
 * derived by HKDF-SHA256 under an info string of their own, never the integrity
 * ring's: the key derived from `app.key` wraps, and the others only unwrap what
 * they wrapped before a rotation. A derived key's id is `d-` and the first 16
 * hex characters of a fingerprint of its secret, so a rotated `app.key` gets a
 * new id and the keys wrapped before it keep theirs.
 *
 * With an explicit ring (`audit-log.privacy.keys`), `audit-log.privacy.current`
 * wraps, and nothing is ever wrapped under a derived key again; a malformed
 * explicit ring fails closed and never falls back to them. The keys derived
 * from `app.key` and `app.previous_keys` stay in the ring to unwrap only, so
 * the keys wrapped before the explicit ring was set still unwrap and
 * `audit-log:rewrap` moves them onto the current key; an application key that
 * is missing or malformed then adds no derived key and refuses nothing. An
 * explicit key whose id a derived key also has is the one the ring holds.
 *
 * The derivation separates the wrapping keys from every other key the
 * application key gives; it does not make them independent of it, and anyone
 * holding `app.key` holds the derived wrapping keys too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WrappingRing
{
    /** @var string HKDF info of every derived wrapping key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:subject-wrap:v1';

    /** @var string Message the derived key id fingerprints. */
    private const string KEY_ID_LABEL = 'audit-log:wrap-key-id';

    /** @var int Length of every derived secret, in bytes. */
    private const int DERIVED_SECRET_BYTES = 32;

    /** @var string Prefix of every derived key id. */
    private const string DERIVED_ID_PREFIX = 'd-';

    /** @var int Hex characters of the fingerprint a derived key id keeps. */
    private const int FINGERPRINT_LENGTH = 16;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeySettings  $settings
     */
    public function __construct(

        /** The settings the ring is built from on every call. */
        private KeySettings $settings,
    ) {}

    /**
     * The key that wraps: the current key of an explicit ring, or the key
     * derived from `app.key`.
     *
     * @return \SineMacula\Laravel\AuditLog\Keys\WrappingKey
     *
     * @throws \InvalidArgumentException
     */
    public function current(): WrappingKey
    {
        [$current, $keys] = $this->ring();

        return $keys[$current];
    }

    /**
     * The key of the ring with the id, wrapping or unwrapping only. Malformed
     * settings fail closed with the settings' `InvalidArgumentException` before
     * any key is looked up.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Keys\WrappingKey
     *
     * @throws \SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException
     */
    public function key(string $id): WrappingKey
    {
        return $this->ring()[1][$id] ?? throw UnknownWrappingKeyException::forKey($id);
    }

    /**
     * The id of every key of the ring, the key that wraps first.
     *
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function ids(): array
    {
        [$current, $keys] = $this->ring();

        return array_values(array_unique([(string) $current, ...array_map(strval(...), array_keys($keys))]));
    }

    /**
     * The id of the key that wraps, and every key of the ring by its id: the
     * explicit ring with its current key, then the keys derived from the
     * application keys to unwrap only; or the keys derived from `app.key` and
     * each of `app.previous_keys`, the first wrapping.
     *
     * @return array{0: int|string, 1: non-empty-array<int|string, \SineMacula\Laravel\AuditLog\Keys\WrappingKey>}
     *
     * @throws \InvalidArgumentException
     */
    private function ring(): array
    {
        $current = $this->settings->currentKeyId();
        $keys    = [];

        if ($current !== null) {
            foreach ($this->settings->explicitKeys() as $id => $secret) {
                $keys[$id] = new WrappingKey((string) $id, $secret);
            }

            foreach ($this->historicalKeys() as $key) {
                $keys[$key->id] ??= $key;
            }

            /** @var non-empty-array<int|string, \SineMacula\Laravel\AuditLog\Keys\WrappingKey> $keys */
            return [$current, $keys];
        }

        foreach ($this->settings->applicationKeys() as $applicationKey) {
            $key = self::derive($applicationKey);

            $keys[$key->id] ??= $key;
        }

        return [array_key_first($keys), $keys];
    }

    /**
     * The keys derived from `app.key` and each of `app.previous_keys`, which an
     * explicit ring keeps to unwrap only; none when the application keys are
     * missing or malformed, since an explicit ring needs none of them.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Keys\WrappingKey>
     */
    private function historicalKeys(): array
    {
        try {
            return array_map(self::derive(...), $this->settings->applicationKeys());
        } catch (\InvalidArgumentException) {
            return [];
        }
    }

    /**
     * The key derived from an application key: its secret is HKDF-SHA256 of the
     * key's bytes under the derivation info, and its id the fingerprint of that
     * secret.
     *
     * @param  string  $applicationKey
     * @return \SineMacula\Laravel\AuditLog\Keys\WrappingKey
     *
     * @throws \InvalidArgumentException
     */
    private static function derive(#[\SensitiveParameter] string $applicationKey): WrappingKey
    {
        $secret = hash_hkdf('sha256', $applicationKey, self::DERIVED_SECRET_BYTES, self::DERIVATION_INFO, '');
        $id     = self::DERIVED_ID_PREFIX . substr(hash_hmac('sha256', self::KEY_ID_LABEL, $secret), 0, self::FINGERPRINT_LENGTH);

        return new WrappingKey($id, $secret);
    }
}
