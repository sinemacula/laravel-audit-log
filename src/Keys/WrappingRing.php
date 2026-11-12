<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

/**
 * The wrapping keys, rebuilt on every call: an explicit ring when set, plus the
 * keys derived from the application keys, which then only unwrap.
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
     * The ring key with the id; malformed settings fail closed before any
     * lookup.
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
     * The id of the key that wraps, and every ring key by id; an explicit key
     * wins over a derived key with the same id.
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
     * The keys derived from the application keys, or none when they are missing
     * or malformed, since an explicit ring needs none.
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
     * The key derived from an application key, its id a fingerprint of its
     * secret so a rotated `app.key` gets a new id.
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
