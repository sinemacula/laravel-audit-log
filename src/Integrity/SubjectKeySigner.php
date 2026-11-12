<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Signs and verifies an owner's key row under a key derived from a ring key by
 * HKDF, so its HMAC is never another structure's signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectKeySigner
{
    /** @var string HKDF info of every key row key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:subject-key:v1';

    /** @var string What every key row's HMAC covers before its digest. */
    public const string LABEL = "audit-log:subject-key:v1\n";

    /** @var int Length of every key row key, in bytes. */
    private const int KEY_BYTES = 32;

    /** @var string The HMAC a row is given before it is signed, so its key id can be checked; never stored. */
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
     * The key row key of a ring key's secret, as 32 raw bytes.
     *
     * @param  string  $secret
     * @return string
     */
    public static function key(#[\SensitiveParameter] string $secret): string
    {
        return hash_hkdf('sha256', $secret, self::KEY_BYTES, self::DERIVATION_INFO, '');
    }

    /**
     * The digest a key row's HMAC covers: SHA-256, in hex, of the canonical
     * encoding of its signed fields.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function digest(#[\SensitiveParameter] SubjectKeyRow $keyRow): string
    {
        return hash('sha256', CanonicalEncoder::encode($keyRow->signedFields()));
    }

    /**
     * The row signed under the key row key of the ring's signing key, which the
     * row then names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $draft
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function sign(#[\SensitiveParameter] SubjectKeyRow $draft): SubjectKeyRow
    {
        $key = $this->keys->signingKey();

        // The key id is signed, so the row names it before the digest is taken
        $named = $draft->withSignature($key->id, self::UNSIGNED);

        return $draft->withSignature($key->id, self::hmac($named, $key));
    }

    /**
     * Whether the row's HMAC is its own, under the key the row names; an
     * unsigned row or an unknown key is refused instead.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $signed
     * @return bool
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function verifies(#[\SensitiveParameter] SubjectKeyRow $signed): bool
    {
        self::checkHmac($signed->hmac);

        return hash_equals(self::hmac($signed, $this->keys->key($signed->keyId)), $signed->hmac);
    }

    /**
     * HMAC-SHA256, as lower-case hex, of the label and the row's digest under
     * the key row key of the ring key given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function hmac(#[\SensitiveParameter] SubjectKeyRow $keyRow, #[\SensitiveParameter] IntegrityKey $key): string
    {
        return hash_hmac('sha256', self::LABEL . self::digest($keyRow), self::key($key->secret()));
    }

    /**
     * Refuse an HMAC that is not 64 lower-case hex, such as an unsigned row's
     * empty one.
     *
     * @param  string  $hmac
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function checkHmac(string $hmac): void
    {
        if (preg_match(SealEnvelope::DIGEST_PATTERN, $hmac) !== 1) {
            throw new \UnexpectedValueException('Only a signed subject key row is verified.');
        }
    }
}
