<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Random\RandomException;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;

/**
 * The package's key wrapper: AES-256-GCM under a key of the wrapping ring, with
 * the context as additional data so a wrapped key unwraps only beside its own
 * row.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LocalKeyWrapper implements KeyWrapper
{
    /** @var int Length of a data key, in bytes. */
    public const int DATA_KEY_BYTES = 32;

    /** @var int Length of a nonce, in bytes: 96 bits. */
    public const int NONCE_BYTES = 12;

    /** @var int Length of a tag, in bytes: 128 bits. */
    public const int TAG_BYTES = 16;

    /** @var string HKDF info of the AES key a wrapping key's secret gives. */
    public const string AES_KEY_INFO = 'sinemacula/audit-log:wrap-key:v1';

    /** @var string The cipher every data key is wrapped with. */
    private const string CIPHER = 'aes-256-gcm';

    /** @var string A wrapped key's alphabet: base64url, with no padding. */
    private const string BASE64URL_PATTERN = '/\A[A-Za-z0-9_-]+\z/';

    /** @var string Refusal for a key that does not unwrap; names nothing of the text, key or context. */
    private const string UNWRAPPED = 'The wrapped key does not unwrap under its wrapping key and context.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\WrappingRing  $ring
     */
    public function __construct(

        /** The wrapping ring, read on every call. */
        private WrappingRing $ring,
    ) {}

    /**
     * The id of the ring's current wrapping key.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function currentKeyId(): string
    {
        return $this->ring->current()->id;
    }

    /**
     * The 32-byte data key wrapped under the ring key with the id and a fresh
     * nonce, bound to the context.
     *
     * @param  string  $dataKey
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException
     */
    #[\Override]
    public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
    {
        return self::encrypt($dataKey, $this->ring->key($wrapKeyId), $context);
    }

    /**
     * The data key the wrapped text holds, authenticated against the context.
     *
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return string
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException
     */
    #[\Override]
    public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
    {
        $sealed = self::decoded($wrapped);

        return self::decrypt($sealed, $this->ring->key($wrapKeyId), $context);
    }

    /**
     * The data key encrypted with a fresh nonce, as base64url of the nonce,
     * ciphertext and tag.
     *
     * @param  string  $dataKey
     * @param  \SineMacula\Laravel\AuditLog\Keys\WrappingKey  $key
     * @param  string  $context
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function encrypt(#[\SensitiveParameter] string $dataKey, #[\SensitiveParameter] WrappingKey $key, string $context): string
    {
        if (strlen($dataKey) !== self::DATA_KEY_BYTES) {
            throw new \InvalidArgumentException(sprintf('A data key must be %d bytes.', self::DATA_KEY_BYTES));
        }

        $nonce = self::nonce();
        $tag   = '';

        $ciphertext = openssl_encrypt($dataKey, self::CIPHER, self::aesKey($key), OPENSSL_RAW_DATA, $nonce, $tag, $context, self::TAG_BYTES);

        if ($ciphertext === false) {
            throw new \UnexpectedValueException('The data key could not be wrapped.');
        }

        return self::base64url($nonce . $ciphertext . $tag);
    }

    /**
     * The data key the decoded text holds, authenticated against the context.
     *
     * @param  string  $sealed
     * @param  \SineMacula\Laravel\AuditLog\Keys\WrappingKey  $key
     * @param  string  $context
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function decrypt(#[\SensitiveParameter] string $sealed, #[\SensitiveParameter] WrappingKey $key, string $context): string
    {
        $nonce = substr($sealed, 0, self::NONCE_BYTES);
        $tag   = substr($sealed, -self::TAG_BYTES);

        $dataKey = openssl_decrypt(substr($sealed, self::NONCE_BYTES, self::DATA_KEY_BYTES), self::CIPHER, self::aesKey($key), OPENSSL_RAW_DATA, $nonce, $tag, $context);

        if ($dataKey === false) {
            throw new \UnexpectedValueException(self::UNWRAPPED);
        }

        return $dataKey;
    }

    /**
     * The AES key derived from the wrapping secret, so the secret itself is
     * never another algorithm's key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\WrappingKey  $key
     * @return string
     */
    private static function aesKey(#[\SensitiveParameter] WrappingKey $key): string
    {
        return hash_hkdf('sha256', $key->secret(), self::DATA_KEY_BYTES, self::AES_KEY_INFO, '');
    }

    /**
     * The bytes a wrapped text encodes, refused unless it is unpadded base64url
     * of exactly a nonce, a 32-byte key and a tag.
     *
     * @param  string  $wrapped
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function decoded(#[\SensitiveParameter] string $wrapped): string
    {
        $sealed = preg_match(self::BASE64URL_PATTERN, $wrapped) === 1 ? base64_decode(strtr($wrapped, '-_', '+/'), true) : false;

        if (!is_string($sealed) || strlen($sealed) !== self::NONCE_BYTES + self::DATA_KEY_BYTES + self::TAG_BYTES) {
            throw new \UnexpectedValueException(self::UNWRAPPED);
        }

        return $sealed;
    }

    /**
     * A fresh nonce from the system's random source.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function nonce(): string
    {
        try {
            return random_bytes(self::NONCE_BYTES);
        } catch (RandomException) {
            throw new \UnexpectedValueException('A nonce could not be drawn.');
        }
    }

    /**
     * The bytes in base64url, with no padding.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function base64url(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
