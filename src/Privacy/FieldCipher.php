<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use Random\RandomException;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * Seals a field's typed plaintext under an owner's data key, and opens it, as
 * AES-256-GCM envelope version 1.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FieldCipher
{
    /** @var int The envelope version this cipher seals and opens. */
    public const int VERSION = 1;

    /** @var int Length of a nonce, in bytes: 96 bits. */
    public const int NONCE_BYTES = 12;

    /** @var int Length of a tag, in bytes: 128 bits. */
    public const int TAG_BYTES = 16;

    /** @var int Length of a data key, in bytes. */
    public const int DATA_KEY_BYTES = 32;

    /** @var string The cipher every envelope is sealed with. */
    private const string CIPHER = 'aes-256-gcm';

    /** @var string The domain the additional data names, so it is never another structure's. */
    private const string DOMAIN = 'sinemacula/audit-log:field:v1';

    /** @var string HKDF info of every field key. */
    private const string FIELD_KEY_INFO = 'sinemacula/audit-log:field-key:v1';

    /** @var string Refusal for an envelope that does not open; names nothing of it. */
    private const string UNOPENED = 'The envelope does not open under its key at its entry and path.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The typed plaintext sealed as an envelope bound to the entry, path and
     * log, under a nonce drawn here so no caller can repeat one.
     *
     * @param  string  $dataKey
     * @param  string  $keyId
     * @param  string  $plaintext
     * @param  string  $entryId
     * @param  array<array-key, int|string>  $path
     * @param  string  $logId
     * @return array{v: int, k: string, c: string}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public static function seal(
        #[\SensitiveParameter]
        string $dataKey,
        string $keyId,
        #[\SensitiveParameter]
        string $plaintext,
        string $entryId,
        #[\SensitiveParameter]
        array $path,
        string $logId,
    ): array {
        if ($plaintext === '' || strlen($plaintext) > TypedPlaintext::MAX_BYTES) {
            throw new \InvalidArgumentException(sprintf('A plaintext must be from 1 to %d bytes.', TypedPlaintext::MAX_BYTES));
        }

        $fieldKey       = self::fieldKey($dataKey, $entryId);
        $additionalData = self::additionalData($logId, $keyId, self::VERSION, $entryId, $path);
        $nonce          = self::nonce();
        $tag            = '';

        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $fieldKey, OPENSSL_RAW_DATA, $nonce, $tag, $additionalData, self::TAG_BYTES);

        if ($ciphertext === false) {
            throw new \UnexpectedValueException('The plaintext could not be sealed.');
        }

        return ['v' => self::VERSION, 'k' => $keyId, 'c' => self::base64url($nonce . $ciphertext . $tag)];
    }

    /**
     * The typed plaintext an envelope holds, opened at the entry, path and log
     * it was sealed for.
     *
     * @param  string  $dataKey
     * @param  string  $keyId
     * @param  int  $version
     * @param  string  $ciphertext
     * @param  string  $entryId
     * @param  array<array-key, int|string>  $path
     * @param  string  $logId
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function open(
        #[\SensitiveParameter]
        string $dataKey,
        string $keyId,
        int $version,
        #[\SensitiveParameter]
        string $ciphertext,
        string $entryId,
        #[\SensitiveParameter]
        array $path,
        string $logId,
    ): string {
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(self::UNOPENED);
        }

        $sealed         = self::decoded($ciphertext);
        $fieldKey       = self::fieldKey($dataKey, $entryId);
        $additionalData = self::additionalData($logId, $keyId, $version, $entryId, $path);
        $body           = substr($sealed, self::NONCE_BYTES, -self::TAG_BYTES);

        $plaintext = openssl_decrypt($body, self::CIPHER, $fieldKey, OPENSSL_RAW_DATA, substr($sealed, 0, self::NONCE_BYTES), substr($sealed, -self::TAG_BYTES), $additionalData);

        if ($plaintext === false) {
            throw new \UnexpectedValueException(self::UNOPENED);
        }

        return $plaintext;
    }

    /**
     * The additional data an envelope is authenticated with.
     *
     * @param  string  $logId
     * @param  string  $keyId
     * @param  int  $version
     * @param  string  $entryId
     * @param  array<array-key, int|string>  $path
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function additionalData(string $logId, string $keyId, int $version, string $entryId, #[\SensitiveParameter] array $path): string
    {
        if ($path === [] || !array_is_list($path)) {
            throw new \InvalidArgumentException('A field\'s path must be a non-empty list.');
        }

        return CanonicalEncoder::encode(['d' => self::DOMAIN, 'entry' => $entryId, 'k' => $keyId, 'log' => $logId, 'path' => $path, 'v' => $version]);
    }

    /**
     * The key one entry's fields are sealed under, keeping each derived key far
     * below AES-GCM's random-nonce bound.
     *
     * @param  string  $dataKey
     * @param  string  $entryId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function fieldKey(#[\SensitiveParameter] string $dataKey, string $entryId): string
    {
        if (strlen($dataKey) !== self::DATA_KEY_BYTES) {
            throw new \InvalidArgumentException(sprintf('A data key must be %d bytes.', self::DATA_KEY_BYTES));
        }

        return hash_hkdf('sha256', $dataKey, self::DATA_KEY_BYTES, self::FIELD_KEY_INFO, $entryId);
    }

    /**
     * The bytes a ciphertext encodes, refused unless it is canonical unpadded
     * base64url of a nonce, a 1 to 1024 byte plaintext and a tag.
     *
     * @param  string  $ciphertext
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function decoded(#[\SensitiveParameter] string $ciphertext): string
    {
        $sealed = base64_decode(strtr($ciphertext, '-_', '+/'), true);

        if (!is_string($sealed) || self::base64url($sealed) !== $ciphertext) {
            throw new \UnexpectedValueException(self::UNOPENED);
        }

        $length = strlen($sealed);

        if ($length <= self::NONCE_BYTES + self::TAG_BYTES || $length > self::NONCE_BYTES + TypedPlaintext::MAX_BYTES + self::TAG_BYTES) {
            throw new \UnexpectedValueException(self::UNOPENED);
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
