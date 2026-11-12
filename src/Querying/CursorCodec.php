<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Issues and opens a page cursor: `v1.<key id>.<payload>.<mac>` in unpadded
 * base64url, the MAC under an HKDF-derived key never used to sign rows.
 *
 * Opening checks the MAC in constant time before decoding the payload, and
 * every failure is the one uniform `InvalidCursorException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CursorCodec
{
    /** @var int Longest cursor opened, in bytes. */
    public const int MAX_BYTES = 512;

    /** @var string The version part every cursor starts with. */
    public const string VERSION = 'v1';

    /** @var string HKDF info of every cursor key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:cursor:v1';

    /** @var string What separates the parts of a cursor. */
    private const string SEPARATOR = '.';

    /** @var int The version, the key id, the payload and the MAC. */
    private const int PARTS = 4;

    /** @var string Unpadded base64url. */
    private const string PART_PATTERN = '/\A[A-Za-z0-9_-]+\z/';

    /** @var string The one key a payload holds. */
    private const string POSITION_KEY = 'pos';

    /** @var int The map, its list and the list's strings, as PHP counts depth. */
    private const int DEPTH = 3;

    /** @var int Length of every cursor key and MAC, in bytes. */
    private const int KEY_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** Issues under its signing key; opens under any key it still holds. */
        private KeyRing $keys,
    ) {}

    /**
     * The cursor of the position, bound to the read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $binding
     * @param  \SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function issue(CursorBinding $binding, Position $position): string
    {
        $key     = $this->keys->signingKey();
        $payload = self::encode(CanonicalEncoder::encode([self::POSITION_KEY => $position->toArray()]));

        return implode(self::SEPARATOR, [self::VERSION, self::encode($key->id), $payload, self::encode(self::mac($key, $binding, $payload))]);
    }

    /**
     * The position the cursor holds, once shown to be issued for the read.
     *
     * @param  string  $cursor
     * @param  \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $binding
     * @return \SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    public function open(string $cursor, CursorBinding $binding): Position
    {
        return self::position($this->authenticated(self::parts($cursor), $binding));
    }

    /**
     * The payload part of a cursor whose MAC matches the read's.
     *
     * @param  array{0: string, 1: string, 2: string}  $parts
     * @param  \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $binding
     * @return string
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private function authenticated(array $parts, CursorBinding $binding): string
    {
        [$keyPart, $payload, $macPart] = $parts;

        $keyId = self::decode($keyPart);

        if ($keyId === null || preg_match(IntegrityKey::ID_PATTERN, $keyId) !== 1) {
            throw InvalidCursorException::refused();
        }

        $key = $this->keyOf($keyId);
        $mac = self::decode($macPart);

        if ($mac === null || strlen($mac) !== self::KEY_BYTES || !hash_equals(self::mac($key, $binding, $payload), $mac)) {
            throw InvalidCursorException::refused();
        }

        return $payload;
    }

    /**
     * The ring's key with the id; an unknown key gets the uniform refusal.
     *
     * @param  string  $keyId
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private function keyOf(string $keyId): IntegrityKey
    {
        try {
            return $this->keys->key($keyId);
        } catch (UnknownKeyException) {
            throw InvalidCursorException::refused();
        }
    }

    /**
     * The key id, payload and MAC parts of a well-formed cursor, undecoded.
     *
     * @param  string  $cursor
     * @return array{0: string, 1: string, 2: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private static function parts(string $cursor): array
    {
        if (strlen($cursor) > self::MAX_BYTES) {
            throw InvalidCursorException::refused();
        }

        $parts = explode(self::SEPARATOR, $cursor);

        if (count($parts) !== self::PARTS || $parts[0] !== self::VERSION) {
            throw InvalidCursorException::refused();
        }

        $encoded = [$parts[1], $parts[2], $parts[3]];

        foreach ($encoded as $part) {
            if (preg_match(self::PART_PATTERN, $part) !== 1) {
                throw InvalidCursorException::refused();
            }
        }

        return $encoded;
    }

    /**
     * The position an authenticated payload part holds.
     *
     * @param  string  $payload
     * @return \SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private static function position(#[\SensitiveParameter] string $payload): Position
    {
        $pair = self::pair(self::decode($payload));

        if ($pair === null) {
            throw InvalidCursorException::refused();
        }

        try {
            return new Position(...$pair);
        } catch (\InvalidArgumentException) {
            throw InvalidCursorException::refused();
        }
    }

    /**
     * The two strings of a payload that is exactly the canonical encoding of
     * `{pos: [string, string]}`, or `null`.
     *
     * @param  ?string  $json
     * @return ?array{0: string, 1: string}
     *
     * @throws \UnexpectedValueException
     */
    private static function pair(#[\SensitiveParameter] ?string $json): ?array
    {
        $decoded = self::decoded($json);

        if (!is_array($decoded) || array_keys($decoded) !== [self::POSITION_KEY]) {
            return null;
        }

        $position = $decoded[self::POSITION_KEY];

        if (!is_array($position) || array_keys($position) !== [0, 1] || !is_string($position[0]) || !is_string($position[1])) {
            return null;
        }

        $pair = [$position[0], $position[1]];

        return CanonicalEncoder::encode([self::POSITION_KEY => $pair]) === $json ? $pair : null;
    }

    /**
     * The JSON decoded to at most `DEPTH`, or `null` when it cannot be.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?string  $json
     * @return mixed
     */
    private static function decoded(#[\SensitiveParameter] ?string $json): mixed
    {
        if ($json === null) {
            return null;
        }

        try {
            return json_decode($json, true, self::DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * The raw MAC of a cursor under the key's derived cursor key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @param  \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $binding
     * @param  string  $payload
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function mac(IntegrityKey $key, CursorBinding $binding, #[\SensitiveParameter] string $payload): string
    {
        $cursorKey = hash_hkdf('sha256', $key->secret(), self::KEY_BYTES, self::DERIVATION_INFO, '');

        return hash_hmac('sha256', $binding->macInput($key->id, $payload), $cursorKey, true);
    }

    /**
     * Encode bytes as unpadded base64url.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The bytes of a canonically encoded part, so no two spellings decode
     * alike, or `null`.
     *
     * @param  string  $part
     * @return ?string
     */
    private static function decode(string $part): ?string
    {
        $bytes = base64_decode(strtr($part, '-_', '+/'), true);

        return $bytes !== false && self::encode($bytes) === $part ? $bytes : null;
    }
}
