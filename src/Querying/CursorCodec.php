<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Issues and opens the cursor of a page of the trail, version 1: `v1`, then the
 * key id, the payload and the MAC, each as unpadded base64url, separated by
 * dots. The payload is the canonical encoding of `{pos: [time, id]}`, the
 * position of the last entry a page showed, and the MAC is HMAC-SHA256 over the
 * binding's canonical input, the key id and the payload part exactly as sent,
 * under a key derived by HKDF-SHA256 from the secret of the ring key the key id
 * names, with an empty salt and an info string of its own, so it is never the
 * key that signs rows or seals.
 *
 * A cursor is issued under the ring's signing key and opened under the key it
 * names, so a cursor issued before a rotation still opens while its key stays
 * in the ring. Opening is bounded to 512 bytes, checks the MAC in constant time
 * before anything of the payload is decoded, decodes the payload to exactly one
 * key holding two strings, two levels deep and no deeper, and refuses every
 * failure, a key the ring does not hold included, with the one uniform
 * `InvalidCursorException`. It makes no query, reads no row and never expires a
 * cursor: the scope is answered again on every read, so a cursor can never
 * widen what a viewer sees. The derived key is made on every call and never
 * kept.
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

    /** @var int How many parts a cursor has: the version, the key id, the payload and the MAC. */
    private const int PARTS = 4;

    /** @var string A part after the version: one or more characters of the base64url alphabet, with no padding. */
    private const string PART_PATTERN = '/\A[A-Za-z0-9_-]+\z/';

    /** @var string The one key a payload holds. */
    private const string POSITION_KEY = 'pos';

    /** @var int How deep a payload is decoded: the map, its list and the list's strings, as PHP counts them. */
    private const int DEPTH = 3;

    /** @var int Length of every cursor key and MAC, in bytes. */
    private const int KEY_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose signing key issues a cursor and whose keys open one. */
        private KeyRing $keys,
    ) {}

    /**
     * The cursor of the position, bound to the read, under the ring's signing
     * key.
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
     * The position the cursor holds, once it is shown to have been issued for
     * the read, or the uniform refusal: longer than `MAX_BYTES`, not four
     * parts, the first `v1` and the others base64url, a key id that is not one
     * or that the ring does not hold, a MAC that is not 32 bytes or does not
     * match, and only then a payload that is not exactly a position.
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
     * The payload part of a cursor whose MAC matches the one computed for the
     * read under the key it names, or the refusal.
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
     * The ring's key with the id, or the refusal when the ring does not hold
     * it, so an unknown key is refused as any other cursor is.
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
     * The key id, payload and MAC parts of a cursor of at most `MAX_BYTES` that
     * is exactly four parts, the first `v1` and each other one or more
     * base64url characters, or the refusal. Nothing is decoded here.
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
     * The position an authenticated payload part holds, or the refusal when it
     * is not exactly a position's payload, or its position is not one.
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
     * The two strings of a payload that decodes strictly to exactly `{pos:
     * [string, string]}`, two levels deep and no deeper, and is the canonical
     * encoding of them, or `null` for any other payload.
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
     * The JSON decoded with objects as arrays, at most two levels deep, or
     * `null` when there is nothing to decode, it is not JSON or it nests
     * deeper.
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
     * The MAC of a cursor under the key's cursor key, as raw bytes, over the
     * binding's canonical input.
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
     * The bytes of a part that is the very unpadded base64url encoding of them,
     * so no two spellings decode alike, or `null` for any other part.
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
