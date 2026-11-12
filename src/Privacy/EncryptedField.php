<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * An encrypted fragment of a stored entry as a field reader is handed it; only
 * the projector builds one, from a verified entry.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EncryptedField
{
    /** @var list<string> The keys of an envelope, sorted: exactly these and nothing else. */
    private const array ENVELOPE_KEYS = ['c', 'k', 'v'];

    /** @var string Where in the entry the fragment sits, as the dotted form of its segments. */
    public string $path;

    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $segments
     * @param  int  $version
     * @param  string  $keyReference
     * @param  string  $ciphertext
     */
    private function __construct(

        /** The id of the entry the fragment belongs to. */
        public string $entryId,

        /** Where in the entry the fragment sits: the column, then each map key and list index as `segment()` names it. */
        #[\SensitiveParameter]
        public array $segments,

        /** The envelope's version, from 1. */
        public int $version,

        /** The reference of the key that sealed it, never the key itself. */
        public string $keyReference,

        /** The ciphertext, exactly as stored. */
        #[\SensitiveParameter]
        public string $ciphertext,
    ) {
        $this->path = implode('.', $segments);
    }

    /**
     * The fragment the value holds when it is exactly a well-formed envelope,
     * or `null`; segments that are not a column then strings and indexes from 0
     * are refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $entryId
     * @param  array<array-key, mixed>  $segments
     * @param  array<array-key, mixed>|\stdClass  $envelope
     * @return ?self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function fromEnvelope(string $entryId, #[\SensitiveParameter] array $segments, #[\SensitiveParameter] array|\stdClass $envelope): ?self
    {
        if (!self::isSegmentList($segments)) {
            throw new \InvalidArgumentException('An encrypted field\'s segments must be its column, then strings and indexes from 0.');
        }

        $parts = self::parts($envelope);

        return $parts === null ? null : new self($entryId, $segments, $parts['v'], $parts['k'], $parts['c']);
    }

    /**
     * Whether the value is exactly a well-formed envelope, without building a
     * field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|\stdClass  $envelope
     * @return bool
     *
     * @internal
     */
    public static function isWellFormed(#[\SensitiveParameter] array|\stdClass $envelope): bool
    {
        return self::parts($envelope) !== null;
    }

    /**
     * The path segment of a member's key, an integer from 0 or a string, so it
     * holds whether minimisation stores the container as a list or a map.
     *
     * @param  int|string  $key
     * @return int|string
     *
     * @internal
     */
    public static function segment(#[\SensitiveParameter] int|string $key): int|string
    {
        return is_int($key) && $key >= 0 ? $key : (string) $key;
    }

    /**
     * The envelope's version, key reference and ciphertext when it is well
     * formed, or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|\stdClass  $envelope
     * @return ?array{v: int, k: string, c: string}
     */
    private static function parts(#[\SensitiveParameter] array|\stdClass $envelope): ?array
    {
        $parts = $envelope instanceof \stdClass ? get_object_vars($envelope) : $envelope;
        $keys  = array_map(strval(...), array_keys($parts));

        sort($keys);

        if ($keys !== self::ENVELOPE_KEYS) {
            return null;
        }

        ['v' => $version, 'k' => $keyReference, 'c' => $ciphertext] = $parts;

        if (!self::isVersion($version) || !self::isText($keyReference) || !self::isText($ciphertext)) {
            return null;
        }

        return ['v' => $version, 'k' => $keyReference, 'c' => $ciphertext];
    }

    /**
     * Whether the segments are a non-empty column, then strings and integers
     * from 0.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true non-empty-list<int|string> $segments
     *
     * @param  array<array-key, mixed>  $segments
     * @return bool
     */
    private static function isSegmentList(#[\SensitiveParameter] array $segments): bool
    {
        if (!array_is_list($segments) || !isset($segments[0]) || !is_string($segments[0]) || $segments[0] === '') {
            return false;
        }

        foreach ($segments as $segment) {
            if (!is_string($segment) && (!is_int($segment) || $segment < 0)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the value is an integer from 1 to the largest integer every
     * reader of the stored JSON keeps exactly.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true int $value
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isVersion(#[\SensitiveParameter] mixed $value): bool
    {
        return is_int($value) && $value >= 1 && $value <= ValueNormaliser::MAX_SAFE_INTEGER;
    }

    /**
     * Whether the value is a non-empty string that cleaning would not change.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true string $value
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isText(#[\SensitiveParameter] mixed $value): bool
    {
        return is_string($value) && $value !== '' && TextSanitizer::isClean($value);
    }
}
