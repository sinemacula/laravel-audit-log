<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * An encrypted fragment of a stored entry, as a field reader is handed it: the
 * entry it belongs to, where in the entry it sits, and the envelope it was
 * sealed in, its version, the reference of the key that sealed it and the
 * ciphertext.
 *
 * Its path is `ip` for an address stored under the `encrypt` mode, and
 * otherwise the column, `properties` or `context`, followed by the dotted path
 * of keys down to the envelope, with a list's indexes as digits. An envelope is
 * held to the rules it was sealed under: a version from 1 to the largest
 * integer every reader of the stored JSON keeps exactly, and a key reference
 * and a ciphertext that are non-empty clean text.
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

    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  string  $path
     * @param  int  $version
     * @param  string  $keyReference
     * @param  string  $ciphertext
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the entry the fragment belongs to. */
        public string $entryId,

        /** Where in the entry the fragment sits: `ip`, or the column and the dotted path of keys down to it. */
        #[\SensitiveParameter]
        public string $path,

        /** The envelope's version, from 1. */
        public int $version,

        /** The reference of the key that sealed it, never the key itself. */
        public string $keyReference,

        /** The ciphertext, exactly as stored. */
        #[\SensitiveParameter]
        public string $ciphertext,
    ) {
        if (!self::isVersion($version)) {
            throw new \InvalidArgumentException(sprintf('An encrypted field\'s version must be an integer from 1 to %d.', ValueNormaliser::MAX_SAFE_INTEGER));
        }

        if (!self::isText($keyReference) || !self::isText($ciphertext)) {
            throw new \InvalidArgumentException('An encrypted field\'s key reference and ciphertext must be non-empty clean text.');
        }
    }

    /**
     * The fragment the value holds when it is exactly an envelope, of exactly
     * `v`, `k` and `c` in any order, each as its rules require, or `null` for
     * any other value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $entryId
     * @param  string  $path
     * @param  array<array-key, mixed>|\stdClass  $envelope
     * @return ?self
     */
    public static function fromEnvelope(string $entryId, #[\SensitiveParameter] string $path, #[\SensitiveParameter] array|\stdClass $envelope): ?self
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

        return new self($entryId, $path, $version, $keyReference, $ciphertext);
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
     * Whether the value is a non-empty string that cleaning would not change,
     * as the sealer required of it when it was stored.
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
