<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * The keys a record's encryption envelopes name, as the key uses index them:
 * the distinct `k` of every value that is exactly an envelope, at any depth of
 * the properties and the context, and of an IP address stored as one, kept when
 * it is a canonical lower-case UUID, the form every key the package creates
 * has, and sorted bytewise.
 *
 * A value is an envelope exactly when the read path reads it as one: a map of
 * `v`, `k` and `c` and nothing else, in any order, `v` an integer from 1 to the
 * largest integer every reader of the stored JSON keeps exactly, and `k` and
 * `c` non-empty clean text. An envelope is a leaf: nothing inside it is read.
 * An IP address is one when it begins `{` and decodes, one level deep, to a map
 * that is. Whatever encrypter sealed an envelope it is found alike, so a key
 * use never misses an envelope the reader would show. An envelope the
 * application shaped itself never reaches a stored record: minimisation removes
 * every value that is exactly an envelope from the properties and the context a
 * record is given, before anything is sealed (`Privacy\RecordMinimiser`), so
 * every envelope a record holds is one its own sealer made, and no key use
 * links an entry to a key that sealed nothing in it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnvelopeKeys
{
    /** @var string A canonical lower-case UUID: the only form of a key a key use names. */
    public const string KEY_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var list<string> The keys of an envelope, sorted: exactly these and nothing else. */
    private const array ENVELOPE_MEMBERS = ['c', 'k', 'v'];

    /** @var int How deep an IP address's JSON is decoded: one map of scalars. */
    private const int IP_DEPTH = 2;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The distinct keys, sorted bytewise, of every envelope in the properties
     * and the context, at any depth of arrays and objects, and of an IP address
     * stored as one, each a canonical lower-case UUID.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $properties
     * @param  mixed  $context
     * @param  ?string  $ip
     * @return list<string>
     */
    public static function of(#[\SensitiveParameter] mixed $properties, #[\SensitiveParameter] mixed $context, #[\SensitiveParameter] ?string $ip): array
    {
        $keys = [];

        self::collect($properties, $keys);
        self::collect($context, $keys);
        self::collectIp($ip, $keys);

        $found = array_keys($keys);

        sort($found, SORT_STRING);

        return $found;
    }

    /**
     * The distinct keys, sorted bytewise, of every envelope the record holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return list<string>
     */
    public static function ofRecord(#[\SensitiveParameter] AuditRecord $record): array
    {
        return self::of($record->properties, $record->context, $record->ip);
    }

    /**
     * Whether the members are exactly an envelope: `v`, `k` and `c` and nothing
     * else, `v` an integer from 1 to the largest every reader keeps exactly,
     * and `k` and `c` non-empty clean text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true array{v: int, k: string, c: string} $members
     *
     * @param  array<array-key, mixed>  $members
     * @return bool
     */
    public static function isEnvelope(#[\SensitiveParameter] array $members): bool
    {
        $names = array_map(strval(...), array_keys($members));

        sort($names);

        if ($names !== self::ENVELOPE_MEMBERS) {
            return false;
        }

        return self::isVersion($members['v']) && self::isText($members['k']) && self::isText($members['c']);
    }

    /**
     * Gather the key of the value when it is an envelope, and otherwise of
     * every envelope its members hold, at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  array<string, true>  $keys
     * @return void
     */
    private static function collect(#[\SensitiveParameter] mixed $value, array &$keys): void
    {
        if (!$value instanceof \stdClass && !is_array($value)) {
            return;
        }

        $members = $value instanceof \stdClass ? get_object_vars($value) : $value;

        if (self::isEnvelope($members)) {
            self::keep($members['k'], $keys);

            return;
        }

        foreach ($members as $member) {
            self::collect($member, $keys);
        }
    }

    /**
     * Gather the key of an IP address stored as an envelope: one that begins
     * `{` and decodes, one level deep, to a map that is exactly one.
     *
     * @param  ?string  $ip
     * @param  array<string, true>  $keys
     * @return void
     */
    private static function collectIp(#[\SensitiveParameter] ?string $ip, array &$keys): void
    {
        if ($ip === null || !str_starts_with($ip, '{')) {
            return;
        }

        $decoded = json_decode($ip, false, self::IP_DEPTH);

        if (!$decoded instanceof \stdClass) {
            return;
        }

        $members = get_object_vars($decoded);

        if (!self::isEnvelope($members)) {
            return;
        }

        self::keep($members['k'], $keys);
    }

    /**
     * Keep the key when it is a canonical lower-case UUID.
     *
     * @param  string  $key
     * @param  array<string, true>  $keys
     * @return void
     */
    private static function keep(string $key, array &$keys): void
    {
        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            return;
        }

        $keys[$key] = true;
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
