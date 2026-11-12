<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * Keeps a record's encoded properties and context within their byte budgets by
 * omitting whole top-level keys; the row is always kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ByteBudget
{
    /** @var int Bytes kept for the bounded metadata at its largest: 4535 measured with a `disclosure` descriptor, rounded up. */
    public const int METADATA_RESERVE_BYTES = 4600;

    /** @var int How far the context's costs must stay under its budget: its two braces, less the last key's comma. */
    private const int CONTEXT_OVERHEAD_BYTES = 1;

    /** @var string The key the package's metadata sits under, last in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The key the note sits under in the metadata. */
    private const string NOTE_KEY = 'note';

    /** @var string The key the manifest descriptor sits under in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /** @var string The path an omitted note is reported under. */
    private const string NOTE_PATH = '_audit.note';

    /** @var int Tier of a property no rule governs and of an application's context key: the first to go. */
    private const int TIER_FIRST = 0;

    /** @var int Tier of a property a rule governs and of a context key the package fills. */
    private const int TIER_SECOND = 1;

    /** @var int Bytes of a cost that are the colon after the key and the comma after the value. */
    private const int PUNCTUATION_BYTES = 2;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The properties as stored, `_audit` last, with top-level keys and then the
     * note omitted until the encoding fits; `null` when nothing is left.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<array-key, mixed>|string|null  $note
     * @param  ?string  $identifierHash
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  ?array{artifact_id: string, kind: string, digest: string, count: int}  $manifest
     * @return ?array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public static function properties(
        #[\SensitiveParameter]
        array $values,
        #[\SensitiveParameter]
        array|string|null $note,
        ?string $identifierHash,
        EventDefinition $definition,
        int $maxBytes,
        OmissionLog $omissions,
        ?array $manifest = null,
    ): ?array {
        $composed = self::compose($values, $note, $identifierHash, $omissions, $manifest);

        if (self::encodedLength($composed) <= $maxBytes) {
            return self::nullWhenEmpty($composed);
        }

        $candidates = self::candidates(
            $values,
            static fn (#[\SensitiveParameter] int|string $key): int => self::isGoverned($key, $definition) ? self::TIER_SECOND : self::TIER_FIRST,
        );
        $limit    = $maxBytes - self::METADATA_RESERVE_BYTES;
        $noteCost = $note === null ? 0 : self::cost(self::NOTE_KEY, $note);

        // Every key leaves before the note, so the keys must fit beside it
        foreach (self::omitted($candidates, $limit - $noteCost) as $candidate) {
            unset($values[$candidate['key']]);

            $omissions->add(PathMasker::property([$candidate['key']], $definition));
        }

        if ($noteCost > $limit) {
            $note = null;

            $omissions->add(self::NOTE_PATH);
        }

        return self::nullWhenEmpty(self::compose($values, $note, $identifierHash, $omissions, $manifest));
    }

    /**
     * The context as stored, with top-level keys omitted until it fits; `null`
     * when nothing is left.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return ?array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public static function context(#[\SensitiveParameter] array $values, int $maxBytes, OmissionLog $omissions): ?array
    {
        if (self::encodedLength($values) <= $maxBytes) {
            return self::nullWhenEmpty($values);
        }

        $candidates = self::candidates($values, static fn (#[\SensitiveParameter] int|string $key): int => self::isPackageName($key) ? self::TIER_SECOND : self::TIER_FIRST);

        foreach (self::omitted($candidates, $maxBytes - self::CONTEXT_OVERHEAD_BYTES) as $candidate) {
            unset($values[$candidate['key']]);

            $omissions->add(PathMasker::context([$candidate['key']]));
        }

        return self::nullWhenEmpty($values);
    }

    /**
     * The values with the metadata parts present under `_audit`, assigned
     * rather than merged so an integer key keeps its value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<array-key, mixed>|string|null  $note
     * @param  ?string  $identifierHash
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  ?array{artifact_id: string, kind: string, digest: string, count: int}  $manifest
     * @return array<array-key, mixed>
     */
    private static function compose(
        #[\SensitiveParameter]
        array $values,
        #[\SensitiveParameter]
        array|string|null $note,
        ?string $identifierHash,
        OmissionLog $omissions,
        ?array $manifest,
    ): array {
        $metadata = [];

        if ($note !== null) {
            $metadata[self::NOTE_KEY] = $note;
        }

        if ($identifierHash !== null) {
            $metadata['identifier_hash'] = $identifierHash;
        }

        if ($manifest !== null) {
            $metadata[self::MANIFEST_KEY] = $manifest;
        }

        $omitted = $omissions->toArray();

        if ($omitted !== null) {
            $metadata['omitted'] = $omitted;
        }

        if ($metadata !== []) {
            $values[self::METADATA_KEY] = $metadata;
        }

        return $values;
    }

    /**
     * One omission candidate per key, with its tier and cost.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \Closure(int|string): int  $tierOf
     * @return list<array{key: int|string, tier: int, cost: int}>
     *
     * @throws \JsonException
     */
    private static function candidates(#[\SensitiveParameter] array $values, \Closure $tierOf): array
    {
        $candidates = [];

        foreach ($values as $key => $value) {
            $candidates[] = ['key' => $key, 'tier' => $tierOf($key), 'cost' => self::cost((string) $key, $value)];
        }

        return $candidates;
    }

    /**
     * Whether a rule governs the top-level key: it decides the key, or it names
     * a field beneath it.
     *
     * @param  int|string  $key
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return bool
     */
    private static function isGoverned(#[\SensitiveParameter] int|string $key, EventDefinition $definition): bool
    {
        return $definition->ruleFor([$key]) !== null || $definition->ruleBeneath([$key]) !== null;
    }

    /**
     * Whether the context key is one of the fixed names the package fills.
     *
     * @param  int|string  $key
     * @return bool
     */
    private static function isPackageName(#[\SensitiveParameter] int|string $key): bool
    {
        return in_array((string) $key, PathMasker::CONTEXT_NAMES, true);
    }

    /**
     * The candidates to omit, in order, until what remains costs no more than
     * the limit.
     *
     * @param  list<array{key: int|string, tier: int, cost: int}>  $candidates
     * @param  int  $limit
     * @return list<array{key: int|string, tier: int, cost: int}>
     */
    private static function omitted(#[\SensitiveParameter] array $candidates, int $limit): array
    {
        usort($candidates, static fn (#[\SensitiveParameter] array $a, #[\SensitiveParameter] array $b): int => self::order($a, $b));

        $remaining = array_sum(array_column($candidates, 'cost'));
        $omitted   = [];

        foreach ($candidates as $candidate) {
            if ($remaining <= $limit) {
                return $omitted;
            }

            $remaining -= $candidate['cost'];
            $omitted[] = $candidate;
        }

        return $omitted;
    }

    /**
     * Which of two candidates goes first: lower tier, then greater cost, then
     * bytewise lesser key, so the order never depends on the input's.
     *
     * @param  array{key: int|string, tier: int, cost: int}  $a
     * @param  array{key: int|string, tier: int, cost: int}  $b
     * @return int
     */
    private static function order(#[\SensitiveParameter] array $a, #[\SensitiveParameter] array $b): int
    {
        $order = [$a['tier'], $b['cost']] <=> [$b['tier'], $a['cost']];

        return $order !== 0 ? $order : strcmp((string) $a['key'], (string) $b['key']);
    }

    /**
     * What a key and its value add to the encoding, an upper bound since the
     * last key has no comma.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return int
     *
     * @throws \JsonException
     */
    private static function cost(#[\SensitiveParameter] string $key, #[\SensitiveParameter] mixed $value): int
    {
        return self::encodedLength($key) + self::encodedLength($value) + self::PUNCTUATION_BYTES;
    }

    /**
     * How many bytes the value encodes to; a failure is thrown anew, since the
     * original's trace holds the value unmarked.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return int
     *
     * @throws \JsonException
     */
    private static function encodedLength(#[\SensitiveParameter] mixed $value): int
    {
        try {
            return strlen(json_encode($value, CanonicalEncoder::JSON_FLAGS));
        } catch (\JsonException) {
            throw new \JsonException('A value that cannot be encoded cannot be measured.');
        }
    }

    /**
     * The values, or `null` when there are none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return ?array<array-key, mixed>
     */
    private static function nullWhenEmpty(#[\SensitiveParameter] array $values): ?array
    {
        return $values === [] ? null : $values;
    }
}
