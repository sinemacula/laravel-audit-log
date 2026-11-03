<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * Keeps a record's encoded properties and context within their byte budgets,
 * measured on the complete JSON as it is stored, by omitting whole top-level
 * keys and never descending into one. The row is always kept.
 *
 * Each key's cost is computed once and the keys are sorted once, so the pass is
 * linear in the payload. Keys go by tier, then largest first, then bytewise on
 * the key, so the result depends on neither the order of the input nor anything
 * outside it. In the properties, keys no rule governs go first, then keys a
 * rule governs, itself or beneath it, and the note last of all. The identifier
 * hash, a bulk operation's manifest descriptor and the list of what was omitted
 * are never omitted, because all three are bounded: `METADATA_RESERVE_BYTES`
 * holds a hash, the largest descriptor and 32 paths of 128 bytes under the
 * largest count, so omitting until the rest fits beside that reserve brings the
 * final encoding within the budget, whatever the omissions themselves add. In
 * the context, which has no metadata and no reserve, application keys go before
 * the fixed names the package fills, and `_audit` is an ordinary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ByteBudget
{
    /** @var int Bytes kept for the identifier hash, the manifest descriptor and the omitted list at their largest, with their braces and a comma: 4515 measured, rounded up. */
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
     * The properties as they are stored, with `_audit` last, holding the note,
     * the identifier hash, the manifest descriptor and what was omitted, as
     * present, with top-level keys and then the note omitted until the final
     * encoding fits; `null` when nothing is left. The descriptor is the
     * package's own and is never omitted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<array-key, mixed>|string|null  $note
     * @param  ?string  $identifierHash
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  ?array{artifact_id: string, digest: string, count: int}  $manifest
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
     * The context as it is stored, with top-level keys omitted until its
     * encoding fits; `null` when nothing is left.
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
     * The values with the metadata after them, under `_audit`, in its fixed
     * order (the note, the identifier hash, the manifest descriptor, what was
     * omitted) and with only the parts present; the values alone when none is.
     * An integer key keeps its value: this assigns rather than merges.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<array-key, mixed>|string|null  $note
     * @param  ?string  $identifierHash
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  ?array{artifact_id: string, digest: string, count: int}  $manifest
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
     * One candidate for omission per key of the values, each with its tier and
     * its cost.
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
     * The candidates to omit: in order, those it takes for what remains to cost
     * no more than the limit.
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
     * Which of two candidates goes first: the lower tier, then the greater
     * cost, then the bytewise lesser key. Keys are unique within a tier, so the
     * order is total and does not depend on the input's.
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
     * What a key and its value add to the encoding: the encoded key, a colon,
     * the encoded value and a comma. The comma the last key does not have is
     * what makes this an upper bound.
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
     * How many bytes the value encodes to, with the flags it is stored with. A
     * failure is thrown anew, because the original's stack trace holds the
     * value as the argument of `json_encode()`, which cannot mark it sensitive.
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
