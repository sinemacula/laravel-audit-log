<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * Why an erasure must keep one key of an owner: the key, its unit's digest and
 * its generation, and every reason it is blocked, each once and sorted
 * bytewise. A reason is `held:<hold id>`, when an active hold of the verified
 * chain matches an entry the key encrypted; `preserved:<category>`, when such
 * an entry is still within its category's preservation; or `unverified`, when
 * such an entry fails its HMAC, so what it says cannot decide a destruction.
 *
 * A block names no owner and no value of any entry: key ids are opaque, a
 * unit's digest is unkeyed but names nothing on its own, and hold ids and
 * categories are the operator's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, int|list<string>|string>
 */
final readonly class ErasureBlock implements Arrayable
{
    /** @var string The reason an entry that fails its HMAC gives. */
    public const string UNVERIFIED = 'unverified';

    /** @var string What the reason an active hold gives starts with, before the hold's id. */
    public const string HELD = 'held:';

    /** @var string What the reason preservation gives starts with, before the category. */
    public const string PRESERVED = 'preserved:';

    /** @var non-empty-list<string> Every reason the key is blocked, each once, sorted bytewise. */
    public array $reasons;

    /**
     * Constructor.
     *
     * @param  string  $keyId
     * @param  string  $unit
     * @param  int  $generation
     * @param  list<string>  $reasons
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the key that is kept. */
        public string $keyId,

        /** The digest of the key's unit. */
        public string $unit,

        /** The key's generation. */
        public int $generation,

        // Every reason the key is blocked, in any order and with repeats.
        array $reasons,
    ) {
        $unique = array_values(array_unique($reasons));

        if ($unique === []) {
            throw new \InvalidArgumentException('An erasure block names at least one reason.');
        }

        sort($unique, SORT_STRING);

        $this->reasons = $unique;
    }

    /**
     * What an erasure row lists of the kept key: its id, its unit's digest, its
     * generation and its reasons.
     *
     * @return array{key_id: string, unit: string, generation: int, reasons: non-empty-list<string>}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'key_id'     => $this->keyId,
            'unit'       => $this->unit,
            'generation' => $this->generation,
            'reasons'    => $this->reasons,
        ];
    }
}
