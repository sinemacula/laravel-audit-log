<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * Why an erasure must keep one of an owner's keys; it names no owner and no
 * value of any entry.
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
    /** @var string The reason of an entry that fails its HMAC. */
    public const string UNVERIFIED = 'unverified';

    /** @var string The prefix of a hold's reason, before the hold id. */
    public const string HELD = 'held:';

    /** @var string The prefix of a preservation reason, before the category. */
    public const string PRESERVED = 'preserved:';

    /** @var non-empty-list<string> The distinct reasons, sorted bytewise. */
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

        // Not promoted: deduplicated and sorted into $this->reasons.
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
     * What an erasure row lists of the kept key.
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
