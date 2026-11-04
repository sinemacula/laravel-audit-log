<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Support\Arrayable;

/**
 * What a page disclosed of the encrypted fragments of its entries: whether its
 * scope revealed them, and how many it showed in each state, `encrypted`,
 * `erased`, `revealed` and `unreadable`. It counts fragments, never names one,
 * and holds nothing a fragment holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, int>
 */
final readonly class FieldDisclosure implements Arrayable
{
    /**
     * Constructor.
     *
     * @param  bool  $reveal
     * @param  int  $encrypted
     * @param  int  $erased
     * @param  int  $revealed
     * @param  int  $unreadable
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Whether the page's scope revealed the encrypted fields. */
        public bool $reveal,

        /** How many fragments were shown sealed as `encrypted`. */
        public int $encrypted,

        /** How many fragments were shown as `erased`, their owner's keys destroyed. */
        public int $erased,

        /** How many fragments were shown as the value the field reader revealed. */
        public int $revealed,

        /** How many fragments were shown as `unreadable`. */
        public int $unreadable,
    ) {
        if (min($encrypted, $erased, $revealed, $unreadable) < 0) {
            throw new \InvalidArgumentException('A page\'s disclosure counts each state\'s fragments from none.');
        }
    }

    /**
     * The disclosure of a page that showed no encrypted fragment, under a scope
     * that revealed them or not: a denied or failed page's, or one whose
     * entries hold none.
     *
     * @param  bool  $reveal
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function none(bool $reveal): self
    {
        return new self($reveal, 0, 0, 0, 0);
    }

    /**
     * How many fragments were shown in each state, by the state's name, sorted.
     *
     * @return array{encrypted: int, erased: int, revealed: int, unreadable: int}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'encrypted'  => $this->encrypted,
            'erased'     => $this->erased,
            'revealed'   => $this->revealed,
            'unreadable' => $this->unreadable,
        ];
    }
}
