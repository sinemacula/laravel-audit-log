<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * One page of the trail, newest first: the entries shown, at most the page
 * size, and the cursor that opens the next page when there is one. A page never
 * says how many entries there are in all.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TrailPage
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\TrailEntry>  $entries
     * @param  ?string  $nextCursor
     * @param  int  $perPage
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function __construct(

        /** The entries shown, newest first. */
        #[\SensitiveParameter]
        public array $entries,

        /** The cursor that opens the next page, or `null` on the last. */
        public ?string $nextCursor,

        /** The most entries a page of this read shows. */
        public int $perPage,
    ) {
        if ($perPage < 1 || count($entries) > $perPage) {
            throw new \InvalidArgumentException('A page shows from none to its page size of entries, and its page size is at least 1.');
        }
    }

    /**
     * A page showing nothing, with no next page: a denied read's, or one whose
     * filters no entry can match.
     *
     * @param  int  $perPage
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function empty(int $perPage): self
    {
        return new self([], null, $perPage);
    }

    /**
     * Whether there is a next page to open with the cursor.
     *
     * @return bool
     */
    public function hasMore(): bool
    {
        return $this->nextCursor !== null;
    }
}
