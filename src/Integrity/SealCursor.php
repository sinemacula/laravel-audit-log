<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * A position in the entries' `(recorded_at, id)` order, from which sealing
 * reads on: the rows after an entry, or every row from an instant on.
 *
 * Both parts are kept in the stored form, as the column returned them, so a
 * position round-trips on each engine whatever form its times take. Neither is
 * checked as a UUID or an instant, nor bounded or cut to a length, because the
 * row a position names may be one the sealer skipped as malformed, an id longer
 * than a UUID or an empty time among them, and a position that could not name
 * it exactly would stop sealing there or never move past it. Whether the
 * position starts at its time, the row at that time included, or after the
 * entry it names is kept apart from both parts, so an empty id is never read as
 * either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealCursor
{
    /**
     * Constructor.
     *
     * @param  string  $recordedAt
     * @param  string  $id
     * @param  bool  $fromItsTime
     */
    private function __construct(

        /** The time of the position, in the stored form, as the column returned it. */
        public string $recordedAt,

        /** The id of the entry the position is after, as stored, or empty for a position from its time on. */
        public string $id,

        /** Whether the position starts at its time, the row at that time included, rather than after the entry. */
        private bool $fromItsTime,
    ) {}

    /**
     * The position from which every row recorded at the instant or later is
     * read, the instant given in the package's form.
     *
     * @param  string  $instant
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function from(string $instant): self
    {
        return new self(StoredTime::toStorage($instant), '', true);
    }

    /**
     * The position after the entry with the stored time and id, whatever they
     * hold: the rows read from it on are later, or at the same time with a
     * greater id.
     *
     * @param  string  $recordedAt
     * @param  string  $id
     * @return self
     */
    public static function after(string $recordedAt, string $id): self
    {
        return new self($recordedAt, $id, false);
    }

    /**
     * The position progress holds, or `null` when it holds none, or one that is
     * not a time and an id as strings.
     *
     * @param  ?array<string, scalar|null>  $value
     * @return ?self
     */
    public static function fromProgress(?array $value): ?self
    {
        $recordedAt = $value['recorded_at'] ?? null;
        $id         = $value['id']          ?? null;

        if (!is_string($recordedAt) || !is_string($id)) {
            return null;
        }

        return new self($recordedAt, $id, ($value['from_its_time'] ?? false) === true);
    }

    /**
     * Whether the position starts at its time, the row at that time included,
     * rather than after an entry.
     *
     * @return bool
     */
    public function startsAtItsTime(): bool
    {
        return $this->fromItsTime;
    }

    /**
     * The position as progress keeps it.
     *
     * @return array{recorded_at: string, id: string, from_its_time: bool}
     */
    public function toProgress(): array
    {
        return ['recorded_at' => $this->recordedAt, 'id' => $this->id, 'from_its_time' => $this->fromItsTime];
    }
}
