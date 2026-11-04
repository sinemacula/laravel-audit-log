<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * One owner marker, as its row stores it: the id of the journal row that
 * records the transition, the owner, whether the owner was erased or
 * reinstated, the generation every later key of the owner is created above, the
 * journal row's sequence and when the marker was written.
 *
 * The owner's latest marker, by journal sequence, decides whether a key may be
 * created for it: none is while the latest records an erasure. A marker is not
 * verified on its own, since its journal row is: a forged or missing marker can
 * only refuse or allow a creation, and a key created for an erased owner is
 * reported as restored. Every field is checked as the marker is built, and a
 * stored row read through `fromRow()` is refused with an
 * `UnexpectedValueException` naming the column and never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnerMarker
{
    /** @var string A lower-case UUID: the journal row's id. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string Why a generation floor is refused. */
    private const string FLOOR_OUT_OF_RANGE = 'An owner marker\'s generation floor must be from 0 to 2147483647.';

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored owner marker\'s `%s` is malformed.';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition  $transition
     * @param  int  $generationFloor
     * @param  int  $journalSequence
     * @param  string  $createdAt
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the journal row that records the transition, a lower-case UUID. */
        public string $id,

        /** The owner the marker is about. */
        #[\SensitiveParameter]
        public Reference $owner,

        /** Whether the owner was erased or reinstated. */
        public MarkerTransition $transition,

        /** The generation every later key of the owner is created above, from 0. */
        public int $generationFloor,

        /** The sequence of the journal row that records the transition, from 1. */
        public int $journalSequence,

        /** When the marker was written, ISO-8601 UTC with microseconds. */
        public string $createdAt,
    ) {
        $malformed = self::malformedField($id, $generationFloor, $journalSequence, $createdAt);

        if ($malformed !== null) {
            throw new \InvalidArgumentException($malformed);
        }
    }

    /**
     * The marker a decoded stored row holds: integers are read as an integer or
     * its decimal string and the time in any form an engine returns. A missing
     * or malformed column is refused naming the column, never quoting its
     * value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromRow(#[\SensitiveParameter] array $stored): self
    {
        $transition = MarkerTransition::tryFrom(self::storedText($stored, 'transition'))
            ?? throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, 'transition'));

        try {
            return new self(
                self::storedText($stored, 'id'),
                Reference::of(self::storedText($stored, 'owner_type'), self::storedText($stored, 'owner_id')),
                $transition,
                self::storedInteger($stored, 'generation_floor'),
                self::storedInteger($stored, 'journal_sequence'),
                self::storedTime($stored),
            );
        } catch (\InvalidArgumentException $malformed) {
            // Every refusal of a field names the field and never its value
            throw new \UnexpectedValueException($malformed->getMessage());
        }
    }

    /**
     * Whether the marker records an erasure, so no key may be created for the
     * owner while it is the latest.
     *
     * @return bool
     */
    public function isErasure(): bool
    {
        return $this->transition === MarkerTransition::ERASED;
    }

    /**
     * The row that stores the marker, in table order, with its time in the form
     * the database stores.
     *
     * @return array{id: string, owner_type: string, owner_id: string, transition: string, generation_floor: int, journal_sequence: int, created_at: string}
     *
     * @throws \InvalidArgumentException
     */
    public function toRow(): array
    {
        return [
            'id'               => $this->id,
            'owner_type'       => $this->owner->type,
            'owner_id'         => $this->owner->id,
            'transition'       => $this->transition->value,
            'generation_floor' => $this->generationFloor,
            'journal_sequence' => $this->journalSequence,
            'created_at'       => StoredTime::toStorage($this->createdAt),
        ];
    }

    /**
     * Why the first malformed field is refused, or `null` when none is.
     *
     * @param  string  $id
     * @param  int  $generationFloor
     * @param  int  $journalSequence
     * @param  string  $createdAt
     * @return ?string
     */
    private static function malformedField(string $id, int $generationFloor, int $journalSequence, string $createdAt): ?string
    {
        return match (true) {
            preg_match(self::UUID_PATTERN, $id) !== 1                                => 'An owner marker\'s id must be a lower-case UUID.',
            $generationFloor < 0 || $generationFloor > SubjectKeyRow::MAX_GENERATION => self::FLOOR_OUT_OF_RANGE,
            $journalSequence < 1                                                     => 'An owner marker\'s journal sequence must be from 1.',
            !StoredTime::isInstant($createdAt)                                       => 'An owner marker\'s creation time must be ISO-8601 UTC with microseconds.',
            default                                                                  => null,
        };
    }

    /**
     * The stored column as text, refused naming the column when it is missing
     * or not a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedText(#[\SensitiveParameter] array $stored, string $column): string
    {
        $value = $stored[$column] ?? null;

        return is_string($value) ? $value : throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
    }

    /**
     * The stored column as an integer, from an integer or its decimal string,
     * refused naming the column otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    private static function storedInteger(#[\SensitiveParameter] array $stored, string $column): int
    {
        return IntegerSetting::parse($stored[$column] ?? null) ?? throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
    }

    /**
     * The stored creation time in the package's form, from any form an engine
     * returns, refused naming the column.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedTime(#[\SensitiveParameter] array $stored): string
    {
        try {
            return StoredTime::fromStorage(self::storedText($stored, 'created_at'));
        } catch (\UnexpectedValueException) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, 'created_at'));
        }
    }
}
