<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an owner marker, its stored row and the malformed fields it
 * refuses without their value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerMarker::class)]
final class OwnerMarkerTest extends TestCase
{
    /** @var string The marker's journal row's id. */
    private const string ID = '01932b4e-e000-7000-8000-000000000001';

    /** @var string When the marker was written. */
    private const string CREATED_AT = '2026-11-01T12:00:00.123456Z';

    /** @var array{id: string, owner_type: string, owner_id: string, transition: string, generation_floor: int, journal_sequence: int, created_at: string} The stored row of the marker. */
    private const array ROW = [
        'id'               => self::ID,
        'owner_type'       => 'App\Models\User',
        'owner_id'         => '42',
        'transition'       => 'erased',
        'generation_floor' => 3,
        'journal_sequence' => 17,
        'created_at'       => '2026-11-01 12:00:00.123456',
    ];

    /**
     * A marker keeps each field as given, and its row holds them in table
     * order, the time in the form the database stores.
     *
     * @return void
     */
    public function testItKeepsItsFieldsAndStoresThemInTableOrder(): void
    {
        $marker = self::marker();

        self::assertSame(self::ID, $marker->id);
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $marker->owner->toArray());
        self::assertSame(MarkerTransition::ERASED, $marker->transition);
        self::assertSame(3, $marker->generationFloor);
        self::assertSame(17, $marker->journalSequence);
        self::assertSame(self::CREATED_AT, $marker->createdAt);
        self::assertSame(self::ROW, $marker->toRow());
    }

    /**
     * A marker of an erasure records one, and a marker of a reinstatement does
     * not.
     *
     * @return void
     */
    public function testOnlyAnErasureMarkerRecordsAnErasure(): void
    {
        self::assertTrue(self::marker()->isErasure());
        self::assertFalse(self::marker(MarkerTransition::REINSTATED)->isErasure());
    }

    /**
     * A stored row reads back in any form an engine returns: integers as
     * strings, fewer fractional digits.
     *
     * @return void
     */
    public function testAStoredRowIsReadInAnyFormAnEngineReturns(): void
    {
        self::assertEquals(self::marker(), OwnerMarker::fromRow(self::ROW));

        $read = OwnerMarker::fromRow(['generation_floor' => '3', 'journal_sequence' => '17', 'created_at' => '2026-11-01 12:00:00.1'] + self::ROW);

        self::assertSame(3, $read->generationFloor);
        self::assertSame(17, $read->journalSequence);
        self::assertSame('2026-11-01T12:00:00.100000Z', $read->createdAt);
        self::assertSame(MarkerTransition::REINSTATED, OwnerMarker::fromRow(['transition' => 'reinstated'] + self::ROW)->transition);
    }

    /**
     * Rows of `[column, stored value, message]`: each stored column that is
     * missing or malformed, and what it is refused with.
     *
     * @return iterable<string, array{0: string, 1: int|string|null, 2: string}>
     */
    public static function provideMalformedColumns(): iterable
    {
        yield from [
            'a missing id'               => ['id', null, 'A stored owner marker\'s `id` is malformed.'],
            'an id that is no UUID'      => ['id', 'marker-1', 'An owner marker\'s id must be a lower-case UUID.'],
            'an upper-case id'           => ['id', strtoupper(self::ID), 'An owner marker\'s id must be a lower-case UUID.'],
            'a missing owner type'       => ['owner_type', null, 'A stored owner marker\'s `owner_type` is malformed.'],
            'an empty owner id'          => ['owner_id', '', 'A reference\'s id must be from 1 to 191 characters, with no control characters.'],
            'an unknown transition'      => ['transition', 'forgotten', 'A stored owner marker\'s `transition` is malformed.'],
            'a missing transition'       => ['transition', null, 'A stored owner marker\'s `transition` is malformed.'],
            'a floor that is no integer' => ['generation_floor', '3.0', 'A stored owner marker\'s `generation_floor` is malformed.'],
            'a negative floor'           => ['generation_floor', -1, 'An owner marker\'s generation floor must be from 0 to 2147483647.'],
            'a floor past the column'    => ['generation_floor', 2147483648, 'An owner marker\'s generation floor must be from 0 to 2147483647.'],
            'a missing sequence'         => ['journal_sequence', null, 'A stored owner marker\'s `journal_sequence` is malformed.'],
            'a sequence of 0'            => ['journal_sequence', 0, 'An owner marker\'s journal sequence must be from 1.'],
            'a time of another form'     => ['created_at', '2026-11-01T12:00:00Z', 'A stored owner marker\'s `created_at` is malformed.'],
            'a missing time'             => ['created_at', null, 'A stored owner marker\'s `created_at` is malformed.'],
        ];
    }

    /**
     * Each malformed stored column is refused with an unexpected value naming
     * the column or the field, and never the value.
     *
     * @param  string  $column
     * @param  int|string|null  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedColumns')]
    public function testAMalformedStoredColumnIsRefused(string $column, int|string|null $value, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        OwnerMarker::fromRow([$column => $value] + self::ROW);
    }

    /**
     * Rows of `[id, floor, sequence, created at, message]`: each malformed
     * field of a marker built by hand.
     *
     * @return iterable<string, array{0: string, 1: int, 2: int, 3: string, 4: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        yield from [
            'an id that is no UUID'  => ['marker', 0, 1, self::CREATED_AT, 'An owner marker\'s id must be a lower-case UUID.'],
            'a negative floor'       => [self::ID, -1, 1, self::CREATED_AT, 'An owner marker\'s generation floor must be from 0 to 2147483647.'],
            'a floor past the limit' => [self::ID, 2147483648, 1, self::CREATED_AT, 'An owner marker\'s generation floor must be from 0 to 2147483647.'],
            'a sequence of 0'        => [self::ID, 0, 0, self::CREATED_AT, 'An owner marker\'s journal sequence must be from 1.'],
            'a time in storage form' => [self::ID, 0, 1, '2026-11-01 12:00:00.000000', 'An owner marker\'s creation time must be ISO-8601 UTC with microseconds.'],
        ];
    }

    /**
     * Each malformed field is refused as the marker is built, with an invalid
     * argument naming the field.
     *
     * @param  string  $id
     * @param  int  $floor
     * @param  int  $sequence
     * @param  string  $createdAt
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testAMalformedFieldIsRefused(string $id, int $floor, int $sequence, string $createdAt, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new OwnerMarker($id, Reference::of('App\Models\User', '42'), MarkerTransition::ERASED, $floor, $sequence, $createdAt);
    }

    /**
     * The bounds themselves are kept: a floor of 0 and of the largest
     * generation, and a sequence of 1.
     *
     * @return void
     */
    public function testTheBoundsAreKept(): void
    {
        $lowest  = new OwnerMarker(self::ID, Reference::of('App\Models\User', '42'), MarkerTransition::REINSTATED, 0, 1, self::CREATED_AT);
        $highest = new OwnerMarker(self::ID, Reference::of('App\Models\User', '42'), MarkerTransition::ERASED, 2147483647, PHP_INT_MAX, self::CREATED_AT);

        self::assertSame([0, 1], [$lowest->generationFloor, $lowest->journalSequence]);
        self::assertSame([2147483647, PHP_INT_MAX], [$highest->generationFloor, $highest->journalSequence]);
    }

    /**
     * The marker of user 42, with the transition.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition  $transition
     * @return \SineMacula\Laravel\AuditLog\Keys\OwnerMarker
     */
    private static function marker(MarkerTransition $transition = MarkerTransition::ERASED): OwnerMarker
    {
        return new OwnerMarker(self::ID, Reference::of('App\Models\User', '42'), $transition, 3, 17, self::CREATED_AT);
    }
}
