<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an active hold: the fields it keeps, the ones it refuses,
 * whether its review date has passed, and the form a listing shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type HoldFields array{id?: string, reviewBy?: ?string, placedAt?: string, reason?: string, externalReference?: ?string, operationId?: string, journalSequence?: int}
 */
#[CoversClass(Hold::class)]
final class HoldTest extends TestCase
{
    /** @var string The hold's id. */
    private const string ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The operation that placed it. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string When it was placed. */
    private const string PLACED_AT = '2026-11-01T12:00:00.123456Z';

    /** @var string When it is due for review. */
    private const string REVIEW_BY = '2027-05-01T00:00:00.000000Z';

    /**
     * Every field is kept as given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'));
        $user  = Reference::of('user', '7');
        $hold  = new Hold(self::ID, $scope, HoldBasis::LEGAL_CLAIM, self::REVIEW_BY, self::PLACED_AT, $user, 'case.review', 'app:ticket-123', self::OPERATION, 4);

        self::assertSame(self::ID, $hold->id);
        self::assertSame($scope, $hold->scope);
        self::assertSame(HoldBasis::LEGAL_CLAIM, $hold->basis);
        self::assertSame(self::REVIEW_BY, $hold->reviewBy);
        self::assertSame(self::PLACED_AT, $hold->placedAt);
        self::assertSame(['type' => 'user', 'id' => '7'], $hold->operator->toArray());
        self::assertSame('case.review', $hold->reason);
        self::assertSame('app:ticket-123', $hold->externalReference);
        self::assertSame(self::OPERATION, $hold->operationId);
        self::assertSame(4, $hold->journalSequence);
    }

    /**
     * The listing form holds every field, the scope as its canonical form and
     * the operator as its pair.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $hold = self::hold(reviewBy: null, externalReference: null);

        self::assertSame([
            'id'                 => self::ID,
            'scope'              => HoldScope::all()->toArray(),
            'basis'              => 'regulatory',
            'review_by'          => null,
            'placed_at'          => self::PLACED_AT,
            'operator'           => ['type' => 'user', 'id' => '7'],
            'reason'             => 'case.review',
            'external_reference' => null,
            'operation_id'       => self::OPERATION,
            'journal_sequence'   => 1,
        ], $hold->toArray());
    }

    /**
     * Rows of `[review date, instant, whether it has passed]`: a review date
     * passes only once it is before the instant, never at it, and a hold with
     * none never passes it.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: bool}>
     */
    public static function provideReviews(): iterable
    {
        yield from [
            'before the instant'        => ['2027-05-01T00:00:00.000000Z', '2027-05-01T00:00:00.000001Z', true],
            'at the instant'            => ['2027-05-01T00:00:00.000000Z', '2027-05-01T00:00:00.000000Z', false],
            'after the instant'         => ['2027-05-01T00:00:00.000001Z', '2027-05-01T00:00:00.000000Z', false],
            'no review date'            => [null, '2099-01-01T00:00:00.000000Z', false],
            'a year before the instant' => ['2026-05-01T00:00:00.000000Z', '2027-05-01T00:00:00.000000Z', true],
        ];
    }

    /**
     * Whether the review date has passed is judged at the instant given.
     *
     * @param  ?string  $reviewBy
     * @param  string  $now
     * @param  bool  $passed
     * @return void
     */
    #[DataProvider('provideReviews')]
    public function testIsPastReviewOnlyOnceTheDateIsBeforeTheInstant(?string $reviewBy, string $now, bool $passed): void
    {
        self::assertSame($passed, self::hold(reviewBy: $reviewBy)->isPastReview($now));
    }

    /**
     * An instant that is not in the package's form is refused rather than
     * compared as text.
     *
     * @return void
     */
    public function testIsPastReviewRefusesAMalformedInstant(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The instant a hold\'s review is judged at must be ISO-8601 UTC with microseconds.');

        self::hold()->isPastReview('2027-05-01 00:00:00');
    }

    /**
     * Rows of `[the fields to change, the message]`: each field that is
     * malformed.
     *
     * @return iterable<string, array{0: HoldFields, 1: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        $text   = 'A hold\'s external reference must be from 1 to 191 characters, with no control characters.';
        $reason = 'A reason must be a machine-readable code of 1 to 64 characters: lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

        yield from [
            'an upper-case id'              => [['id' => strtoupper(self::ID)], 'A hold\'s id must be a lower-case UUID.'],
            'an id that is no UUID'         => [['id' => 'hold-1'], 'A hold\'s id must be a lower-case UUID.'],
            'an operation id that is none'  => [['operationId' => 'op-1'], 'A hold\'s operation id must be a lower-case UUID.'],
            'a review date in storage form' => [['reviewBy' => '2027-05-01 00:00:00.000000'], 'A hold\'s review date must be ISO-8601 UTC with microseconds.'],
            'a placing time without micros' => [['placedAt' => '2026-11-01T12:00:00Z'], 'A hold\'s placing time must be ISO-8601 UTC with microseconds.'],
            'an upper-case reason'          => [['reason' => 'Case'], $reason],
            'an empty external reference'   => [['externalReference' => ''], $text],
            'a long external reference'     => [['externalReference' => str_repeat('a', 192)], $text],
            'an unclean external reference' => [['externalReference' => "app:\x07ticket"], $text],
            'a journal sequence of 0'       => [['journalSequence' => 0], 'A hold\'s journal sequence must be at least 1.'],
        ];
    }

    /**
     * Each malformed field is refused, naming the field and never its value.
     *
     * @param  HoldFields  $fields
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(array $fields, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::hold(...$fields);
    }

    /**
     * An external reference of exactly 191 characters, multibyte ones counted
     * as one each, is kept: protects against a limit off by one or counted in
     * bytes.
     *
     * @return void
     */
    public function testKeepsAnExternalReferenceAtItsLimit(): void
    {
        $reference = str_repeat('é', 191);

        self::assertSame($reference, self::hold(externalReference: $reference)->externalReference);
    }

    /**
     * A hold of the fields given, every other field a valid default.
     *
     * @param  string  $id
     * @param  ?string  $reviewBy
     * @param  string  $placedAt
     * @param  string  $reason
     * @param  ?string  $externalReference
     * @param  string  $operationId
     * @param  int  $journalSequence
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function hold(
        string $id = self::ID,
        ?string $reviewBy = self::REVIEW_BY,
        string $placedAt = self::PLACED_AT,
        string $reason = 'case.review',
        ?string $externalReference = 'app:ticket-123',
        string $operationId = self::OPERATION,
        int $journalSequence = 1,
    ): Hold {
        $user = Reference::of('user', '7');

        return new Hold($id, HoldScope::all(), HoldBasis::REGULATORY, $reviewBy, $placedAt, $user, $reason, $externalReference, $operationId, $journalSequence);
    }
}
