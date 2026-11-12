<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentRows;

/**
 * Unit tests for how a segment's verification reads what it was given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SegmentRows::class)]
final class SegmentRowsTest extends TestCase
{
    /** @var string The id of the seal a test reads. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000002';

    /** @var string The id of the seal before it. */
    private const string PREVIOUS_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The digest of the seal before it. */
    private const string PREVIOUS_DIGEST = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @var string A member's entry id. */
    private const string FIRST_MEMBER = '01932b4e-a000-7000-8000-000000000001';

    /** @var string Another member's entry id, sorting after the first. */
    private const string SECOND_MEMBER = '01932b4e-a000-7000-8000-000000000002';

    /** @var string A member's HMAC. */
    private const string HMAC = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

    /** @var string When every seal of a test was made. */
    private const string INSTANT = '2026-11-01T12:00:00.000000Z';

    /**
     * A set of as many members as the seal counts, giving its members digest in
     * whatever order the rows came, has no finding.
     *
     * @return void
     */
    public function testAnAuthenticMembershipHasNoFinding(): void
    {
        $pairs = [[self::SECOND_MEMBER, self::HMAC], [self::FIRST_MEMBER, self::HMAC]];

        self::assertSame([], SegmentRows::membership(self::seal(2, $pairs), 2, $pairs));
    }

    /**
     * A set of another size than the seal counts fails both the count and the
     * digest, at the seal.
     *
     * @return void
     */
    public function testAnotherCountFailsTheCountAndTheDigest(): void
    {
        $pairs = [[self::FIRST_MEMBER, self::HMAC]];

        self::assertSame([[Finding::MEMBER_COUNT, self::SEAL_ID], [Finding::MEMBERS_DIGEST, self::SEAL_ID]], SegmentRows::membership(self::seal(2, $pairs), 1, $pairs));
    }

    /**
     * A set of the right size that gives another digest, and one that cannot
     * give a digest at all, fail the digest alone.
     *
     * @return void
     */
    public function testAnotherSetFailsTheDigest(): void
    {
        $seal = self::seal(1, [[self::FIRST_MEMBER, self::HMAC]]);

        self::assertSame([[Finding::MEMBERS_DIGEST, self::SEAL_ID]], SegmentRows::membership($seal, 1, [[self::SECOND_MEMBER, self::HMAC]]));
        self::assertSame([[Finding::MEMBERS_DIGEST, self::SEAL_ID]], SegmentRows::membership($seal, 1, [['not-an-id', self::HMAC]]));
    }

    /**
     * Rows of `[the previous report's id, its digest, whether the link is
     * broken]`.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: bool}>
     */
    public static function provideLinks(): iterable
    {
        yield from [
            'the seal before'            => [self::PREVIOUS_ID, self::PREVIOUS_DIGEST, false],
            'another seal'               => [self::SEAL_ID, self::PREVIOUS_DIGEST, true],
            'another digest'             => [self::PREVIOUS_ID, self::HMAC, true],
            'a seal that cannot be read' => [self::PREVIOUS_ID, null, true],
        ];
    }

    /**
     * A seal's link to the seal before is broken unless it names that seal's id
     * and recomputed digest.
     *
     * @param  string  $previousId
     * @param  ?string  $previousDigest
     * @param  bool  $broken
     * @return void
     */
    #[DataProvider('provideLinks')]
    public function testTheChainNamesTheSealBefore(string $previousId, ?string $previousDigest, bool $broken): void
    {
        $previous = new SegmentReport(1, $previousId, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, 1, null, null, $previousDigest);

        self::assertSame($broken ? [[Finding::CHAIN_BROKEN, self::SEAL_ID]] : [], SegmentRows::chain(self::seal(1, [[self::FIRST_MEMBER, self::HMAC]]), $previous));
    }

    /**
     * The first seal of a run has no link to check.
     *
     * @return void
     */
    public function testWithoutASealBeforeTheChainHasNoFinding(): void
    {
        self::assertSame([], SegmentRows::chain(self::seal(1, [[self::FIRST_MEMBER, self::HMAC]], 1, null, null), null));
    }

    /**
     * Rows of `[sequence, previous id, previous digest, whether the genesis
     * rule is broken]`.
     *
     * @return iterable<string, array{0: int, 1: ?string, 2: ?string, 3: bool}>
     */
    public static function provideGenesis(): iterable
    {
        yield from [
            'a first seal linking to none'    => [1, null, null, false],
            'a first seal naming an id'       => [1, self::PREVIOUS_ID, null, true],
            'a first seal naming a digest'    => [1, null, self::PREVIOUS_DIGEST, true],
            'a later seal linking by both'    => [2, self::PREVIOUS_ID, self::PREVIOUS_DIGEST, false],
            'a later seal without its id'     => [2, null, self::PREVIOUS_DIGEST, true],
            'a later seal without its digest' => [2, self::PREVIOUS_ID, null, true],
        ];
    }

    /**
     * Whether a seal breaks the genesis rule follows its sequence and its
     * link's two fields.
     *
     * @param  int  $sequence
     * @param  ?string  $previousId
     * @param  ?string  $previousDigest
     * @param  bool  $breaks
     * @return void
     */
    #[DataProvider('provideGenesis')]
    public function testTheGenesisRule(int $sequence, ?string $previousId, ?string $previousDigest, bool $breaks): void
    {
        self::assertSame($breaks, SegmentRows::breaksGenesis(self::seal(1, [[self::FIRST_MEMBER, self::HMAC]], $sequence, $previousId, $previousDigest)));
    }

    /**
     * Rows of `[stored receipt, receipt read]`: only a JSON object of string
     * keys and scalars or `null` is a receipt.
     *
     * @return iterable<string, array{0: int|string|null, 1: ?array<string, scalar|null>}>
     */
    public static function provideReceipts(): iterable
    {
        yield from [
            'no receipt'           => [null, null],
            'a number'             => [12, null],
            'text that is no JSON' => ['receipt', null],
            'a JSON list'          => ['["a"]', null],
            'a nested object'      => ['{"a":{"b":1}}', null],
            'a list in an object'  => ['{"a":[1]}', null],
            'an empty object'      => ['{}', []],
            'scalars and null'     => ['{"a":"x","b":2,"c":true,"d":null}', ['a' => 'x', 'b' => 2, 'c' => true, 'd' => null]],
        ];
    }

    /**
     * The receipt kept beside a seal is read only when it is a JSON object of
     * string keys and scalars or `null`.
     *
     * @param  int|string|null  $stored
     * @param  ?array<string, scalar|null>  $receipt
     * @return void
     */
    #[DataProvider('provideReceipts')]
    public function testTheReceiptIsReadOnlyAsAnObjectOfScalars(int|string|null $stored, ?array $receipt): void
    {
        self::assertSame($receipt, SegmentRows::receiptOf($stored));
    }

    /**
     * A stored sequence is read from an integer or its decimal string, and is 0
     * when it is anything else or missing.
     *
     * @return void
     */
    public function testTheSequenceIsReadOrZero(): void
    {
        self::assertSame(7, SegmentRows::sequenceOf(['sequence' => 7]));
        self::assertSame(7, SegmentRows::sequenceOf(['sequence' => '7']));
        self::assertSame(0, SegmentRows::sequenceOf(['sequence' => 'seven']));
        self::assertSame(0, SegmentRows::sequenceOf([]));
    }

    /**
     * The earlier of the kept id and the given one is taken bytewise, and the
     * given one when none is kept.
     *
     * @return void
     */
    public function testTheEarliestIsBytewise(): void
    {
        self::assertSame(self::SECOND_MEMBER, SegmentRows::earliest(null, self::SECOND_MEMBER));
        self::assertSame(self::FIRST_MEMBER, SegmentRows::earliest(self::SECOND_MEMBER, self::FIRST_MEMBER));
        self::assertSame(self::FIRST_MEMBER, SegmentRows::earliest(self::FIRST_MEMBER, self::SECOND_MEMBER));
        self::assertSame('B', SegmentRows::earliest('a', 'B'));
    }

    /**
     * A stored value is text only when it is a string.
     *
     * @return void
     */
    public function testAValueIsTextOnlyAsAString(): void
    {
        self::assertSame('id', SegmentRows::textOf('id'));
        self::assertSame('', SegmentRows::textOf(''));
        self::assertNull(SegmentRows::textOf(7));
        self::assertNull(SegmentRows::textOf(null));
    }

    /**
     * The constructor is private: the class is a utility container only.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SegmentRows::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SegmentRows::class, $instance);
    }

    /**
     * A seal of the members given, at the sequence, linking to the seal before
     * as given.
     *
     * @param  int  $count
     * @param  list<array{0: string, 1: string}>  $pairs
     * @param  int  $sequence
     * @param  ?string  $previousId
     * @param  ?string  $previousDigest
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     */
    private static function seal(
        int $count,
        array $pairs,
        int $sequence = 2,
        ?string $previousId = self::PREVIOUS_ID,
        ?string $previousDigest = self::PREVIOUS_DIGEST,
    ): SealEnvelope {
        $digest = SealEnvelope::membersDigest($pairs);

        return new SealEnvelope('audit-log', self::SEAL_ID, $sequence, $previousId, $previousDigest, $count, $digest, self::INSTANT, self::INSTANT, self::INSTANT, 'k1');
    }
}
