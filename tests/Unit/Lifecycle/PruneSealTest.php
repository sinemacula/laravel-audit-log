<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal;

/**
 * Unit tests for an authenticated seal as a prune reads it: its members sorted
 * bytewise, each member's position in that order and the HMAC it was sealed
 * with, and the refusal of an entry the seal does not hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneSeal::class)]
final class PruneSealTest extends TestCase
{
    /** @var array<string, string> The members, by entry id, in no order: digits sort before letters, bytewise. */
    private const array MEMBERS = [
        '01932b4e-9000-7000-8000-00000000000b' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        '01932b4e-9000-7000-8000-000000000002' => '2222222222222222222222222222222222222222222222222222222222222222',
        '01932b4e-9000-7000-8000-00000000000a' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '01932b4e-9000-7000-8000-000000000001' => '1111111111111111111111111111111111111111111111111111111111111111',
    ];

    /** @var string An entry id no member has. */
    private const string STRANGER = '01932b4e-9000-7000-8000-0000000000ff';

    /**
     * The members are sorted bytewise by entry id, and each member's position
     * is its place in that order, from 0, whatever order they were given in.
     *
     * @return void
     */
    public function testPositionsFollowTheSortedMembers(): void
    {
        $seal = self::seal(self::MEMBERS);

        $sorted = [
            '01932b4e-9000-7000-8000-000000000001',
            '01932b4e-9000-7000-8000-000000000002',
            '01932b4e-9000-7000-8000-00000000000a',
            '01932b4e-9000-7000-8000-00000000000b',
        ];

        self::assertSame($sorted, $seal->memberIds);

        foreach ($sorted as $position => $id) {
            self::assertSame($position, $seal->positionOf($id), $id);
            self::assertTrue($seal->hasMember($id), $id);
        }

        self::assertSame($sorted, self::seal(array_reverse(self::MEMBERS, true))->memberIds);
    }

    /**
     * Each member gives the HMAC it was sealed with, and the seal keeps the
     * envelope and the digest it was built with.
     *
     * @return void
     */
    public function testEachMemberGivesItsSealedHmac(): void
    {
        $envelope = self::envelope();
        $seal     = new PruneSeal($envelope, str_repeat('d', 64), self::MEMBERS);

        foreach (self::MEMBERS as $id => $hmac) {
            self::assertSame($hmac, $seal->memberHmac($id), $id);
        }

        self::assertSame($envelope, $seal->envelope);
        self::assertSame(str_repeat('d', 64), $seal->digest);
    }

    /**
     * An entry the seal does not hold is no member, and has neither a position
     * nor an HMAC.
     *
     * @return void
     */
    public function testAnEntryTheSealDoesNotHoldIsRefused(): void
    {
        $seal = self::seal(self::MEMBERS);

        self::assertFalse($seal->hasMember(self::STRANGER));

        foreach ([$seal->positionOf(...), $seal->memberHmac(...)] as $read) {
            try {
                $read(self::STRANGER);

                self::fail('Expected an entry the seal does not hold to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The entry is not a member of the seal.', $exception->getMessage());
            }
        }
    }

    /**
     * The seal of the members given, under the test's envelope.
     *
     * @param  array<string, string>  $members
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal
     */
    private static function seal(array $members): PruneSeal
    {
        return new PruneSeal(self::envelope(), str_repeat('d', 64), $members);
    }

    /**
     * An envelope of the four members.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     */
    private static function envelope(): SealEnvelope
    {
        return new SealEnvelope(
            'app-eu-1',
            '01932b4e-a000-7000-8000-000000000001',
            1,
            null,
            null,
            4,
            str_repeat('c', 64),
            '2026-10-31T23:34:56.000001Z',
            '2026-10-31T23:34:56.000004Z',
            '2026-10-31T23:40:00.000000Z',
            'k2026',
        );
    }
}
