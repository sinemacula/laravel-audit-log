<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\FieldDisclosure;

/**
 * Unit tests for what a page disclosed of its encrypted fragments: the grant
 * and the count of each state it keeps, the disclosure of a page that showed
 * none, the counts as a map sorted by state, and the counts it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldDisclosure::class)]
final class FieldDisclosureTest extends TestCase
{
    /**
     * The grant and each state's count are kept as given, and the counts are
     * shown by state, sorted, without the grant.
     *
     * @return void
     */
    public function testKeepsTheGrantAndEachStatesCount(): void
    {
        $disclosure = new FieldDisclosure(true, 1, 2, 3, 4);

        self::assertTrue($disclosure->reveal);
        self::assertSame([1, 2, 3, 4], [$disclosure->encrypted, $disclosure->erased, $disclosure->revealed, $disclosure->unreadable]);
        self::assertSame(['encrypted' => 1, 'erased' => 2, 'revealed' => 3, 'unreadable' => 4], $disclosure->toArray());
    }

    /**
     * A page that showed no fragment counts none of any state, under a scope
     * that revealed them or not.
     *
     * @return void
     */
    public function testNoneCountsNothingUnderEitherGrant(): void
    {
        foreach ([true, false] as $reveal) {
            $none = FieldDisclosure::none($reveal);

            self::assertSame($reveal, $none->reveal);
            self::assertSame(['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0], $none->toArray());
        }
    }

    /**
     * Rows of `[encrypted, erased, revealed, unreadable]`: counts with one
     * state below none.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int, 3: int}>
     */
    public static function provideNegativeCounts(): iterable
    {
        yield from [
            'encrypted'  => [-1, 0, 0, 0],
            'erased'     => [0, -1, 0, 0],
            'revealed'   => [0, 0, -1, 0],
            'unreadable' => [0, 0, 0, -1],
        ];
    }

    /**
     * A count below none is refused, whichever state it is of.
     *
     * @param  int  $encrypted
     * @param  int  $erased
     * @param  int  $revealed
     * @param  int  $unreadable
     * @return void
     */
    #[DataProvider('provideNegativeCounts')]
    public function testRefusesANegativeCount(int $encrypted, int $erased, int $revealed, int $unreadable): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A page\'s disclosure counts each state\'s fragments from none.');

        new FieldDisclosure(false, $encrypted, $erased, $revealed, $unreadable);
    }
}
