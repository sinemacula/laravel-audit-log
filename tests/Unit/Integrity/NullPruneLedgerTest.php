<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;

/**
 * Unit tests for the prune ledger of an application that never prunes: it is a
 * prune ledger, it has no record of any seal, and it keeps no state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NullPruneLedger::class)]
final class NullPruneLedgerTest extends TestCase
{
    /**
     * Rows of `[seal id]`: the golden seal's id, another seal's, an id in upper
     * case, and ids no seal could have.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSealIds(): iterable
    {
        yield from [
            'the golden seal' => ['01932b4e-9000-7000-8000-000000000001'],
            'another seal'    => ['01932b4e-9000-7000-8000-000000000002'],
            'upper case'      => ['01932B4E-9000-7000-8000-000000000001'],
            'not a uuid'      => ['seal-1'],
            'empty'           => [''],
            'a nul byte'      => ["01932b4e-9000-7000-8000-00000000000\0"],
        ];
    }

    /**
     * No seal has a prune record, whatever its id, so a missing member of any
     * seal is reported rather than excused.
     *
     * @param  string  $sealId
     * @return void
     */
    #[DataProvider('provideSealIds')]
    public function testItHasNoRecords(string $sealId): void
    {
        $ledger = new NullPruneLedger;

        self::assertInstanceOf(PruneLedger::class, $ledger);
        self::assertSame([], $ledger->recordsFor($sealId));
    }

    /**
     * Asking again gives the same answer: the ledger holds nothing, so asking
     * leaves nothing behind.
     *
     * @return void
     */
    public function testKeepsNoState(): void
    {
        $ledger = new NullPruneLedger;

        self::assertSame([], $ledger->recordsFor('01932b4e-9000-7000-8000-000000000001'));
        self::assertSame([], $ledger->recordsFor('01932b4e-9000-7000-8000-000000000001'));
        self::assertSame([], (new \ReflectionObject($ledger))->getProperties());
    }
}
