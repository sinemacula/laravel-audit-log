<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;

/**
 * Unit tests for the field handling enum: the values definitions and the docs
 * name, and which handlings decide their whole branch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldHandling::class)]
final class FieldHandlingTest extends TestCase
{
    /**
     * The handlings, in order, with their stored values, and nothing else.
     *
     * @return void
     */
    public function testTheCasesAndTheirStoredValues(): void
    {
        self::assertSame([
            FieldHandling::RETAIN,
            FieldHandling::REDACT,
            FieldHandling::PSEUDONYMISE,
            FieldHandling::ENCRYPT,
            FieldHandling::DROP,
        ], FieldHandling::cases());

        self::assertSame(
            ['retain', 'redact', 'pseudonymise', 'encrypt', 'drop'],
            array_map(static fn (FieldHandling $handling): string => $handling->value, FieldHandling::cases()),
        );
    }

    /**
     * Rows of `[handling, whether it is terminal]`: every case, so a case added
     * without a row fails `testEveryHandlingHasARow`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 1: bool}>
     */
    public static function provideHandlings(): iterable
    {
        yield from [
            'retain'       => [FieldHandling::RETAIN, false],
            'redact'       => [FieldHandling::REDACT, true],
            'pseudonymise' => [FieldHandling::PSEUDONYMISE, true],
            'encrypt'      => [FieldHandling::ENCRYPT, true],
            'drop'         => [FieldHandling::DROP, true],
        ];
    }

    /**
     * Only `retain` leaves the branch beneath its path open to further rules;
     * every other handling decides it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  bool  $terminal
     * @return void
     */
    #[DataProvider('provideHandlings')]
    public function testOnlyRetainLeavesItsBranchOpen(FieldHandling $handling, bool $terminal): void
    {
        self::assertSame($terminal, $handling->isTerminal(), $handling->name);
    }

    /**
     * The provider covers every case once, so a new handling cannot be added
     * without deciding whether it is terminal.
     *
     * @return void
     */
    public function testEveryHandlingHasARow(): void
    {
        $handlings = array_map(static fn (array $row): FieldHandling => $row[0], iterator_to_array(self::provideHandlings(), false));

        self::assertSame(FieldHandling::cases(), $handlings);
    }

    /**
     * A stored value reads back as its handling, and an unknown value is not
     * one.
     *
     * @return void
     */
    public function testAStoredValueReadsBackAsItsHandling(): void
    {
        self::assertSame(FieldHandling::PSEUDONYMISE, FieldHandling::from('pseudonymise'));
        self::assertNull(FieldHandling::tryFrom('pseudonymize'));
        self::assertNull(FieldHandling::tryFrom('RETAIN'));
    }
}
