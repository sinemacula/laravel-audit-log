<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the authority a lifecycle operation is asked for under: the
 * operator, the reason and the external reference it keeps exactly as given,
 * the reasons and external references it refuses, each naming its field and
 * never the value, and the array the journal and a record keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Authority::class)]
final class AuthorityTest extends TestCase
{
    /** @var string How a reason outside the grammar is refused. */
    private const string REFUSED_REASON = 'A reason must be a machine-readable code of 1 to 64 characters:'
        . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /** @var string How an external reference that is empty, long or unclean is refused. */
    private const string REFUSED_REFERENCE = 'An authority\'s external reference must be from 1 to 191 characters, with no control characters.';

    /**
     * The operator, the reason and the external reference are kept exactly as
     * given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $operator  = Reference::of('App\Models\User', 42);
        $authority = new Authority($operator, 'legal.hold:case-7', 'Ticket SEC-2041');

        self::assertSame($operator, $authority->operator);
        self::assertSame('legal.hold:case-7', $authority->reason);
        self::assertSame('Ticket SEC-2041', $authority->externalReference);
    }

    /**
     * An authority asked for without an external reference has none.
     *
     * @return void
     */
    public function testTheExternalReferenceIsOptional(): void
    {
        self::assertNull((new Authority(Reference::of('operator', 'ops-1'), 'retention'))->externalReference);
    }

    /**
     * Rows of `[reason]`: reasons inside the grammar, at its edges.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReasonsInsideTheGrammar(): iterable
    {
        yield from [
            'one letter'             => ['a'],
            'one digit'              => ['7'],
            'sixty-four characters'  => [str_repeat('a', 64)],
            'every punctuation mark' => ['a_.:-z'],
            'a dotted, coloned code' => ['legal.hold:case-2041'],
        ];
    }

    /**
     * Each reason inside the grammar is kept as given.
     *
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('provideReasonsInsideTheGrammar')]
    public function testAcceptsAReasonInsideTheGrammar(string $reason): void
    {
        self::assertSame($reason, (new Authority(Reference::of('operator', 'ops-1'), $reason))->reason);
    }

    /**
     * Rows of `[reason]`: reasons outside the grammar.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReasonsOutsideTheGrammar(): iterable
    {
        yield from [
            'empty'                  => [''],
            '65 characters'          => [str_repeat('a', 65)],
            'upper case'             => ['Legal_hold'],
            'a space'                => ['legal hold'],
            'a leading punctuation'  => ['-legal_hold'],
            'a letter outside ASCII' => ['légal_hold'],
            'a trailing newline'     => ["legal_hold\n"],
            'a slash'                => ['legal/hold'],
        ];
    }

    /**
     * Each reason outside the grammar is refused, naming the field and the
     * grammar, never the value.
     *
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('provideReasonsOutsideTheGrammar')]
    public function testRefusesAReasonOutsideTheGrammar(string $reason): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::REFUSED_REASON);

        new Authority(Reference::of('operator', 'ops-1'), $reason);
    }

    /**
     * Rows of `[external reference]`: external references that are empty,
     * longer than the column, or not already clean text.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedExternalReferences(): iterable
    {
        yield from [
            'empty'               => [''],
            '192 characters'      => [str_repeat('a', 192)],
            '192 multibyte'       => [str_repeat('é', 192)],
            'a newline'           => ["SEC-2041\nforged"],
            'a NUL byte'          => ["SEC-2041\0"],
            'an escape character' => ["SEC-\e[31m2041"],
            'invalid UTF-8'       => ["SEC-\xC3\x28"],
        ];
    }

    /**
     * Each external reference that is empty, longer than the column or not
     * already clean is refused rather than cleaned or cut, naming the field and
     * the limit, never the value.
     *
     * @param  string  $externalReference
     * @return void
     */
    #[DataProvider('provideRefusedExternalReferences')]
    public function testRefusesAnExternalReferenceThatIsEmptyLongOrUnclean(string $externalReference): void
    {
        try {
            new Authority(Reference::of('operator', 'ops-1'), 'legal_hold', $externalReference);

            self::fail('Expected the external reference to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::REFUSED_REFERENCE, $exception->getMessage());
            self::assertStringNotContainsString('SEC-', $exception->getMessage());
        }
    }

    /**
     * An external reference of exactly 191 characters is kept, counted in
     * characters rather than bytes, so 191 multibyte characters fit: protects
     * against a mutation that measures bytes or moves the bound by one.
     *
     * @return void
     */
    public function testAcceptsAnExternalReferenceOfTheColumnsLength(): void
    {
        foreach ([str_repeat('a', 191), str_repeat('é', 191), 'x'] as $externalReference) {
            $authority = new Authority(Reference::of('operator', 'ops-1'), 'legal_hold', $externalReference);

            self::assertSame($externalReference, $authority->externalReference, (string) mb_strlen($externalReference));
        }

        self::assertSame(191, Authority::MAX_EXTERNAL_REFERENCE_CHARACTERS);
    }

    /**
     * The array holds the operator's type and id, the reason and the external
     * reference, in that order, with `null` for no external reference.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $operator = Reference::of('App\Models\User', '007');

        self::assertSame(
            ['type' => 'App\Models\User', 'id' => '007', 'reason' => 'legal_hold', 'external_reference' => 'SEC-2041'],
            (new Authority($operator, 'legal_hold', 'SEC-2041'))->toArray(),
        );

        self::assertSame(
            ['type' => 'App\Models\User', 'id' => '007', 'reason' => 'legal_hold', 'external_reference' => null],
            (new Authority($operator, 'legal_hold'))->toArray(),
        );
    }
}
