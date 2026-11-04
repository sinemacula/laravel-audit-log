<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for a key unit: the owner, the tenant and the category it keeps,
 * its digest as the key rows store it, a tenantless unit apart, and the
 * categories it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUnit::class)]
final class KeyUnitTest extends TestCase
{
    /** @var string The golden unit's digest. */
    private const string GOLDEN_UNIT = 'e04da77c985cc0ed5a98c5faf362eab7ebb34e4db753aef921fa2e05e6585a79';

    /**
     * The unit keeps its parts, and its digest is the key row's digest of them.
     *
     * @return void
     */
    public function testKeepsItsPartsAndTheirDigest(): void
    {
        $owner  = Reference::of('App\Models\User', 7);
        $tenant = Reference::of('App\Models\Team', 3);
        $unit   = new KeyUnit($owner, $tenant, 'security');

        self::assertSame($owner, $unit->owner);
        self::assertSame($tenant, $unit->tenant);
        self::assertSame('security', $unit->category);
        self::assertSame(self::GOLDEN_UNIT, $unit->digest());
        self::assertSame(SubjectKeyRow::unitOf('App\Models\User', '7', 'App\Models\Team', '3', 'security'), $unit->digest());
    }

    /**
     * A tenantless unit's digest is its own, never that of a tenant's unit of
     * the same owner and category.
     *
     * @return void
     */
    public function testATenantlessUnitHasItsOwnDigest(): void
    {
        $unit = new KeyUnit(Reference::of('App\Models\User', 7), null, 'security');

        self::assertNull($unit->tenant);
        self::assertSame(SubjectKeyRow::unitOf('App\Models\User', '7', null, null, 'security'), $unit->digest());
        self::assertNotSame(self::GOLDEN_UNIT, $unit->digest());
    }

    /**
     * The same owner in another tenant or category is another unit.
     *
     * @return void
     */
    public function testATenantOrACategoryMakesAnotherUnit(): void
    {
        $owner = Reference::of('App\Models\User', 7);

        self::assertNotSame((new KeyUnit($owner, Reference::of('App\Models\Team', 4), 'security'))->digest(), self::GOLDEN_UNIT);
        self::assertNotSame((new KeyUnit($owner, Reference::of('App\Models\Team', 3), 'billing'))->digest(), self::GOLDEN_UNIT);
    }

    /**
     * Rows of `[category]`: categories outside the definitions' grammar.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedCategories(): iterable
    {
        yield from [
            'empty'           => [''],
            'in capitals'     => ['Security'],
            'a leading digit' => ['1security'],
            'too long'        => [str_repeat('a', 65)],
        ];
    }

    /**
     * A category outside the definitions' grammar is refused.
     *
     * @param  string  $category
     * @return void
     */
    #[DataProvider('provideRefusedCategories')]
    public function testRefusesACategoryOutsideTheGrammar(string $category): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A key unit\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.');

        new KeyUnit(Reference::of('App\Models\User', 7), null, $category);
    }

    /**
     * The owner and the tenant are marked sensitive.
     *
     * @return void
     */
    public function testTheOwnerAndTheTenantAreMarkedSensitive(): void
    {
        foreach (['owner', 'tenant'] as $parameter) {
            $reflected = new \ReflectionParameter([KeyUnit::class, '__construct'], $parameter);

            self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }
}
