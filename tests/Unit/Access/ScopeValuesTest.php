<?php

declare(strict_types = 1);

namespace Tests\Unit\Access;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\ScopeValues;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the reference and category lists an access scope holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeValues::class)]
final class ScopeValuesTest extends TestCase
{
    /**
     * Each exact pair is kept once, sorted by type then id bytewise, so a type
     * that is a prefix of another sorts first and case is never folded.
     *
     * @return void
     */
    public function testReferencesAreEachPairOnceSortedBytewise(): void
    {
        $held = ScopeValues::references([
            Reference::of('team', 'b'),
            Reference::of('Team', 'a'),
            Reference::of('team', 'B'),
            Reference::of('te', 'z'),
            Reference::of('team', 'b'),
        ], 5, 'tenants');

        self::assertSame([['Team', 'a'], ['te', 'z'], ['team', 'B'], ['team', 'b']], ScopeValues::pairs($held));
    }

    /**
     * References are refused beyond the limit, counted once each, and the
     * refusal names the limit and what is held.
     *
     * @return void
     */
    public function testReferencesAreRefusedBeyondTheLimit(): void
    {
        $two = [Reference::of('team', '1'), Reference::of('team', '2'), Reference::of('team', '2')];

        self::assertCount(2, ScopeValues::references($two, 2, 'tenants'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An access scope holds at most 1 about-references.');

        ScopeValues::references($two, 1, 'about-references');
    }

    /**
     * Categories are each kept once, sorted bytewise.
     *
     * @return void
     */
    public function testCategoriesAreEachOnceSortedBytewise(): void
    {
        self::assertSame(['alpha', 'beta', 'zeta'], ScopeValues::categoryList(['zeta', 'alpha', 'beta', 'alpha']));
        self::assertSame([], ScopeValues::categoryList([]));
    }

    /**
     * A category outside the definitions' grammar is refused.
     *
     * @return void
     */
    public function testAMalformedCategoryIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An access scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');

        ScopeValues::categoryList(['auth', 'Billing']);
    }

    /**
     * Categories are refused beyond a scope's limit, counted once each.
     *
     * @return void
     */
    public function testCategoriesAreRefusedBeyondTheLimit(): void
    {
        $most = array_map(static fn (int $index): string => 'c' . $index, range(1, AccessScope::MAX_CATEGORIES));

        self::assertCount(AccessScope::MAX_CATEGORIES, ScopeValues::categoryList([...$most, 'c1']));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An access scope holds at most 50 categories in each list.');

        ScopeValues::categoryList([...$most, 'extra']);
    }

    /**
     * Each reference is shown as its type and id, in order, and no list as
     * `null`.
     *
     * @return void
     */
    public function testPairsShowEachReferenceAsItsTypeAndId(): void
    {
        self::assertSame([['user', '1'], ['team', '2']], ScopeValues::pairs([Reference::of('user', '1'), Reference::of('team', '2')]));
        self::assertSame([], ScopeValues::pairs([]));
        self::assertNull(ScopeValues::pairs(null));
    }

    /**
     * The constructor is private; reflection invokes it to cover the line.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ScopeValues::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ScopeValues::class, $instance);
    }
}
