<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Privacy\PathMasker;

/**
 * Unit tests for the path masker: a segment is written only from a matching
 * rule or the fixed context names, never a concrete key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PathMasker::class)]
final class PathMaskerTest extends TestCase
{
    /** @var string The address a dynamic key could be. */
    private const string DYNAMIC_KEY = 'bob@example.com';

    /**
     * The masker is a utility container and cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PathMasker::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PathMasker::class, $instance);
    }

    /**
     * The fixed context names are the keys the package fills, in a fixed order.
     *
     * @return void
     */
    public function testTheFixedContextNames(): void
    {
        self::assertSame(['route', 'method', 'command', 'job', 'channel'], PathMasker::CONTEXT_NAMES);
    }

    /**
     * Rows of `[retained paths, dropped paths, concrete path, mask]`: the mask
     * table, then specificity, prefixes, numeric keys and nesting.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<int|string>, 3: string}>
     */
    public static function provideMasks(): iterable
    {
        yield from [
            'no rule'                          => [[], [], [self::DYNAMIC_KEY], '*'],
            'a rule on the field'              => [[], ['ssn'], ['ssn'], 'ssn'],
            'a nested rule on the field'       => [[], ['customer.ssn'], ['customer', 'ssn'], 'customer.ssn'],
            'a rule on the branch'             => [['customer'], [], ['customer', 'name'], 'customer.*'],
            'a sibling of a rule'              => [['customer.email'], [], ['customer', 'name'], '*.*'],
            'the last word of a rule'          => [['customer.email'], [], ['other', 'email'], '*.*'],
            'a word of a rule, moved'          => [['email'], [], ['x', 'email'], '*.*'],
            'the branch holding a rule'        => [['customer.email'], [], ['customer'], 'customer'],
            'a wildcard over a list'           => [[], ['items.*.sku'], ['items', 0, 'sku'], 'items.*.sku'],
            'a wildcard over a dynamic key'    => [[], ['*.phone'], [self::DYNAMIC_KEY, 'phone'], '*.phone'],
            'a list index'                     => [[], ['items.0'], ['items', 0], 'items.0'],
            'a key holding a dot'              => [['a.b'], [], ['a.b'], '*'],
            'the more specific rule'           => [['customer'], ['customer.ssn'], ['customer', 'ssn'], 'customer.ssn'],
            'the less specific rule'           => [['customer'], ['customer.ssn'], ['customer', 'name'], 'customer.*'],
            'deeper than the rule'             => [['customer'], [], ['customer', 'address', 'city'], 'customer.*.*'],
            'beneath a wildcard rule'          => [['*.phone'], [], [self::DYNAMIC_KEY], '*'],
            'an ancestor of a long rule'       => [['a.b.c'], [], ['a', 'b'], 'a.b'],
            'off the branch of a long rule'    => [['a.b.c'], [], ['a', 'x'], '*.*'],
            'a numeric key a rule names'       => [[], ['5'], [5], '5'],
            'a numeric key no rule names'      => [[], ['5'], [6], '*'],
            'another index than the rule'      => [[], ['items.0'], ['items', 1], '*.*'],
            'the first of the rules beneath'   => [['a.c', 'a.b'], [], ['a'], 'a'],
            'a wildcard first of those'        => [['a.b', '*.c'], [], ['a'], '*'],
            'the rule deciding it comes first' => [['*', 'customer.email'], [], ['customer'], '*'],
            'the empty path has no segments'   => [['a'], [], [], ''],
        ];
    }

    /**
     * A segment comes only from the rule that decides the field, or failing
     * that the first rule beneath it, and every other position is `*`.
     *
     * @param  list<string>  $retained
     * @param  list<string>  $dropped
     * @param  list<int|string>  $path
     * @param  string  $mask
     * @return void
     */
    #[DataProvider('provideMasks')]
    public function testTheMaskTable(array $retained, array $dropped, array $path, string $mask): void
    {
        $definition = EventDefinition::for('invoice.approved')->retain(...$retained)->drop(...$dropped);

        self::assertSame($mask, PathMasker::property($path, $definition));
    }

    /**
     * A key a rule does not name is never written, whichever rule the path
     * meets, and neither is a key that a wildcard matched.
     *
     * @return void
     */
    public function testAConcreteKeyIsNeverWritten(): void
    {
        $definition = EventDefinition::for('invoice.approved')
            ->retain('customer')
            ->retain('*.phone')
            ->drop('items.*.sku')
            ->retain('a.b.c');

        $paths = [
            [self::DYNAMIC_KEY],
            ['customer', self::DYNAMIC_KEY],
            [self::DYNAMIC_KEY, 'phone'],
            ['items', self::DYNAMIC_KEY],
            ['items', self::DYNAMIC_KEY, 'sku'],
            ['items', 0, self::DYNAMIC_KEY],
            ['a', self::DYNAMIC_KEY, 'c'],
            ['customer', 'address', self::DYNAMIC_KEY],
        ];

        foreach ($paths as $path) {
            $mask = PathMasker::property($path, $definition);

            self::assertStringNotContainsString(self::DYNAMIC_KEY, $mask, $mask);
            self::assertStringNotContainsString('example', $mask, $mask);
            self::assertStringNotContainsString(self::DYNAMIC_KEY, PathMasker::context($path), $mask);
        }
    }

    /**
     * The masked path has as many segments as the concrete path, so the depth
     * of what was removed is kept while its keys are not.
     *
     * @return void
     */
    public function testAMaskHasOneSegmentPerPosition(): void
    {
        $definition = EventDefinition::for('invoice.approved');

        self::assertSame('*.*.*.*', PathMasker::property(['a', 'b', 'c', 'd'], $definition));
        self::assertSame('context.*.*.*.*', PathMasker::context(['a', 'b', 'c', 'd']));
    }

    /**
     * Rows of `[concrete path, mask]`: each fixed name, then what is not one.
     *
     * @return iterable<string, array{0: list<int|string>, 1: string}>
     */
    public static function provideContextMasks(): iterable
    {
        yield from [
            'route'                       => [['route'], 'context.route'],
            'method'                      => [['method'], 'context.method'],
            'command'                     => [['command'], 'context.command'],
            'job'                         => [['job'], 'context.job'],
            'channel'                     => [['channel'], 'context.channel'],
            'beneath a fixed name'        => [['route', 'x'], 'context.route.*'],
            'deep beneath a fixed name'   => [['job', 'x', 'y'], 'context.job.*.*'],
            'a fixed name not at the top' => [['x', 'route'], 'context.*.*'],
            'a fixed name twice'          => [['route', 'route'], 'context.route.*'],
            'an address'                  => [[self::DYNAMIC_KEY], 'context.*'],
            'the reserved key'            => [['_audit'], 'context.*'],
            'another case'                => [['Route'], 'context.*'],
            'a numeric key'               => [[0], 'context.*'],
            'the empty path'              => [[], 'context.'],
        ];
    }

    /**
     * Only the first segment can be literal, and only when it is a fixed name.
     *
     * @param  list<int|string>  $path
     * @param  string  $mask
     * @return void
     */
    #[DataProvider('provideContextMasks')]
    public function testTheContextMaskTable(array $path, string $mask): void
    {
        self::assertSame($mask, PathMasker::context($path));
    }
}
