<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;

/**
 * Unit tests for the minimised value: what it keeps, and the parameters it
 * keeps out of a stack trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Minimised::class)]
final class MinimisedTest extends TestCase
{
    /**
     * Each field holds what it is given, and each may be `null`.
     *
     * @return void
     */
    public function testKeepsWhatItIsGiven(): void
    {
        $minimised = new Minimised(['a' => 1, '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], ['route' => 'home'], '203.0.113.7');

        self::assertSame(['a' => 1, '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $minimised->properties);
        self::assertSame(['route' => 'home'], $minimised->context);
        self::assertSame('203.0.113.7', $minimised->ip);

        $nothing = new Minimised(null, null, null);

        self::assertNull($nothing->properties);
        self::assertNull($nothing->context);
        self::assertNull($nothing->ip);
    }

    /**
     * Every parameter holds a value of the record, so each is marked sensitive
     * and a stack trace through the constructor shows none.
     *
     * @return void
     */
    public function testItsParametersAreSensitive(): void
    {
        $parameters = (new \ReflectionMethod(Minimised::class, '__construct'))->getParameters();

        self::assertSame(['properties', 'context', 'ip'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters));

        foreach ($parameters as $parameter) {
            self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }
    }
}
