<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\SpillLine;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * Unit tests for the spill line value: what it keeps, and that its JSON stays
 * out of a stack trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SpillLine::class)]
final class SpillLineTest extends TestCase
{
    /**
     * A line keeps its number, the JSON taken from it and why none was.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $held    = new SpillLine(3, '{"id":"a"}', null);
        $refused = new SpillLine(4, null, EnvelopeFailure::TRUNCATED);

        self::assertSame([3, '{"id":"a"}', null], [$held->number, $held->json, $held->failure]);
        self::assertSame([4, null, EnvelopeFailure::TRUNCATED], [$refused->number, $refused->json, $refused->failure]);
    }

    /**
     * The JSON holds a record, so a stack trace never shows it, and neither of
     * the others needs hiding.
     *
     * @return void
     */
    public function testTheJsonIsSensitive(): void
    {
        $sensitive = [];

        foreach ((new \ReflectionMethod(SpillLine::class, '__construct'))->getParameters() as $parameter) {
            $sensitive[$parameter->getName()] = $parameter->getAttributes(\SensitiveParameter::class) !== [];
        }

        self::assertSame(['number' => false, 'json' => true, 'failure' => false], $sensitive);
    }
}
