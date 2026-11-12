<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Description;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Unit tests for the description of an entry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Description::class)]
final class DescriptionTest extends TestCase
{
    /**
     * The array has every field in order, the outcome as its value.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $description = new Description('Invoice approved', 'invoice.approved', Outcome::DENIED, 'over_limit', ['amount' => '[ENCRYPTED]', 'lines' => [['sku' => 'A1']]]);

        self::assertSame([
            'title'      => 'Invoice approved',
            'code'       => 'invoice.approved',
            'outcome'    => 'denied',
            'reason'     => 'over_limit',
            'properties' => ['amount' => '[ENCRYPTED]', 'lines' => [['sku' => 'A1']]],
        ], $description->toArray());
    }

    /**
     * A description keeps its fields, and `null` for no reason.
     *
     * @return void
     */
    public function testHoldsWhatItIsGiven(): void
    {
        $description = new Description('Signed in', 'authentication.signed_in', Outcome::SUCCESS, null, []);

        self::assertSame('Signed in', $description->title);
        self::assertSame('authentication.signed_in', $description->code);
        self::assertSame(Outcome::SUCCESS, $description->outcome);
        self::assertNull($description->reason);
        self::assertSame([], $description->properties);
        self::assertNull($description->toArray()['reason']);
        self::assertSame('success', $description->toArray()['outcome']);
    }

    /**
     * The properties are kept out of a stack trace's frames.
     *
     * @return void
     */
    public function testThePropertiesAreSensitive(): void
    {
        self::assertCount(1, (new \ReflectionParameter([Description::class, '__construct'], 'properties'))->getAttributes(\SensitiveParameter::class));
    }
}
