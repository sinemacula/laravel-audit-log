<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;

/**
 * Unit tests for the recorded event, which carries the record's id, code and
 * category and no value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRecorded::class)]
final class AuditRecordedTest extends TestCase
{
    /**
     * The event carries what it is given, each under its own name.
     *
     * @return void
     */
    public function testCarriesTheIdCodeAndCategory(): void
    {
        $event = new AuditRecorded('01932b4e-8a40-7000-8000-000000000001', 'invoice.approved', 'finance');

        self::assertSame('01932b4e-8a40-7000-8000-000000000001', $event->id);
        self::assertSame('invoice.approved', $event->code);
        self::assertSame('finance', $event->category);
    }

    /**
     * The three properties are all it has, so a new one has to be argued for
     * here.
     *
     * @return void
     */
    public function testCarriesNothingElse(): void
    {
        $properties = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(AuditRecorded::class))->getProperties(),
        );

        self::assertSame(['id', 'code', 'category'], $properties);
    }

    /**
     * The event is marked as the package's own, so it is never mapped to a
     * record of itself.
     *
     * @return void
     */
    public function testIsAnAuditLogEvent(): void
    {
        self::assertInstanceOf(AuditLogEvent::class, new AuditRecorded('id', 'invoice.approved', 'finance'));
    }
}
