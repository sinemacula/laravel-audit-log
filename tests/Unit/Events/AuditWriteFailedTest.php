<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;

/**
 * Unit tests for the write failure event, which carries ids and class names and
 * no value of the record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditWriteFailed::class)]
final class AuditWriteFailedTest extends TestCase
{
    /**
     * The event carries what it is given, each under its own name, and the four
     * properties are all it has, so a new one has to be argued for here.
     *
     * @return void
     */
    public function testCarriesTheFourFieldsAndNothingElse(): void
    {
        $event = new AuditWriteFailed('01932b4e-8a40-7000-8000-000000000001', 'invoice.approved', 'Acme\Stores\WarehouseStore', 'Illuminate\Database\QueryException');

        self::assertSame([
            'id'        => '01932b4e-8a40-7000-8000-000000000001',
            'code'      => 'invoice.approved',
            'store'     => 'Acme\Stores\WarehouseStore',
            'exception' => 'Illuminate\Database\QueryException',
        ], get_object_vars($event));

        $properties = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(AuditWriteFailed::class))->getProperties(),
        );

        self::assertSame(['id', 'code', 'store', 'exception'], $properties);
    }

    /**
     * The event is marked as the package's own, so it is never mapped to a
     * record of itself, and it cannot be changed once dispatched.
     *
     * @return void
     */
    public function testIsAPackageEvent(): void
    {
        $class = new \ReflectionClass(AuditWriteFailed::class);

        self::assertInstanceOf(AuditLogEvent::class, new AuditWriteFailed('id', 'invoice.approved', 'store', 'exception'));
        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
    }
}
