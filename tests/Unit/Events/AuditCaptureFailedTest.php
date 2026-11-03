<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;

/**
 * Unit tests for the event dispatched when a capture fails: it carries the
 * classes of the event, of what translated it and of the exception, and nothing
 * that could leak a value of the event to a listener.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditCaptureFailed::class)]
final class AuditCaptureFailedTest extends TestCase
{
    /**
     * The event carries the three class names it is given, each under its own
     * name, and they are all it has, so a new property has to be argued for
     * here; an ambiguity names no mapper.
     *
     * @return void
     */
    public function testItCarriesOnlyClassNames(): void
    {
        $event = new AuditCaptureFailed('Acme\Events\InvoiceApproved', 'Acme\Mappers\InvoiceMapper', \RuntimeException::class);

        self::assertSame([
            'eventClass'     => 'Acme\Events\InvoiceApproved',
            'mapperClass'    => 'Acme\Mappers\InvoiceMapper',
            'exceptionClass' => \RuntimeException::class,
        ], get_object_vars($event));

        $properties = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(AuditCaptureFailed::class))->getProperties(),
        );

        self::assertSame(['eventClass', 'mapperClass', 'exceptionClass'], $properties);

        $types = array_map(
            static fn (\ReflectionProperty $property): string => (string) $property->getType(),
            (new \ReflectionClass(AuditCaptureFailed::class))->getProperties(),
        );

        self::assertSame(['string', '?string', 'string'], $types);
        self::assertNull((new AuditCaptureFailed('Acme\Events\InvoiceApproved', null, \LogicException::class))->mapperClass);
    }

    /**
     * The event is marked as the package's own, so it is never mapped to a
     * record of itself, and it cannot be changed once dispatched.
     *
     * @return void
     */
    public function testItIsAPackageEvent(): void
    {
        $class = new \ReflectionClass(AuditCaptureFailed::class);

        self::assertInstanceOf(AuditLogEvent::class, new AuditCaptureFailed('event', null, 'exception'));
        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
    }
}
