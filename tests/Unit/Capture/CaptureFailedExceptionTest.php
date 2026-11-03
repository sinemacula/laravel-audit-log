<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;

/**
 * Unit tests for what is reported when a capture fails: the classes of the
 * event, of the mapper and of the failure, each by name alone, a message built
 * from them alone, and no previous exception through which the failure's text
 * could reach a log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureFailedException::class)]
final class CaptureFailedExceptionTest extends TestCase
{
    /** @var string A secret the failure's message holds, which must reach nothing. */
    private const string SECRET = 'card 4111 1111 1111 1111';

    /**
     * The message names the event's class, the mapper's and the failure's, and
     * never the failure's message; each class is kept as it is named.
     *
     * @return void
     */
    public function testTheMessageNamesOnlyTheClasses(): void
    {
        $exception = CaptureFailedException::of('Acme\Events\InvoiceApproved', 'Acme\Mappers\InvoiceMapper', new \UnexpectedValueException(self::SECRET));

        self::assertSame('Capturing `Acme\Events\InvoiceApproved` with `Acme\Mappers\InvoiceMapper` failed with `UnexpectedValueException`.', $exception->getMessage());
        self::assertSame('Acme\Events\InvoiceApproved', $exception->eventClass);
        self::assertSame('Acme\Mappers\InvoiceMapper', $exception->mapperClass);
        self::assertSame(\UnexpectedValueException::class, $exception->exceptionClass);
        self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    /**
     * A capture that failed because more than one mapping matched the event
     * names no mapper, in the message as on the exception.
     *
     * @return void
     */
    public function testAnAmbiguityNamesNoMapper(): void
    {
        $exception = CaptureFailedException::of('Acme\Events\InvoiceApproved', null, new \LogicException(self::SECRET));

        self::assertSame('Capturing `Acme\Events\InvoiceApproved` with `no mapper` failed with `LogicException`.', $exception->getMessage());
        self::assertNull($exception->mapperClass);
    }

    /**
     * The failure is never kept as the previous exception, so neither a handler
     * nor a log that walks the chain reaches its message, and nothing of it is
     * kept on the exception but its class.
     *
     * @return void
     */
    public function testItHasNoPrevious(): void
    {
        $failure   = new \RuntimeException(self::SECRET, 7, new \LogicException(self::SECRET));
        $exception = CaptureFailedException::of('Acme\Events\InvoiceApproved', 'Acme\Mappers\InvoiceMapper', $failure);

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertSame(['eventClass', 'mapperClass', 'exceptionClass'], array_keys(array_diff_key(get_object_vars($exception), get_class_vars(\RuntimeException::class))));
        self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
    }

    /**
     * An anonymous failure is named as `get_debug_type()` names it, without the
     * path of the file it was declared in.
     *
     * @return void
     */
    public function testAnAnonymousClassIsNamedWithoutItsFile(): void
    {
        $failure   = new class (self::SECRET) extends \RuntimeException {};
        $exception = CaptureFailedException::of('Acme\Events\InvoiceApproved', 'Acme\Mappers\InvoiceMapper', $failure);

        self::assertSame('RuntimeException@anonymous', $exception->exceptionClass);
        self::assertSame('Capturing `Acme\Events\InvoiceApproved` with `Acme\Mappers\InvoiceMapper` failed with `RuntimeException@anonymous`.', $exception->getMessage());
        self::assertStringNotContainsString('.php', $exception->getMessage());
    }
}
