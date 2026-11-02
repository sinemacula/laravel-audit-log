<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Models\ImmutableEntryException;

/**
 * Unit tests for the immutable entry exception: the message naming the refused
 * method, and the class it specialises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImmutableEntryException::class)]
final class ImmutableEntryExceptionTest extends TestCase
{
    /**
     * The exception for a refused write names the model method in its message,
     * and says what writes entries and what keeps them unchanged.
     *
     * @return void
     */
    public function testNamesTheRefusedMethod(): void
    {
        $exception = ImmutableEntryException::refusing('save');

        $message = 'Audit entries are append-only: `save()` cannot write an entry;'
            . ' the store writes entries, and the database\'s grants keep them unchanged.';

        self::assertSame($message, $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The exception is a logic exception, never a runtime one: writing an entry
     * through the model is a misuse, not a failure of the database.
     *
     * @return void
     */
    public function testIsALogicException(): void
    {
        $exception = ImmutableEntryException::refusing('delete');

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertNotInstanceOf(\RuntimeException::class, $exception);
        self::assertTrue((new \ReflectionClass(ImmutableEntryException::class))->isFinal());
    }
}
