<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleLockException;

/**
 * Unit tests for the exception a lifecycle operation is refused with when the
 * lock cannot be taken as the protocol needs it: a missing lock row, and an
 * isolation level other than `read committed`, each with its message and no
 * previous exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleLockException::class)]
final class LifecycleLockExceptionTest extends TestCase
{
    /**
     * A missing lock row says the migrations seed it.
     *
     * @return void
     */
    public function testAMissingRowNamesTheMigrations(): void
    {
        self::assertSame('The lifecycle lock row is missing; run the migrations, which seed it.', LifecycleLockException::missing()->getMessage());
    }

    /**
     * Another isolation level is named, beside the one an operation needs.
     *
     * @return void
     */
    public function testAnotherIsolationNamesTheLevel(): void
    {
        self::assertSame(
            'The maintenance connection\'s transactions are `repeatable read`; a lifecycle operation needs `read committed`.',
            LifecycleLockException::isolation('repeatable read')->getMessage(),
        );
    }

    /**
     * Neither carries a previous exception, so no statement reaches whoever
     * reads it, nor a code.
     *
     * @return void
     */
    public function testNeitherCarriesAPreviousException(): void
    {
        foreach ([LifecycleLockException::missing(), LifecycleLockException::isolation('serializable')] as $exception) {
            self::assertNull($exception->getPrevious());
            self::assertSame(0, $exception->getCode());
            self::assertInstanceOf(\RuntimeException::class, $exception);
        }
    }
}
