<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException;

/**
 * Unit tests for the exception a release of a hold that is not active is
 * refused with: its message names the hold id, and it carries no previous
 * exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownHoldException::class)]
final class UnknownHoldExceptionTest extends TestCase
{
    /**
     * The message names the hold and says only an active hold is released.
     *
     * @return void
     */
    public function testTheMessageNamesTheHold(): void
    {
        self::assertSame(
            'The hold `01932b4e-d000-7000-8000-000000000001` is not active; only an active hold is released.',
            UnknownHoldException::for('01932b4e-d000-7000-8000-000000000001')->getMessage(),
        );
    }

    /**
     * It carries no previous exception and no code, and is a runtime exception.
     *
     * @return void
     */
    public function testCarriesNoPreviousException(): void
    {
        $exception = UnknownHoldException::for('01932b4e-d000-7000-8000-000000000001');

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
