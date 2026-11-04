<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException;

/**
 * Unit tests for the exception a reinstatement of an owner that is not erased
 * is refused with: its reason, its message, which names no owner, and that it
 * carries no previous exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReinstatementRefusedException::class)]
final class ReinstatementRefusedExceptionTest extends TestCase
{
    /**
     * The refusal carries `not_erased`, the reason its activity record names.
     *
     * @return void
     */
    public function testTheReasonIsNotErased(): void
    {
        self::assertSame('not_erased', ReinstatementRefusedException::NOT_ERASED);
        self::assertSame('not_erased', ReinstatementRefusedException::notErased()->reason);
    }

    /**
     * The message is a sentence that names no owner.
     *
     * @return void
     */
    public function testTheMessageNamesNoOwner(): void
    {
        self::assertSame(
            'The owner is not erased; only an owner whose latest marker records an erasure is reinstated.',
            ReinstatementRefusedException::notErased()->getMessage(),
        );
    }

    /**
     * It carries no previous exception and no code, and is a runtime exception.
     *
     * @return void
     */
    public function testCarriesNoPreviousException(): void
    {
        $exception = ReinstatementRefusedException::notErased();

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
