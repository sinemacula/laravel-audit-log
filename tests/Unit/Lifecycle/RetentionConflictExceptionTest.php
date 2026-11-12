<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException;

/**
 * Unit tests for refusing a retention shorter than its preservation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetentionConflictException::class)]
final class RetentionConflictExceptionTest extends TestCase
{
    /**
     * The message names the policy's class, never a category or a tenant.
     *
     * @return void
     */
    public function testTheMessageNamesThePolicy(): void
    {
        $exception = RetentionConflictException::forPolicy('App\Retention\RegulatedPolicy');

        $message = 'The retention policy `App\Retention\RegulatedPolicy` retains a category for less than it must be preserved;'
            . ' pruning refuses it.';

        self::assertSame($message, $exception->getMessage());
        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
    }

    /**
     * A conflict is an `UnexpectedValueException`, like any malformed answer.
     *
     * @return void
     */
    public function testItIsAnUnexpectedValue(): void
    {
        self::assertInstanceOf(\UnexpectedValueException::class, RetentionConflictException::forPolicy('App\Retention\RegulatedPolicy'));
    }
}
