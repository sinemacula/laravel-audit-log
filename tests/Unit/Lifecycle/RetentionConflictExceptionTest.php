<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException;

/**
 * Unit tests for the refusal of a policy that keeps a category for less than it
 * must be preserved: the message naming the policy's class, and the class a
 * caller catches it as.
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
     * The message names the policy's class and nothing of a category or a
     * tenant, and the exception carries no other.
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
     * The conflict is an answer that came back wrong, so it is caught as an
     * `UnexpectedValueException`, like every other malformed answer of a
     * policy.
     *
     * @return void
     */
    public function testItIsAnUnexpectedValue(): void
    {
        self::assertInstanceOf(\UnexpectedValueException::class, RetentionConflictException::forPolicy('App\Retention\RegulatedPolicy'));
    }
}
