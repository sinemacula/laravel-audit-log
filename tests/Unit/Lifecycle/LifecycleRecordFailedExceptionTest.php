<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;

/**
 * Unit tests for the exception reported when a committed lifecycle operation's
 * record could not be written: each message names the operation, the code and
 * why, and points at reconciliation; the exception keeps those three, and
 * carries no previous exception and no code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleRecordFailedException::class)]
final class LifecycleRecordFailedExceptionTest extends TestCase
{
    /** @var string The operation that committed. */
    private const string OPERATION_ID = '019a4b2e-7c10-7000-8000-00000000000a';

    /**
     * A failed or refused write names the class of its failure.
     *
     * @return void
     */
    public function testAFailureNamesItsClass(): void
    {
        $exception = LifecycleRecordFailedException::of(self::OPERATION_ID, PackageActivity::PRUNED, \DomainException::class);

        self::assertSame(
            'The lifecycle operation `019a4b2e-7c10-7000-8000-00000000000a` committed, and its `audit_log.pruned` record could not be written '
            . '(DomainException); run `audit-log:reconcile`.',
            $exception->getMessage(),
        );
        self::assertSame([self::OPERATION_ID, PackageActivity::PRUNED, \DomainException::class], [$exception->operationId, $exception->activity, $exception->failure]);
    }

    /**
     * A write never acknowledged says so.
     *
     * @return void
     */
    public function testAWriteNeverAcknowledgedSaysSo(): void
    {
        $exception = LifecycleRecordFailedException::unacknowledged(self::OPERATION_ID, PackageActivity::HELD);

        self::assertSame(
            'The lifecycle operation `019a4b2e-7c10-7000-8000-00000000000a` committed, and its `audit_log.held` record could not be written '
            . '(it was never acknowledged); run `audit-log:reconcile`.',
            $exception->getMessage(),
        );
        self::assertSame([self::OPERATION_ID, PackageActivity::HELD, 'it was never acknowledged'], [$exception->operationId, $exception->activity, $exception->failure]);
    }

    /**
     * A record not attempted inside a transaction names the connection.
     *
     * @return void
     */
    public function testATransactionNamesItsConnection(): void
    {
        $exception = LifecycleRecordFailedException::inTransaction(self::OPERATION_ID, PackageActivity::RELEASED, 'audit');

        self::assertSame(
            'The lifecycle operation `019a4b2e-7c10-7000-8000-00000000000a` committed, and its `audit_log.released` record could not be written '
            . '(a transaction is open on the `audit` connection); run `audit-log:reconcile`.',
            $exception->getMessage(),
        );
        self::assertSame(PackageActivity::RELEASED, $exception->activity);
        self::assertSame('a transaction is open on the `audit` connection', $exception->failure);
    }

    /**
     * The exception carries no previous exception, so nothing a failed write
     * held reaches whoever reads it, and no code.
     *
     * @return void
     */
    public function testItCarriesNoPreviousException(): void
    {
        $exception = LifecycleRecordFailedException::of(self::OPERATION_ID, PackageActivity::IMPORTED, \RuntimeException::class);

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertTrue((new \ReflectionClass(LifecycleRecordFailedException::class))->isFinal());
    }
}
