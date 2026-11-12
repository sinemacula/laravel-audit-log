<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;

/**
 * Unit tests for the exception a stack throws when a destination fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StackDeliveryException::class)]
final class StackDeliveryExceptionTest extends TestCase
{
    /** @var string The id of the record not every destination took. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * The message names the record, then each failed destination and its class.
     *
     * @return void
     */
    public function testTheMessageNamesEachFailure(): void
    {
        $exception = new StackDeliveryException(self::ID, ['database' => QueryException::class, 'siem' => \RuntimeException::class], false, false, false, []);

        $message = 'Audit record 01932b4e-8a40-7000-8000-000000000001 did not reach every destination: '
            . 'database (Illuminate\Database\QueryException), siem (RuntimeException).';

        self::assertSame($message, $exception->getMessage());
    }

    /**
     * A single failure is named alone, with no separator.
     *
     * @return void
     */
    public function testTheMessageNamesASingleFailure(): void
    {
        $exception = new StackDeliveryException(self::ID, ['log' => 'class@anonymous'], false, false, false, []);

        self::assertSame('Audit record 01932b4e-8a40-7000-8000-000000000001 did not reach every destination: log (class@anonymous).', $exception->getMessage());
    }

    /**
     * The record's id, the failures in order and both flags are kept as given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $exception = new StackDeliveryException(self::ID, ['siem' => \RuntimeException::class, 'database' => QueryException::class], true, false, false, []);

        self::assertSame(self::ID, $exception->recordId);
        self::assertSame(['siem' => \RuntimeException::class, 'database' => QueryException::class], $exception->failures);
        self::assertTrue($exception->causedByConcurrency);
        self::assertFalse($exception->causedByLostConnection);

        $lost = new StackDeliveryException(self::ID, ['siem' => \RuntimeException::class], false, true, false, []);

        self::assertFalse($lost->causedByConcurrency);
        self::assertTrue($lost->causedByLostConnection);
    }

    /**
     * It has no previous exception and no code.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $exception = new StackDeliveryException(self::ID, ['database' => QueryException::class], true, true, false, []);

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
    }

    /**
     * It is a runtime exception, so a caller that catches those catches it.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, new StackDeliveryException(self::ID, ['database' => QueryException::class], false, false, false, []));
    }
}
