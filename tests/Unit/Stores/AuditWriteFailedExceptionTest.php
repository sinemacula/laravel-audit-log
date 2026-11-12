<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Tests\Concerns\SearchesForSecrets;

/**
 * Unit tests for the exception that stands in for a failed write's exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditWriteFailedException::class)]
#[CoversClass(WriteDiagnostics::class)]
final class AuditWriteFailedExceptionTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The id of the record that was not written. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The store the write failed on. */
    private const string STORE = 'SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore';

    /**
     * Rows of `[diagnostics, message]`: all optional fields, none, each alone.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics, 1: string}>
     */
    public static function provideMessages(): iterable
    {
        $base = 'Audit record 01932b4e-8a40-7000-8000-000000000001';
        $tail = 'failed on SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore with Illuminate\Database\QueryException';

        yield from [
            'every optional field' => [
                self::diagnostics('invoice.approved', FailedOperation::DRAIN, '40001', 1213, 'audit', 'warehouse'),
                "{$base} (invoice.approved) was not written: drain {$tail}, SQLSTATE 40001, driver code 1213, connection audit, destination warehouse.",
            ],
            'none' => [
                self::diagnostics(null, FailedOperation::STORE, null, null, null, null),
                "{$base} was not written: store {$tail}.",
            ],
            'the code alone' => [
                self::diagnostics('invoice.approved', FailedOperation::OUTBOX, null, null, null, null),
                "{$base} (invoice.approved) was not written: outbox {$tail}.",
            ],
            'the state alone' => [
                self::diagnostics(null, FailedOperation::STORE, '25P02', null, null, null),
                "{$base} was not written: store {$tail}, SQLSTATE 25P02.",
            ],
            'a driver code of zero' => [
                self::diagnostics(null, FailedOperation::STORE, null, 0, null, null),
                "{$base} was not written: store {$tail}, driver code 0.",
            ],
            'the connection alone' => [
                self::diagnostics(null, FailedOperation::FINALISE, null, null, 'audit', null),
                "{$base} was not written: finalise {$tail}, connection audit.",
            ],
            'the destination alone' => [
                self::diagnostics(null, FailedOperation::DRAIN, null, null, null, 'warehouse'),
                "{$base} was not written: drain {$tail}, destination warehouse.",
            ],
        ];
    }

    /**
     * The message names each known field of the diagnostics in a fixed order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMessages')]
    public function testTheMessageIsPinned(WriteDiagnostics $diagnostics, string $message): void
    {
        self::assertSame($message, (new AuditWriteFailedException($diagnostics))->getMessage());
    }

    /**
     * Each field of the diagnostics is kept, the operation as its value.
     *
     * @return void
     */
    public function testKeepsEachField(): void
    {
        $exception = new AuditWriteFailedException(self::diagnostics('invoice.approved', FailedOperation::SPILL, 'HY000', 1, 'audit', 'warehouse'));

        self::assertSame([
            'recordId'       => self::ID,
            'eventCode'      => 'invoice.approved',
            'operation'      => 'spill',
            'store'          => self::STORE,
            'exceptionClass' => QueryException::class,
            'sqlState'       => 'HY000',
            'driverCode'     => 1,
            'connection'     => 'audit',
            'destination'    => 'warehouse',
        ], [
            'recordId'       => $exception->recordId,
            'eventCode'      => $exception->eventCode,
            'operation'      => $exception->operation,
            'store'          => $exception->store,
            'exceptionClass' => $exception->exceptionClass,
            'sqlState'       => $exception->sqlState,
            'driverCode'     => $exception->driverCode,
            'connection'     => $exception->connection,
            'destination'    => $exception->destination,
        ]);
        self::assertSame(0, $exception->getCode());
    }

    /**
     * It has no previous exception, so nothing of the failure is chained to it.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        self::assertNull((new AuditWriteFailedException(self::diagnostics(null, FailedOperation::STORE, null, null, null, null)))->getPrevious());
    }

    /**
     * No value of the failure reaches the message, the properties or the trace.
     *
     * @return void
     */
    public function testHoldsNoValueOfTheFailure(): void
    {
        $previous = new \PDOException('SQLSTATE[23000]: Duplicate entry ' . self::SECRET);

        $previous->errorInfo = ['23000', 1062, 'Duplicate entry ' . self::SECRET];

        $failure   = new QueryException('audit', 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], $previous);
        $exception = self::fromFailure($failure);

        self::assertTrue(self::holdsText($failure, self::SECRET));
        self::assertHoldsNoSecret($exception, 'the exception');
        $message = 'Audit record 01932b4e-8a40-7000-8000-000000000001 (invoice.approved) was not written: store failed on '
            . self::STORE . ' with Illuminate\Database\QueryException, SQLSTATE 23000, driver code 1062, connection audit.';

        self::assertSame($message, $exception->getMessage());
    }

    /**
     * It is a final runtime exception: the write failed, not the record.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        $exception = new AuditWriteFailedException(self::diagnostics(null, FailedOperation::STORE, null, null, null, null));

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertTrue((new \ReflectionClass(AuditWriteFailedException::class))->isFinal());
    }

    /**
     * The exception for the failure, built as the write path builds it.
     *
     * @param  \Throwable  $failure
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private static function fromFailure(#[\SensitiveParameter] \Throwable $failure): AuditWriteFailedException
    {
        return new AuditWriteFailedException(WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE));
    }

    /**
     * Diagnostics of a query exception on the database store, with the given
     * code, operation and details.
     *
     * @param  ?string  $eventCode
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  ?string  $sqlState
     * @param  ?int  $driverCode
     * @param  ?string  $connection
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics
     */
    private static function diagnostics(
        ?string $eventCode,
        FailedOperation $operation,
        ?string $sqlState,
        ?int $driverCode,
        ?string $connection,
        ?string $destination,
    ): WriteDiagnostics {
        return new WriteDiagnostics(self::ID, $eventCode, $operation, self::STORE, QueryException::class, $sqlState, $driverCode, $connection, $destination);
    }
}
