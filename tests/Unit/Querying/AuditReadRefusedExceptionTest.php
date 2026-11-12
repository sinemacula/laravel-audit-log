<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;

/**
 * Unit tests for the exception a refused or unrecorded read is thrown as.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditReadRefusedException::class)]
final class AuditReadRefusedExceptionTest extends TestCase
{
    /**
     * Rows of `[the exception, its message]`, one per named constructor.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'reentrant' => [
                AuditReadRefusedException::reentrant(),
                'The audit trail was read while a read of it, an audit record\'s write or its failure, or an event mapper was running,'
                . ' so the read was refused.',
            ],
            'in a transaction' => [
                AuditReadRefusedException::inTransaction('reporting'),
                'The audit trail is not read while a transaction is open on the [reporting] connection,'
                . ' since the read\'s record, or a row it would show, could still be rolled back.',
            ],
            'not durable' => [
                AuditReadRefusedException::notDurable('App\Audit\QueueStore'),
                'The audit trail is read only through a durable store, and App\Audit\QueueStore does not say it is. Bind one, or use the outbox.',
            ],
            'keeps no artifacts' => [
                AuditReadRefusedException::keepsNoArtifacts('App\Audit\LogStore'),
                'The audit trail is read only through a store that keeps attachments, and App\Audit\LogStore keeps none.'
                . ' Bind one that does, such as the database store.',
            ],
            'unrecorded' => [
                AuditReadRefusedException::unrecorded(),
                'The read of the audit trail could not be recorded, so nothing was disclosed.',
            ],
            'evidence altered' => [
                AuditReadRefusedException::evidenceAltered(),
                'The record of the read of the audit trail would not keep its evidence exactly, so the read was refused.',
            ],
            'failed' => [
                AuditReadRefusedException::failed('Illuminate\Database\QueryException'),
                'The read of the audit trail failed with Illuminate\Database\QueryException, so nothing was disclosed.',
            ],
            'publish failed' => [
                AuditReadRefusedException::publishFailed(\ErrorException::class),
                'The export was recorded, but its file could not be published (ErrorException), so nothing was published.',
            ],
        ];
    }

    /**
     * Each message names only the class or connection given, never a value.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException  $exception
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testEachMessageNamesNoValue(AuditReadRefusedException $exception, string $message): void
    {
        self::assertSame($message, $exception->getMessage());
        self::assertSame(0, $exception->getCode());
    }

    /**
     * Rows of `[exception, reason, class, connection]`, one per constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException, 1: \SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal, 2: ?string, 3: ?string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideCauses(): iterable
    {
        yield from [
            'reentrant'          => [AuditReadRefusedException::reentrant(), ReadRefusal::REENTRANT, null, null],
            'in a transaction'   => [AuditReadRefusedException::inTransaction('reporting'), ReadRefusal::IN_TRANSACTION, null, 'reporting'],
            'not durable'        => [AuditReadRefusedException::notDurable('App\Audit\QueueStore'), ReadRefusal::NOT_DURABLE, 'App\Audit\QueueStore', null],
            'keeps no artifacts' => [AuditReadRefusedException::keepsNoArtifacts('App\Audit\LogStore'), ReadRefusal::KEEPS_NO_ARTIFACTS, 'App\Audit\LogStore', null],
            'unrecorded'         => [AuditReadRefusedException::unrecorded(), ReadRefusal::UNRECORDED, null, null],
            'evidence altered'   => [AuditReadRefusedException::evidenceAltered(), ReadRefusal::EVIDENCE_ALTERED, null, null],
            'failed'             => [AuditReadRefusedException::failed('Illuminate\Database\QueryException'), ReadRefusal::FAILED, 'Illuminate\Database\QueryException', null],
            'publish failed'     => [AuditReadRefusedException::publishFailed(\ErrorException::class), ReadRefusal::PUBLISH_FAILED, \ErrorException::class, null],
        ];
    }

    /**
     * Each refusal types its cause, so callers need not parse the message.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException  $exception
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal  $reason
     * @param  ?string  $class
     * @param  ?string  $connection
     * @return void
     */
    #[DataProvider('provideCauses')]
    public function testEachRefusalCarriesItsTypedCause(AuditReadRefusedException $exception, ReadRefusal $reason, ?string $class, ?string $connection): void
    {
        self::assertSame($reason, $exception->reason);
        self::assertSame($class, $exception->class);
        self::assertSame($connection, $exception->connection);
    }

    /**
     * Every reason has a named constructor; the constructor is private.
     *
     * @return void
     */
    public function testEveryReasonHasItsConstructorAndNoOtherWayIn(): void
    {
        $reasons = array_map(static fn (array $row): ReadRefusal => $row[1], iterator_to_array(self::provideCauses()));

        self::assertSame(ReadRefusal::cases(), array_values($reasons));
        self::assertTrue((new \ReflectionMethod(AuditReadRefusedException::class, '__construct'))->isPrivate());
    }

    /**
     * Each named constructor takes only a class or connection name.
     *
     * @return void
     */
    public function testEachConstructorTakesOnlyANameOrNothing(): void
    {
        $taken = [];

        foreach ((new \ReflectionClass(AuditReadRefusedException::class))->getMethods(\ReflectionMethod::IS_STATIC) as $method) {
            $taken[$method->getName()] = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $method->getParameters());
        }

        ksort($taken);

        self::assertSame([
            'evidenceAltered'  => [],
            'failed'           => ['exceptionClass'],
            'inTransaction'    => ['connection'],
            'keepsNoArtifacts' => ['storeClass'],
            'notDurable'       => ['storeClass'],
            'publishFailed'    => ['exceptionClass'],
            'reentrant'        => [],
            'unrecorded'       => [],
        ], $taken);
    }

    /**
     * None carries a previous exception, so no message or bindings leak.
     *
     * @return void
     */
    public function testNoneCarriesAPreviousException(): void
    {
        $refusals = iterator_to_array(self::provideRefusals());

        self::assertCount(8, $refusals);

        foreach ($refusals as $name => [$exception]) {
            self::assertNull($exception->getPrevious(), $name);
        }
    }

    /**
     * It is a final runtime exception: the read's state refused it.
     *
     * @return void
     */
    public function testIsAFinalRuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, AuditReadRefusedException::unrecorded());
        self::assertTrue((new \ReflectionClass(AuditReadRefusedException::class))->isFinal());
    }
}
