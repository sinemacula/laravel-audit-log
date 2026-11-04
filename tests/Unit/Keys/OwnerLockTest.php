<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an owner's lock, against a connection that answers as each
 * engine does: the key and name an owner's lock goes by, PostgreSQL's advisory
 * lock taken only inside a transaction and its wait bounded only when asked,
 * MySQL's named lock granted or refused and released as often as it is held,
 * SQLite taking nothing, any other engine refused, and a lock not granted
 * refused naming neither the owner nor the lock.
 *
 * The statements MySQL and PostgreSQL run are pinned here as strings, and run
 * against those engines in the integration tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerLock::class)]
final class OwnerLockTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The owner's type. */
    private const string TYPE = 'App\Models\User';

    /** @var int The lock key of user 42: positive, since its digest's first bit is clear. */
    private const int KEY_42 = 475930243103179438;

    /** @var int The lock key of user 43: negative, since its digest's first bit is set. */
    private const int KEY_43 = -5585180763842391142;

    /** @var string The lock name of user 42. */
    private const string NAME_42 = 'audit_log_owner_069ad808d607c2ae1ee9912c8da4eeec';

    /**
     * An owner's key is the signed 64-bit integer of the first 8 bytes of the
     * SHA-256 of its canonical encoding: the same for every reference to the
     * owner, different for another owner, and negative when the digest's first
     * bit is set.
     *
     * @return void
     */
    public function testTheKeyIsStablePerOwner(): void
    {
        self::assertSame(self::KEY_42, OwnerLock::key(Reference::of(self::TYPE, 42)));
        self::assertSame(self::KEY_42, OwnerLock::key(Reference::of(self::TYPE, '42')));
        self::assertSame(self::KEY_43, OwnerLock::key(Reference::of(self::TYPE, '43')));
        self::assertNotSame(OwnerLock::key(Reference::of(self::TYPE, '42')), OwnerLock::key(Reference::of('App\Models\Team', '42')));
    }

    /**
     * An owner's name is `audit_log_owner_` and the first 32 hex characters of
     * the same digest: 48 characters, within the 64 MySQL allows, stable per
     * owner and different for another.
     *
     * @return void
     */
    public function testTheNameFitsSixtyFourCharacters(): void
    {
        $name = OwnerLock::name(Reference::of(self::TYPE, '42'));

        self::assertSame(self::NAME_42, $name);
        self::assertSame(48, strlen($name));
        self::assertLessThanOrEqual(64, strlen(OwnerLock::name(Reference::of(str_repeat('t', 191), str_repeat('9', 191)))));
        self::assertNotSame($name, OwnerLock::name(Reference::of(self::TYPE, '43')));
    }

    /**
     * On PostgreSQL the lock is a transaction's, so asking for it outside one
     * is refused before any statement runs.
     *
     * @return void
     */
    public function testOnPostgresItRefusesOutsideATransaction(): void
    {
        $connection = self::connection('pgsql', 0);

        $connection->shouldNotReceive('statement');
        $connection->shouldNotReceive('select');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('On PostgreSQL an owner\'s lock is held by a transaction, and is taken only inside one.');

        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'), true);
    }

    /**
     * On PostgreSQL a bounded wait sets the transaction's local lock timeout to
     * the wait first, then takes the advisory lock of the owner's key on the
     * writer.
     *
     * @return void
     */
    public function testOnPostgresABoundedWaitSetsTheLocalTimeoutFirst(): void
    {
        $connection = self::connection('pgsql', 1);

        $connection->expects('statement')->with('set local lock_timeout = \'10s\'')->once()->ordered()->andReturnTrue();
        $connection->expects('select')->with('select pg_advisory_xact_lock(?)', [self::KEY_42], false)->once()->ordered()->andReturn([]);

        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'), true);

        $shorter = self::connection('pgsql', 2);

        $shorter->expects('statement')->with('set local lock_timeout = \'3s\'')->once()->andReturnTrue();
        $shorter->expects('select')->with('select pg_advisory_xact_lock(?)', [self::KEY_43], false)->once()->andReturn([]);

        self::lock(3)->acquire($shorter, Reference::of(self::TYPE, '43'), true);
    }

    /**
     * On PostgreSQL an unbounded wait, an erasure's, sets no lock timeout, so
     * nothing later in its transaction is bounded either; it is the default.
     *
     * @return void
     */
    public function testOnPostgresAnUnboundedWaitSetsNoTimeout(): void
    {
        $connection = self::connection('pgsql', 1);

        $connection->shouldNotReceive('statement');
        $connection->expects('select')->with('select pg_advisory_xact_lock(?)', [self::KEY_42], false)->twice()->andReturn([]);

        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'));
        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'), false);
    }

    /**
     * On PostgreSQL a wait cancelled by its lock timeout is refused naming the
     * wait alone, with no previous exception, so neither the owner nor the
     * lock's key reaches a reporter.
     *
     * @return void
     */
    public function testOnPostgresALockTimeoutIsRefusedNamingNeither(): void
    {
        $connection = self::connection('pgsql', 1);

        $connection->allows('statement')->andReturnTrue();
        $connection->allows('select')->andThrow(self::failure('55P03'));

        try {
            self::lock(4)->acquire($connection, Reference::of(self::TYPE, '42'), true);
            self::fail('Expected the wait to be refused.');
        } catch (OwnerLockTimeoutException $exception) {
            self::assertSame(OwnerLockTimeoutException::after(4)->getMessage(), $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertStringNotContainsString((string) self::KEY_42, $exception->getMessage());
        }
    }

    /**
     * On PostgreSQL any other failure is thrown as the failure it was, its
     * state kept and its bindings, the owner's key among them, dropped.
     *
     * @return void
     */
    public function testOnPostgresAnyOtherFailureIsThrownWithoutItsBindings(): void
    {
        $connection = self::connection('pgsql', 1);

        $connection->allows('select')->andThrow(self::failure('08006'));

        self::assertStringContainsString((string) self::KEY_42, self::failure('08006')->getMessage());

        $thrown = null;

        try {
            self::lock()->acquire($connection, Reference::of(self::TYPE, '42'));
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(QueryException::class, $thrown, 'The failure was not thrown.');
        self::assertSame([], $thrown->getBindings());
        self::assertStringNotContainsString((string) self::KEY_42, $thrown->getMessage());
        self::assertSame('select pg_advisory_xact_lock(?)', $thrown->getSql());
        self::assertSame('08006', $thrown->errorInfo[0] ?? null);
    }

    /**
     * Rows of `[the answer get_lock() gives, whether the lock is granted]`: an
     * integer or its decimal string from the driver, `0` when the wait ran out
     * and SQL's `NULL` when the server could not take it.
     *
     * @return iterable<string, array{0: int|string|null, 1: bool}>
     */
    public static function provideMysqlAnswers(): iterable
    {
        yield from [
            'granted, as an integer' => [1, true],
            'granted, as a string'   => ['1', true],
            'timed out'              => [0, false],
            'timed out, as a string' => ['0', false],
            'not taken'              => [null, false],
            'anything else'          => ['yes', false],
        ];
    }

    /**
     * On MySQL the session's named lock is asked for with the wait on the
     * writer, whether or not the wait is asked to be bounded, and anything but
     * a grant is refused naming the wait alone.
     *
     * @param  int|string|null  $answer
     * @param  bool  $granted
     * @return void
     */
    #[DataProvider('provideMysqlAnswers')]
    public function testOnMysqlTheLockIsGrantedOrRefused(int|string|null $answer, bool $granted): void
    {
        $connection = self::connection('mysql', 0);

        $connection->shouldNotReceive('statement');
        $connection->expects('selectOne')->with('select get_lock(?, ?) as answer', [self::NAME_42, 7], false)->once()->andReturn((object) ['answer' => $answer]);

        try {
            self::lock(7)->acquire($connection, Reference::of(self::TYPE, '42'));
            self::assertTrue($granted, 'The lock was taken though it was not granted.');
        } catch (OwnerLockTimeoutException $exception) {
            self::assertFalse($granted, 'The lock was refused though it was granted.');
            self::assertSame(OwnerLockTimeoutException::after(7)->getMessage(), $exception->getMessage());
        }
    }

    /**
     * On MySQL a server that answers with no row at all is refused as a lock
     * not granted.
     *
     * @return void
     */
    public function testOnMysqlNoAnswerIsRefused(): void
    {
        $connection = self::connection('mysql', 0);

        $connection->allows('selectOne')->andReturnNull();

        $this->expectException(OwnerLockTimeoutException::class);

        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'), true);
    }

    /**
     * On MySQL the lock is released as often as the session answers that it
     * released one, so every level a retried transaction took is freed, and no
     * more than five times.
     *
     * @return void
     */
    public function testOnMysqlReleaseRepeatsWhileHeldAtMostFiveTimes(): void
    {
        $twice = self::connection('mysql', 0);

        $twice->expects('selectOne')->with('select release_lock(?) as answer', [self::NAME_42], false)->times(3)->andReturn(
            (object) ['answer' => 1],
            (object) ['answer' => '1'],
            (object) ['answer' => 0],
        );

        self::lock()->release($twice, Reference::of(self::TYPE, '42'));

        $always = self::connection('mysql', 0);

        $always->expects('selectOne')->times(5)->andReturn((object) ['answer' => 1]);

        self::lock()->release($always, Reference::of(self::TYPE, '42'));

        $never = self::connection('mysql', 0);

        $never->expects('selectOne')->once()->andReturn((object) ['answer' => null]);

        self::lock()->release($never, Reference::of(self::TYPE, '42'));
    }

    /**
     * Rows of `[driver]`: the engines whose lock ends with its transaction, or
     * that take none.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEnginesThatReleaseNothing(): iterable
    {
        yield from [
            'PostgreSQL' => ['pgsql'],
            'SQLite'     => ['sqlite'],
        ];
    }

    /**
     * On PostgreSQL and SQLite releasing runs no statement: the transaction's
     * end released PostgreSQL's lock, and SQLite took none.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideEnginesThatReleaseNothing')]
    public function testReleaseElsewhereRunsNothing(string $driver): void
    {
        $connection = self::connection($driver, 1);

        $connection->shouldNotReceive('selectOne');
        $connection->shouldNotReceive('select');
        $connection->shouldNotReceive('statement');

        self::lock()->release($connection, Reference::of(self::TYPE, '42'));
    }

    /**
     * On SQLite taking the lock runs no statement, inside a transaction or not:
     * the database's write lock serialises the transactions.
     *
     * @return void
     */
    public function testOnSqliteNothingIsTaken(): void
    {
        foreach ([0, 1] as $level) {
            $connection = self::connection('sqlite', $level);

            $connection->shouldNotReceive('selectOne');
            $connection->shouldNotReceive('select');
            $connection->shouldNotReceive('statement');

            self::lock()->acquire($connection, Reference::of(self::TYPE, '42'), true);
        }
    }

    /**
     * Any other engine is refused before any statement runs, naming the engine.
     *
     * @return void
     */
    public function testAnotherEngineIsRefused(): void
    {
        $connection = self::connection('sqlsrv', 1);

        $connection->shouldNotReceive('selectOne');
        $connection->shouldNotReceive('select');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An owner\'s lock is taken on MySQL, PostgreSQL or SQLite, and the connection is sqlsrv.');

        self::lock()->acquire($connection, Reference::of(self::TYPE, '42'));
    }

    /**
     * Rows of `[wait in seconds]`: waits outside 1 to 10 seconds.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedWaits(): iterable
    {
        yield from [
            'none'                => [0],
            'negative'            => [-1],
            'one second too long' => [OwnerLock::WAIT_SECONDS + 1],
        ];
    }

    /**
     * A wait outside 1 to 10 seconds is refused as the lock is made.
     *
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideRefusedWaits')]
    public function testTheWaitIsFromOneToTenSeconds(int $seconds): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An owner\'s lock waits from 1 to 10 seconds.');

        new OwnerLock(new FailureClassifier, $seconds);
    }

    /**
     * The longest wait is ten seconds, and a lock made without one waits that
     * long.
     *
     * @return void
     */
    public function testTheDefaultWaitIsTenSeconds(): void
    {
        self::assertSame(10, OwnerLock::WAIT_SECONDS);

        $connection = self::connection('mysql', 0);

        $connection->expects('selectOne')->with('select get_lock(?, ?) as answer', [self::NAME_42, 10], false)->once()->andReturn((object) ['answer' => 1]);

        (new OwnerLock(new FailureClassifier))->acquire($connection, Reference::of(self::TYPE, '42'));
    }

    /**
     * A lock with the wait given.
     *
     * @param  int  $seconds
     * @return \SineMacula\Laravel\AuditLog\Keys\OwnerLock
     */
    private static function lock(int $seconds = OwnerLock::WAIT_SECONDS): OwnerLock
    {
        return new OwnerLock(new FailureClassifier, $seconds);
    }

    /**
     * A connection on the driver, at the transaction level.
     *
     * @param  string  $driver
     * @param  int  $level
     * @return \Illuminate\Database\Connection&\Mockery\MockInterface
     */
    private static function connection(string $driver, int $level): Connection&MockInterface
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturn($level);

        return $connection;
    }

    /**
     * A failed advisory lock statement with the SQLSTATE, its key bound, so the
     * framework's message would show the key in its SQL.
     *
     * @param  string  $state
     * @return \Illuminate\Database\QueryException
     */
    private static function failure(string $state): QueryException
    {
        $driver            = new \PDOException(sprintf('SQLSTATE[%s]: the statement failed', $state));
        $driver->errorInfo = [$state, 7, 'the statement failed'];

        return new QueryException('pgsql', 'select pg_advisory_xact_lock(?)', [self::KEY_42], $driver);
    }
}
