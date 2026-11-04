<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\DetectsConcurrencyErrors;
use Illuminate\Database\LostConnectionException;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;

/**
 * Unit tests for the classifier of database failures that end a host's
 * transaction: the concurrency errors and lost connections Laravel recognises,
 * a PostgreSQL transaction already aborted, an ordinary failure that is none of
 * these, and the sanitised deadlock that still reads as a concurrency error to
 * Laravel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureClassifier::class)]
final class FailureClassifierTest extends TestCase
{
    /**
     * Rows of `[failure]`: a concurrency error by its code and by each engine's
     * phrase, raw and wrapped in a query exception.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideConcurrencyErrors(): iterable
    {
        $mysql   = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';
        $timeout = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

        $serialisation = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

        yield from [
            'the 40001 code'                => [self::pdoFailure('Serialization failure.', ['40001', 0, ''], '40001')],
            'the 40001 code as an integer'  => [self::pdoFailure('Serialization failure.', null, 40001)],
            'the 40001 code, wrapped'       => [self::wrapped(self::pdoFailure('Serialization failure.', ['40001', 7, ''], '40001'))],
            'MySQL\'s deadlock'             => [self::wrapped(self::pdoFailure($mysql, null, 'HY000'))],
            'PostgreSQL\'s deadlock'        => [self::wrapped(self::pdoFailure('SQLSTATE[40P01]: Deadlock detected: 7 ERROR:  deadlock detected', null, '40P01'))],
            'SQLite\'s locked database'     => [self::wrapped(self::pdoFailure('SQLSTATE[HY000]: General error: 5 database is locked', null, 'HY000'))],
            'a lock wait timeout'           => [self::wrapped(self::pdoFailure($timeout, null, 'HY000'))],
            'a phrase in a plain exception' => [new \RuntimeException('Deadlock found when trying to get lock')],
            'Laravel\'s wrapper'            => [new DeadlockException($serialisation, 0)],
        ];
    }

    /**
     * Each concurrency error is known as one, and none is a lost connection or
     * an aborted host.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideConcurrencyErrors')]
    public function testKnowsAConcurrencyError(\Throwable $failure): void
    {
        $classifier = new FailureClassifier;

        self::assertTrue($classifier->isConcurrencyError($failure));
        self::assertFalse($classifier->isLostConnection($failure));
        self::assertFalse($classifier->isAbortedHost($failure));
    }

    /**
     * Rows of `[failure]`: a lost connection by MySQL's and PostgreSQL's
     * phrase, raw and wrapped in a query exception.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideLostConnections(): iterable
    {
        yield from [
            'MySQL\'s server gone away'       => [self::wrapped(self::pdoFailure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away', ['HY000', 2006, ''], 'HY000'))],
            'PostgreSQL\'s lost server'       => [self::wrapped(self::pdoFailure('SQLSTATE[08006] [7] no connection to the server', ['08006', 7, ''], '08006'))],
            'the server gone away, unwrapped' => [self::pdoFailure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away', null, 'HY000')],
            'Laravel\'s own exception'        => [new LostConnectionException('Lost connection and no reconnector available.')],
        ];
    }

    /**
     * Each lost connection is known as one, and none is a concurrency error or
     * an aborted host.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideLostConnections')]
    public function testKnowsALostConnection(\Throwable $failure): void
    {
        $classifier = new FailureClassifier;

        self::assertTrue($classifier->isLostConnection($failure));
        self::assertFalse($classifier->isConcurrencyError($failure));
        self::assertFalse($classifier->isAbortedHost($failure));
    }

    /**
     * Rows of `[failure]`: a statement in an aborted PostgreSQL transaction, by
     * its error information or its code alone, raw and wrapped.
     *
     * @return iterable<string, array{0: \PDOException}>
     */
    public static function provideAbortedHosts(): iterable
    {
        $message = 'SQLSTATE[25P02]: In failed sql transaction: 7 ERROR:  current transaction is aborted, commands ignored until end of transaction block';

        yield from [
            'the error information, wrapped' => [self::wrapped(self::pdoFailure($message, ['25P02', 7, ''], '25P02'))],
            'the error information alone'    => [self::pdoFailure($message, ['25P02', 7, ''], 'HY000')],
            'the code alone'                 => [self::pdoFailure($message, null, '25P02')],
        ];
    }

    /**
     * A statement refused because the host's transaction is already aborted is
     * known as such, and is neither a concurrency error nor a lost connection,
     * so it follows the failure policy.
     *
     * @param  \PDOException  $failure
     * @return void
     */
    #[DataProvider('provideAbortedHosts')]
    public function testKnowsAnAbortedHost(\PDOException $failure): void
    {
        $classifier = new FailureClassifier;

        self::assertTrue($classifier->isAbortedHost($failure));
        self::assertFalse($classifier->isConcurrencyError($failure));
        self::assertFalse($classifier->isLostConnection($failure));
    }

    /**
     * PostgreSQL's lock timeout is known by its SQLSTATE at the root of the
     * chain, from the driver's error information or its code, whatever its
     * message, and is no concurrency error or lost connection as Laravel
     * recognises them, so a host's savepoint still recovers it; any other
     * failure, a deadlock or the same SQLSTATE only in a message among them, is
     * none.
     *
     * @return void
     */
    public function testKnowsAPostgresLockTimeout(): void
    {
        $classifier = new FailureClassifier;
        $message    = 'SQLSTATE[55P03]: Lock not available: 7 ERROR:  canceling statement due to lock timeout';
        $byInfo     = self::wrapped(self::pdoFailure($message, ['55P03', 7, ''], 0));
        $byCode     = self::pdoFailure('The statement was cancelled.', null, '55P03');

        self::assertTrue($classifier->isLockTimeout($byInfo));
        self::assertTrue($classifier->isLockTimeout($byCode));
        self::assertFalse($classifier->isConcurrencyError($byInfo));
        self::assertFalse($classifier->isLostConnection($byInfo));
        self::assertFalse($classifier->isLockTimeout(self::pdoFailure('SQLSTATE[40P01]: deadlock detected', ['40P01', 7, ''], '40P01')));
        self::assertFalse($classifier->isLockTimeout(new \RuntimeException($message)));
    }

    /**
     * Rows of `[failure]`: failures a savepoint recovers, and failures that
     * only look like an aborted host.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideOrdinaryFailures(): iterable
    {
        $duplicate = 'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry';

        yield from [
            'a unique violation'                 => [self::wrapped(self::pdoFailure($duplicate, ['23000', 1062, ''], '23000'))],
            'a missing table'                    => [self::wrapped(self::pdoFailure('SQLSTATE[42S02]: Base table or view not found', ['42S02', 1146, ''], '42S02'))],
            'a plain exception'                  => [new \RuntimeException('The store is down.')],
            'the aborted state in a message'     => [new \RuntimeException('SQLSTATE[25P02]: In failed sql transaction')],
            'the aborted state in lower case'    => [self::pdoFailure('Failed.', ['25p02', 7, ''], '25p02')],
            'the aborted state as a driver code' => [self::pdoFailure('Failed.', ['HY000', '25P02', ''], 'HY000')],
            'a serialisation code as a driver'   => [self::pdoFailure('Failed.', ['HY000', 40001, ''], 'HY000')],
            'the aborted state, not from PDO'    => [self::coded('25P02')],
        ];
    }

    /**
     * An ordinary failure is none of the three.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideOrdinaryFailures')]
    public function testAnOrdinaryFailureIsNeither(\Throwable $failure): void
    {
        $classifier = new FailureClassifier;

        self::assertFalse($classifier->isConcurrencyError($failure));
        self::assertFalse($classifier->isLostConnection($failure));
        self::assertFalse($classifier->isAbortedHost($failure));
    }

    /**
     * Rows of `[phrase]`: each phrase Laravel reads a failure's message for.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLaravelsPhrases(): iterable
    {
        yield from [
            'a deadlock'            => ['deadlock detected'],
            'MySQL\'s deadlock'     => ['Deadlock found when trying to get lock'],
            'a locked database'     => ['database is locked'],
            'a lock wait'           => ['Lock wait timeout exceeded; try restarting transaction'],
            'the server gone'       => ['server has gone away'],
            'a lost connection'     => ['Lost connection'],
            'a broken pipe'         => ['Broken pipe'],
            'a reset by the peer'   => ['Connection reset by peer'],
            'a missing socket file' => ['No such file or directory'],
        ];
    }

    /**
     * A record's value in a query exception's bindings cannot make an ordinary
     * failure look fatal: what is read is the driver's own message.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('provideLaravelsPhrases')]
    public function testABoundValueIsNeverRead(string $phrase): void
    {
        $classifier = new FailureClassifier;
        $driver     = self::pdoFailure('SQLSTATE[HY000]: General error: 1 no such table', ['HY000', 1, ''], 'HY000');
        $failure    = new QueryException('main', 'insert into entries (note) values (?)', [$phrase], $driver);

        self::assertStringContainsString($phrase, $failure->getMessage());
        self::assertFalse($classifier->isConcurrencyError($failure));
        self::assertFalse($classifier->isLostConnection($failure));
    }

    /**
     * A constraint or data failure's driver message can quote the value itself,
     * as PostgreSQL's `DETAIL` and MySQL's duplicate entry do, so its SQLSTATE
     * decides.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('provideLaravelsPhrases')]
    public function testAValueADriverQuotesIsNeverRead(string $phrase): void
    {
        $classifier = new FailureClassifier;

        foreach (['23505', '22P02'] as $state) {
            foreach ([$state, 'HY000'] as $code) {
                $failure = self::wrapped(self::pdoFailure("SQLSTATE[{$state}]: Key (source_record_id)=({$phrase}) already exists.", [$state, 7, ''], $code));

                self::assertFalse($classifier->isConcurrencyError($failure), $state . ' ' . $code);
                self::assertFalse($classifier->isLostConnection($failure), $state . ' ' . $code);
            }
        }
    }

    /**
     * A phrase in something other than a database failure says nothing of a
     * database connection: a store's cURL error, a queue's Redis error or a
     * channel's missing file ended no transaction.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('provideLaravelsPhrases')]
    public function testAPhraseOutsideTheDatabaseIsNoLostConnection(string $phrase): void
    {
        self::assertFalse((new FailureClassifier)->isLostConnection(new \RuntimeException('cURL error 56: ' . $phrase)));
    }

    /**
     * A database failure is read through whatever wraps it, so a wrapper of a
     * driver's lost connection is one.
     *
     * @return void
     */
    public function testALostConnectionIsReadThroughAWrapper(): void
    {
        $wrapped = new \RuntimeException('The store failed.', 0, self::pdoFailure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away', null, 'HY000'));

        self::assertTrue((new FailureClassifier)->isLostConnection($wrapped));
    }

    /**
     * The connection a failure happened on is what a query exception in its
     * chain says, and nothing says it otherwise.
     *
     * @return void
     */
    public function testNamesTheConnectionAFailureHappenedOn(): void
    {
        $classifier = new FailureClassifier;
        $query      = self::wrapped(self::pdoFailure('Failed.', null, 'HY000'));

        self::assertSame('audit', $classifier->connectionOf($query));
        self::assertSame('audit', $classifier->connectionOf(new DeadlockException('Wrapped.', 0, $query)));
        self::assertNull($classifier->connectionOf(new \RuntimeException('Failed.')));
    }

    /**
     * Rows of `[connections failed on, open, whether a nameless failure counts,
     * expected]`.
     *
     * @return iterable<string, array{0: list<?string>, 1: list<string>, 2: bool, 3: bool}>
     */
    public static function provideReaches(): iterable
    {
        yield from [
            'named and open'          => [['main'], ['main'], false, true],
            'named and not open'      => [['audit'], ['main'], true, false],
            'unnamed, counted'        => [[null], ['main'], true, true],
            'unnamed, not counted'    => [[null], ['main'], false, false],
            'one of several open'     => [['audit', 'main'], ['main'], false, true],
            'no failure named at all' => [[], ['main'], true, false],
            'named with nothing open' => [['main'], [], true, false],
        ];
    }

    /**
     * A failure reaches a transaction only on a connection that had one open,
     * and one that names no connection counts as the caller says.
     *
     * @param  list<?string>  $failed
     * @param  list<string>  $open
     * @param  bool  $unnamedCounts
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideReaches')]
    public function testReachesAnOpenTransactionOnItsOwnConnection(array $failed, array $open, bool $unnamedCounts, bool $expected): void
    {
        self::assertSame($expected, (new FailureClassifier)->reachesAnOpenTransaction($failed, $open, $unnamedCounts));
    }

    /**
     * A masked failure keeps its class, connection and SQLSTATE, and holds no
     * binding, so Laravel reads no record's value as a concurrency error.
     *
     * @return void
     */
    public function testMaskingRemovesTheBindings(): void
    {
        $driver  = self::pdoFailure('SQLSTATE[HY000]: no such table', ['HY000', 1, ''], 'HY000');
        $failure = new QueryException('main', 'insert into entries (note) values (?)', ['deadlock detected'], $driver);
        $masked  = FailureClassifier::masked($failure);

        self::assertSame(QueryException::class, $masked::class);
        self::assertSame('main', $masked->connectionName);
        self::assertStringNotContainsString('deadlock detected', $masked->getMessage());
        self::assertSame('HY000', $masked->errorInfo[0] ?? null);
        self::assertSame(1, $masked->errorInfo[1] ?? null);
    }

    /**
     * Rethrowing masked throws the failure as `masked()` gives it: the same
     * class and connection, with no binding in its message.
     *
     * @return void
     */
    public function testRethrowingMaskedThrowsTheMaskedFailure(): void
    {
        $driver  = self::pdoFailure('SQLSTATE[HY000]: no such table', ['HY000', 1, ''], 'HY000');
        $failure = new QueryException('main', 'insert into entries (note) values (?)', ['secret-note'], $driver);

        try {
            FailureClassifier::rethrowMasked($failure);
        } catch (QueryException $masked) {
            self::assertSame(QueryException::class, $masked::class);
            self::assertSame('main', $masked->connectionName);
            self::assertSame([], $masked->getBindings());
            self::assertStringNotContainsString('secret-note', $masked->getMessage());
        }
    }

    /**
     * A masked unique violation stays one, so the store still resolves it, and
     * a value the driver quoted is gone from its message too.
     *
     * @return void
     */
    public function testMaskingKeepsAUniqueViolationAndDropsWhatTheDriverQuoted(): void
    {
        $driver  = self::pdoFailure('SQLSTATE[23505]: Key (source_record_id)=(deadlock detected) already exists.', ['23505', 7, ''], '23505');
        $failure = new UniqueConstraintViolationException('main', 'insert into entries (id) values (?)', ['x'], $driver);
        $masked  = FailureClassifier::masked($failure);

        self::assertInstanceOf(UniqueConstraintViolationException::class, $masked);
        self::assertStringNotContainsString('deadlock detected', $masked->getMessage());
        self::assertSame('23505', $masked->errorInfo[0] ?? null);
        self::assertSame(7, $masked->errorInfo[1] ?? null);
    }

    /**
     * The SQLSTATE in the driver's error information wins over its code, so a
     * constraint failure whose code says otherwise still loses its quoted
     * value.
     *
     * @return void
     */
    public function testTheErrorInformationsStateWinsOverTheCode(): void
    {
        $driver  = self::pdoFailure('SQLSTATE[23505]: Key (source_record_id)=(deadlock detected) already exists.', ['23505', 7, ''], 'HY000');
        $failure = new QueryException('main', 'insert into entries (id) values (?)', ['x'], $driver);
        $masked  = FailureClassifier::masked($failure);

        self::assertStringNotContainsString('deadlock detected', $masked->getMessage());
        self::assertSame('23505', $masked->errorInfo[0] ?? null);
    }

    /**
     * A real concurrency error is still a concurrency error once masked, so a
     * deadlock on the savepoint reaches Laravel's own handling.
     *
     * @return void
     */
    public function testMaskingKeepsARealConcurrencyError(): void
    {
        $classifier = new FailureClassifier;
        $masked     = FailureClassifier::masked(self::wrapped(self::pdoFailure('SQLSTATE[40P01]: Deadlock detected: 7 ERROR:  deadlock detected', ['40P01', 7, ''], '40P01')));

        self::assertTrue($classifier->isConcurrencyError($masked));
        self::assertStringContainsString('deadlock detected', $masked->getMessage());
    }

    /**
     * The sanitised deadlock is a `DeadlockException` with the settled message
     * and code, and Laravel's own trait, which decides whether its
     * `transaction()` retries, reads it as a concurrency error: the pin for the
     * host's retry on every supported Laravel. It is neither a lost connection
     * nor an aborted host.
     *
     * @return void
     */
    public function testTheSanitisedDeadlockIsStillAConcurrencyError(): void
    {
        $deadlock = FailureClassifier::sanitisedDeadlock();

        $laravel = new class {
            use DetectsConcurrencyErrors;

            /**
             * Whether Laravel reads the failure as a concurrency error.
             *
             * @param  \Throwable  $failure
             * @return bool
             */
            public function isRetried(\Throwable $failure): bool
            {
                return $this->causedByConcurrencyError($failure);
            }
        };

        self::assertInstanceOf(DeadlockException::class, $deadlock);
        self::assertSame('Deadlock found when trying to get lock; an audit write was abandoned inside the host transaction.', $deadlock->getMessage());
        self::assertSame(40001, $deadlock->getCode());
        self::assertTrue($laravel->isRetried($deadlock));
        self::assertTrue((new FailureClassifier)->isConcurrencyError($deadlock));
        self::assertFalse((new FailureClassifier)->isLostConnection($deadlock));
        self::assertFalse((new FailureClassifier)->isAbortedHost($deadlock));
    }

    /**
     * The sanitised deadlock has no previous exception and no error
     * information, and each call builds a new one, so nothing of a failure
     * travels with it and no throw changes another's trace.
     *
     * @return void
     */
    public function testTheSanitisedDeadlockHasNoPrevious(): void
    {
        $deadlock = FailureClassifier::sanitisedDeadlock();

        self::assertNull($deadlock->getPrevious());
        self::assertNull($deadlock->errorInfo);
        self::assertNotSame($deadlock, FailureClassifier::sanitisedDeadlock());
    }

    /**
     * The failure is marked sensitive on each predicate, so a stack trace
     * through the classifier never shows it.
     *
     * @return void
     */
    public function testTheFailureIsMarkedSensitive(): void
    {
        foreach (['isConcurrencyError', 'isLostConnection', 'isAbortedHost'] as $method) {
            $parameter = (new \ReflectionMethod(FailureClassifier::class, $method))->getParameters()[0];

            self::assertSame('failure', $parameter->getName(), $method);
            self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $method);
        }
    }

    /**
     * A PDO failure with the error information and the code a driver would give
     * it.
     *
     * @param  string  $message
     * @param  ?list<int|string>  $errorInfo
     * @param  int|string  $code
     * @return \PDOException
     */
    private static function pdoFailure(string $message, ?array $errorInfo, int|string $code): \PDOException
    {
        return new class ($message, $errorInfo, $code) extends \PDOException {
            /**
             * Constructor.
             *
             * @param  string  $message
             * @param  ?list<int|string>  $errorInfo
             * @param  int|string  $code
             */
            public function __construct(string $message, ?array $errorInfo, int|string $code)
            {
                parent::__construct($message);

                $this->errorInfo = $errorInfo;
                $this->code      = $code;
            }
        };
    }

    /**
     * A failure that is not a database failure, with a code a userland
     * exception may set to anything.
     *
     * @param  string  $code
     * @return \RuntimeException
     */
    private static function coded(string $code): \RuntimeException
    {
        return new class ($code) extends \RuntimeException {
            /**
             * Constructor.
             *
             * @param  string  $code
             */
            public function __construct(string $code)
            {
                parent::__construct('Failed.');

                $this->code = $code;
            }
        };
    }

    /**
     * The failure wrapped in a query exception, as Laravel throws it.
     *
     * @param  \PDOException  $failure
     * @return \Illuminate\Database\QueryException
     */
    private static function wrapped(\PDOException $failure): QueryException
    {
        return new QueryException('audit', 'insert into "audit_log_entries" ("id") values (?)', ['01932b4e-8a40-7000-8000-000000000001'], $failure);
    }
}
