<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Database\QueryException;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Tests\Concerns\SearchesForSecrets;

/**
 * Unit tests for the diagnostics of a failed write, which hold nothing secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteDiagnostics::class)]
final class WriteDiagnosticsTest extends TestCase
{
    use MockeryPHPUnitIntegration, SearchesForSecrets;

    /** @var string The id of the record that was not written. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The store the write failed on. */
    private const string STORE = 'SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore';

    /**
     * Any failure gives its class, with no SQLSTATE or driver code.
     *
     * @return void
     */
    public function testAnyFailureGivesItsClass(): void
    {
        $failure     = new \RuntimeException('The store is down.', 40001);
        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE, 'audit', 'warehouse');

        self::assertSame([
            'recordId'       => self::ID,
            'eventCode'      => 'invoice.approved',
            'operation'      => FailedOperation::STORE,
            'store'          => self::STORE,
            'exceptionClass' => \RuntimeException::class,
            'sqlState'       => null,
            'driverCode'     => null,
            'connection'     => 'audit',
            'destination'    => 'warehouse',
        ], get_object_vars($diagnostics));
    }

    /**
     * The connection, the destination and the event code may each be `null`.
     *
     * @return void
     */
    public function testTheConnectionAndDestinationDefaultToNull(): void
    {
        $diagnostics = WriteDiagnostics::of(new \LogicException('Refused.'), self::ID, null, FailedOperation::DRAIN, self::STORE);

        self::assertNull($diagnostics->eventCode);
        self::assertNull($diagnostics->connection);
        self::assertNull($diagnostics->destination);
        self::assertSame(FailedOperation::DRAIN, $diagnostics->operation);
    }

    /**
     * An anonymous class is named by its parent, never its path or NUL byte.
     *
     * @return void
     */
    public function testAnAnonymousClassIsNamedWithoutItsPath(): void
    {
        $failure = new class ('The store is down.') extends \RuntimeException {};

        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertStringContainsString(__FILE__, $failure::class);
        self::assertSame('RuntimeException@anonymous', $diagnostics->exceptionClass);
    }

    /**
     * A query exception gives its PDO SQLSTATE, driver code and its own alias.
     *
     * @return void
     */
    public function testAQueryExceptionGivesItsStateCodeAndAlias(): void
    {
        $previous = self::pdoFailure('SQLSTATE[23000]: Integrity constraint violation', ['23000', 1062, 'Duplicate entry']);
        $failure  = new QueryException('audit', 'insert into "audit_log_entries" ("id") values (?)', [self::ID], $previous);

        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE, 'mysql');

        self::assertSame(QueryException::class, $diagnostics->exceptionClass);
        self::assertSame('23000', $diagnostics->sqlState);
        self::assertSame(1062, $diagnostics->driverCode);
        self::assertSame('audit', $diagnostics->connection);
    }

    /**
     * A query exception without a string alias keeps the one given.
     *
     * @return void
     */
    public function testAQueryExceptionWithoutAnAliasKeepsTheOneGiven(): void
    {
        $failure = new class ('audit', 'select 1', [], new \RuntimeException('Gone.')) extends QueryException {
            /**
             * Constructor.
             *
             * @param  string  $connectionName
             * @param  string  $sql
             * @param  list<string>  $bindings
             * @param  \Throwable  $previous
             */
            public function __construct(string $connectionName, string $sql, array $bindings, \Throwable $previous)
            {
                parent::__construct($connectionName, $sql, $bindings, $previous);

                // Laravel documents a string, and this is the alias it does not
                // promise
                // @phpstan-ignore assign.propertyType
                $this->connectionName = null;
            }
        };

        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE, 'mysql');

        self::assertSame('mysql', $diagnostics->connection);
    }

    /**
     * A PDO failure with no query, as a failed `SAVEPOINT` is, gives its state.
     *
     * @return void
     */
    public function testAPdoExceptionWithoutAQueryGivesItsState(): void
    {
        $pdo = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);

        try {
            $pdo->exec('RELEASE SAVEPOINT trans2');

            self::fail('Expected the savepoint statement to fail.');
        } catch (\PDOException $failure) {
            $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE, 'audit');
        }

        self::assertSame(\PDOException::class, $diagnostics->exceptionClass);
        self::assertSame('HY000', $diagnostics->sqlState);
        self::assertSame(1, $diagnostics->driverCode);
        self::assertSame('audit', $diagnostics->connection);
    }

    /**
     * Rows of `[error information, code, SQLSTATE]`: error information wins,
     * then the code.
     *
     * @return iterable<string, array{0: ?list<int|string|null>, 1: int|string, 2: ?string}>
     */
    public static function provideStates(): iterable
    {
        yield from [
            'the error information\'s state'         => [['40001', 1213, 'Deadlock'], '23000', '40001'],
            'the code with no error information'     => [null, '25P02', '25P02'],
            'the code past a lower-case state'       => [['hy000', 1, 'Failed'], '42S02', '42S02'],
            'the code past a state of four'          => [['4200', 1, 'Failed'], '42000', '42000'],
            'the code past a state of six'           => [['420001', 1, 'Failed'], '08006', '08006'],
            'the code past a state that is an int'   => [[23000, 1, 'Failed'], 'HY000', 'HY000'],
            'neither a state'                        => [['', null, null], 'abcde', null],
            'an integer code is not a state'         => [null, 40001, null],
            'empty error information and a bad code' => [[], '0', null],
            'a state with a trailing line feed'      => [["40001\n", 1, 'Failed'], "40001\n", null],
        ];
    }

    /**
     * Each SQLSTATE is read as the row says.
     *
     * @param  ?list<int|string|null>  $errorInfo
     * @param  int|string  $code
     * @param  ?string  $state
     * @return void
     */
    #[DataProvider('provideStates')]
    public function testTheStateIsReadOnlyWhenItIsOne(?array $errorInfo, int|string $code, ?string $state): void
    {
        $diagnostics = WriteDiagnostics::of(self::pdoFailure('Failed.', $errorInfo, $code), self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertSame($state, $diagnostics->sqlState);
    }

    /**
     * Rows of `[driver code given, kept]`: an integer or a digit string.
     *
     * @return iterable<string, array{0: int|string|null, 1: ?int}>
     */
    public static function provideDriverCodes(): iterable
    {
        yield from [
            'an integer'                   => [1062, 1062],
            'a negative integer'           => [-1, -1],
            'a string of digits'           => ['1213', 1213],
            'a string of padded digits'    => ['0042', 42],
            'eighteen digits'              => [str_repeat('9', 18), 999999999999999999],
            'letters'                      => ['ORA-03114', null],
            'digits then letters'          => ['12a', null],
            'a sign'                       => ['-1', null],
            'a decimal'                    => ['1.5', null],
            'empty'                        => ['', null],
            'a trailing line feed'         => ["1062\n", null],
            'nineteen digits, past an int' => [str_repeat('9', 19), null],
            'none'                         => [null, null],
        ];
    }

    /**
     * Each driver code is kept or dropped as the row says.
     *
     * @param  int|string|null  $driverCode
     * @param  ?int  $kept
     * @return void
     */
    #[DataProvider('provideDriverCodes')]
    public function testANonNumericDriverCodeIsDropped(int|string|null $driverCode, ?int $kept): void
    {
        $diagnostics = WriteDiagnostics::of(self::pdoFailure('Failed.', ['HY000', $driverCode, 'Failed']), self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertSame($kept, $diagnostics->driverCode);
    }

    /**
     * A failure not from the database gives no SQLSTATE, whatever its code.
     *
     * @return void
     */
    public function testAFailureNotFromPdoGivesNoState(): void
    {
        $failure = new class ('Failed.') extends \RuntimeException {
            /**
             * Constructor.
             *
             * @param  string  $message
             */
            public function __construct(string $message)
            {
                parent::__construct($message);

                $this->code = '40001';
            }
        };

        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertNull($diagnostics->sqlState);
        self::assertNull($diagnostics->driverCode);
    }

    /**
     * Error information without a driver code gives none.
     *
     * @return void
     */
    public function testErrorInformationWithoutACodeGivesNone(): void
    {
        $diagnostics = WriteDiagnostics::of(self::pdoFailure('Failed.', ['HY000']), self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertSame('HY000', $diagnostics->sqlState);
        self::assertNull($diagnostics->driverCode);
    }

    /**
     * A long class name is cut to the cap on a character boundary.
     *
     * @return void
     */
    public function testALongClassNameIsCut(): void
    {
        $prefix = 'Tests\Long\\' . str_repeat('a', WriteDiagnostics::CLASS_MAX_BYTES - 12);
        $long   = \Mockery::namedMock($prefix . 'éFailure', \RuntimeException::class);
        $whole  = \Mockery::namedMock('Tests\Whole\\' . str_repeat('b', WriteDiagnostics::CLASS_MAX_BYTES - 12), \RuntimeException::class);

        $cut  = WriteDiagnostics::of($long, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE)->exceptionClass;
        $kept = WriteDiagnostics::of($whole, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE)->exceptionClass;

        self::assertSame($prefix, $cut);
        self::assertSame(WriteDiagnostics::CLASS_MAX_BYTES - 1, strlen($cut));
        self::assertTrue(mb_check_encoding($cut, 'UTF-8'));
        self::assertSame($whole::class, $kept);
        self::assertSame(WriteDiagnostics::CLASS_MAX_BYTES, strlen($kept));
    }

    /**
     * Only the class, code, error information and alias are read.
     *
     * @return void
     */
    public function testNoMessageSqlOrBindingIsRead(): void
    {
        $previous = self::pdoFailure('SQLSTATE[23000]: Duplicate entry ' . self::SECRET, ['23000', 1062, 'Duplicate entry ' . self::SECRET]);
        $failure  = self::guardedQueryFailure($previous);

        $diagnostics = WriteDiagnostics::of($failure, self::ID, 'invoice.approved', FailedOperation::STORE, self::STORE);

        self::assertTrue(self::holdsText($failure, self::SECRET));
        self::assertHoldsNoSecret($diagnostics, 'the diagnostics');
        self::assertSame(['23000', 1062, 'audit'], [$diagnostics->sqlState, $diagnostics->driverCode, $diagnostics->connection]);
    }

    /**
     * The failure is marked sensitive on entry and on each helper.
     *
     * @return void
     */
    public function testTheFailureIsMarkedSensitive(): void
    {
        $marked = [];

        foreach ((new \ReflectionClass(WriteDiagnostics::class))->getMethods(\ReflectionMethod::IS_STATIC) as $method) {
            foreach ($method->getParameters() as $parameter) {
                if (!in_array($parameter->getName(), ['failure', 'errorInfo'], true)) {
                    continue;
                }

                $marked[$method->getName() . '.' . $parameter->getName()] = $parameter->getAttributes(\SensitiveParameter::class) !== [];
            }
        }

        ksort($marked);

        self::assertSame([
            'driverCodeOf.errorInfo' => true,
            'of.failure'             => true,
            'sqlStateOf.errorInfo'   => true,
            'sqlStateOf.failure'     => true,
        ], $marked);
    }

    /**
     * A PDO failure with the error information and code a driver gives.
     *
     * @param  string  $message
     * @param  ?list<int|string|null>  $errorInfo
     * @param  int|string  $code
     * @return \PDOException
     */
    private static function pdoFailure(string $message, ?array $errorInfo, int|string $code = 0): \PDOException
    {
        return new class ($message, $errorInfo, $code) extends \PDOException {
            /**
             * Constructor.
             *
             * @param  string  $message
             * @param  ?list<int|string|null>  $errorInfo
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
     * A query exception whose accessors of the secret throw.
     *
     * @param  \PDOException  $previous
     * @return \Illuminate\Database\QueryException
     */
    private static function guardedQueryFailure(\PDOException $previous): QueryException
    {
        $details = ['driver' => 'mysql', 'host' => self::SECRET . '.db.internal', 'port' => 3306, 'database' => 'audit'];

        return new class ('audit', 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], $previous, $details) extends QueryException {
            /**
             * Refuse to give the SQL.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function getSql(): never
            {
                throw new \LogicException('The SQL was read.');
            }

            /**
             * Refuse to give the bindings.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function getBindings(): never
            {
                throw new \LogicException('The bindings were read.');
            }

            /**
             * Refuse to give the SQL with its bindings.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function getRawSql(): never
            {
                throw new \LogicException('The raw SQL was read.');
            }

            /**
             * Refuse to give the connection's name through its accessor.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function getConnectionName(): never
            {
                throw new \LogicException('The connection name was read through its accessor.');
            }

            /**
             * Refuse to give the connection's details.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function getConnectionDetails(): never
            {
                throw new \LogicException('The connection details were read.');
            }

            /**
             * Refuse to be written as a string.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function __toString(): never
            {
                throw new \LogicException('The failure was written as a string.');
            }
        };
    }
}
