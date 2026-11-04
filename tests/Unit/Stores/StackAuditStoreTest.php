<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\ConnectionResolver;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;

/**
 * Unit tests for the store that delivers each record to several destinations:
 * the order and the bytes each receives, that a failing destination neither
 * stops nor undoes the others, the one exception naming each failure and what
 * it holds, the destinations it refuses, and what it says of durability,
 * transactions and attachments, which it keeps only when every destination
 * does.
 *
 * The storage connection the database store compares against is read through
 * the configuration facade, so each test gives the facade a bare application
 * whose configuration names `testing` as the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StackAuditStore::class)]
final class StackAuditStoreTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The id of the record delivered. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The message every refused destination id fails with. */
    private const string BAD_ID_MESSAGE = 'A stack store\'s destination id must be 1 to 64 lower-case letters, digits, dots, underscores or hyphens, '
        . 'starting with a letter or a digit, and not a decimal integer.';

    /** @var ?\Illuminate\Container\Container The global container before the test replaced it. */
    private ?Container $previousContainer = null;

    /**
     * Give the configuration facade an application whose default connection is
     * `testing` and whose storage connection is not set.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previousContainer = Container::getInstance();

        $application = new Application;

        $application->instance('config', new Repository(['database' => ['default' => 'testing'], 'audit-log' => []]));

        Facade::setFacadeApplication($application);
    }

    /**
     * Take the application from the facade and put the global container back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance($this->previousContainer);

        parent::tearDown();
    }

    /**
     * Each destination receives the record in the order the stack lists them.
     *
     * @return void
     */
    public function testDeliversToEachInOrder(): void
    {
        $order = [];

        $stack = new StackAuditStore([
            'third' => new CallbackStore(static function () use (&$order): void {
                $order[] = 'third';
            }),
            'first' => new CallbackStore(static function () use (&$order): void {
                $order[] = 'first';
            }),
            'second' => new CallbackStore(static function () use (&$order): void {
                $order[] = 'second';
            }),
        ]);

        $stack->store(self::finalised());

        self::assertSame(['third', 'first', 'second'], $order);
    }

    /**
     * Every destination receives the very record the stack was given, so each
     * holds the same bytes.
     *
     * @return void
     */
    public function testEveryDestinationReceivesIdenticalBytes(): void
    {
        $record = self::finalised();
        $first  = new PlainStore;
        $second = new PlainStore;
        $bytes  = [];

        $third = new CallbackStore(static function (FinalisedRecord $received) use (&$bytes): void {
            $bytes[] = CanonicalEncoder::encode($received->toArray());
        });

        (new StackAuditStore(['database' => $first, 'siem' => $second, 'archive' => $third]))->store($record);

        self::assertSame([$record], $first->received());
        self::assertSame([$record], $second->received());
        self::assertSame([CanonicalEncoder::encode($record->toArray())], $bytes);
    }

    /**
     * A destination that fails stops none of those after it.
     *
     * @return void
     */
    public function testAFailingDestinationDoesNotStopTheOthers(): void
    {
        $second = new PlainStore;
        $third  = new PlainStore;

        $stack = new StackAuditStore([
            'database' => CallbackStore::failingWith(new \RuntimeException('The database is down.')),
            'siem'     => $second,
            'archive'  => $third,
        ]);

        try {
            $stack->store(self::finalised());
        } catch (StackDeliveryException) {
            // The exception is pinned elsewhere; only who received counts here
        }

        self::assertSame(1, $second->calls());
        self::assertSame(1, $third->calls());
    }

    /**
     * A second destination that fails leaves the record with the first, which
     * the stack never undoes.
     *
     * @return void
     */
    public function testAFailingSecondDestinationKeepsTheFirst(): void
    {
        $record = self::finalised();
        $first  = new PlainStore;
        $stack  = new StackAuditStore(['database' => $first, 'siem' => CallbackStore::failingWith(new \RuntimeException('The SIEM is down.'))]);

        try {
            $stack->store($record);

            self::fail('Expected the stack to throw for its failed destination.');
        } catch (StackDeliveryException $exception) {
            self::assertSame(['siem' => \RuntimeException::class], $exception->failures);
        }

        self::assertSame([$record], $first->received());
    }

    /**
     * Every destination is tried before the stack throws, and it throws one
     * exception for all the failures.
     *
     * @return void
     */
    public function testThrowsOneExceptionAfterAttemptingAll(): void
    {
        $last  = new PlainStore;
        $stack = new StackAuditStore([
            'database' => CallbackStore::failingWith(new \RuntimeException('The database is down.')),
            'siem'     => CallbackStore::failingWith(new \LogicException('The SIEM refused it.')),
            'archive'  => $last,
        ]);

        try {
            $stack->store(self::finalised());

            self::fail('Expected the stack to throw.');
        } catch (StackDeliveryException $exception) {
            self::assertSame(1, $last->calls());
            self::assertSame(['database' => \RuntimeException::class, 'siem' => \LogicException::class], $exception->failures);
        }
    }

    /**
     * The exception names the record and each destination that failed, in
     * order, with its failure's class, and leaves out those that succeeded;
     * an anonymous failure is named without its file path.
     *
     * @return void
     */
    public function testNamesEachFailedDestination(): void
    {
        $anonymous = new class ('The archive is full.') extends \RuntimeException {};

        $stack = new StackAuditStore([
            'database' => new PlainStore,
            'siem'     => CallbackStore::failingWith(new \LogicException('The SIEM refused it.')),
            'archive'  => CallbackStore::failingWith($anonymous),
        ]);

        try {
            $stack->store(self::finalised());

            self::fail('Expected the stack to throw.');
        } catch (StackDeliveryException $exception) {
            self::assertSame(self::ID, $exception->recordId);
            self::assertSame(['siem' => \LogicException::class, 'archive' => 'RuntimeException@anonymous'], $exception->failures);
            $failed = 'siem (LogicException), archive (RuntimeException@anonymous)';

            self::assertSame('Audit record ' . self::ID . ' did not reach every destination: ' . $failed . '.', $exception->getMessage());
        }
    }

    /**
     * An error, not only an exception, is kept as a failure and does not stop
     * the destinations after it.
     *
     * @return void
     */
    public function testAnErrorIsAFailureLikeAnyOther(): void
    {
        $last  = new PlainStore;
        $stack = new StackAuditStore(['database' => CallbackStore::failingWith(new \TypeError('A value of the wrong type.')), 'archive' => $last]);

        try {
            $stack->store(self::finalised());

            self::fail('Expected the stack to throw.');
        } catch (StackDeliveryException $exception) {
            self::assertSame(['database' => \TypeError::class], $exception->failures);
            self::assertSame(1, $last->calls());
        }
    }

    /**
     * Neither a failure's message nor its bindings, nor the record the stack
     * was given, reach the exception: no previous, no message, no frame.
     *
     * @return void
     */
    public function testNoSecretOfAFailureReachesTheException(): void
    {
        $failure = new QueryException('testing', 'insert into audit_log_entries values (?)', [self::SECRET], new \PDOException('could not write ' . self::SECRET));
        $record  = self::finalised(['note' => self::SECRET]);
        $stack   = new StackAuditStore(['database' => CallbackStore::failingWith($failure), 'siem' => CallbackStore::failingWith(new \RuntimeException(self::SECRET))]);

        try {
            $stack->store($record);

            self::fail('Expected the stack to throw.');
        } catch (StackDeliveryException $exception) {
            self::assertNull($exception->getPrevious());
            self::assertTrue(self::holdsText($failure, self::SECRET));
            self::assertHoldsNoSecret($exception, 'the stack\'s exception');
        }
    }

    /**
     * Rows of `[failures, concurrency, lost connection]`: what each combination
     * of failures sets, so either flag is set by any destination, not only the
     * first or the last.
     *
     * @return iterable<string, array{0: list<\Throwable>, 1: bool, 2: bool}>
     */
    public static function provideClassifiedFailures(): iterable
    {
        yield from [
            'an ordinary failure'                 => [[new \RuntimeException('The SIEM is down.')], false, false],
            'a deadlock'                          => [[new DeadlockException('Deadlock found when trying to get lock')], true, false],
            'a serialisation failure by its code' => [[new \PDOException('Serialization failure', 40001)], true, false],
            'a deadlock, then an ordinary one'    => [[new DeadlockException('Deadlock found when trying to get lock'), new \RuntimeException('The SIEM is down.')], true, false],
            'an ordinary one, then a deadlock'    => [[new \RuntimeException('The SIEM is down.'), new DeadlockException('Deadlock found when trying to get lock')], true, false],
            'a lost connection'                   => [[new \PDOException('server has gone away')], false, true],
            'a lost connection, then ordinary'    => [[new \PDOException('no connection to the server'), new \RuntimeException('The SIEM is down.')], false, true],
            'an ordinary one, then lost'          => [[new \RuntimeException('The SIEM is down.'), new \PDOException('server has gone away')], false, true],
            'a deadlock and a lost connection'    => [[new DeadlockException('Deadlock found when trying to get lock'), new \PDOException('server has gone away')], true, true],
        ];
    }

    /**
     * Whether any destination failed with a concurrency error, or with a lost
     * connection, is set from the raw failures as Laravel classifies them.
     *
     * @param  list<\Throwable>  $failures
     * @param  bool  $concurrency
     * @param  bool  $lost
     * @return void
     */
    #[DataProvider('provideClassifiedFailures')]
    public function testEachFlagIsSetByAnyDestination(array $failures, bool $concurrency, bool $lost): void
    {
        $destinations = ['database' => new PlainStore];

        foreach ($failures as $index => $failure) {
            $destinations['failing-' . $index] = CallbackStore::failingWith($failure);
        }

        $exception = self::thrownBy(new StackAuditStore($destinations));

        self::assertSame($concurrency, $exception->causedByConcurrency);
        self::assertSame($lost, $exception->causedByLostConnection);
    }

    /**
     * An aborted PostgreSQL host a destination met is kept as a flag of its
     * own, so a spill bound to that transaction is discarded though the failure
     * itself is gone.
     *
     * @return void
     */
    public function testAnAbortedHostIsFlagged(): void
    {
        $aborted = new \PDOException('SQLSTATE[25P02]: In failed sql transaction');

        $aborted->errorInfo = ['25P02', 7, ''];

        $exception = self::thrownBy(new StackAuditStore(['database' => CallbackStore::failingWith($aborted), 'log' => new PlainStore]));

        self::assertTrue($exception->causedByAbortedHost);
        self::assertFalse($exception->causedByConcurrency);
        self::assertFalse($exception->causedByLostConnection);
        self::assertSame([], $exception->fatalConnections);

        self::assertFalse(self::thrownBy(new StackAuditStore(['database' => CallbackStore::failingWith(new \RuntimeException('Down.'))]))->causedByAbortedHost);
    }

    /**
     * The connection each fatal failure happened on is kept, so it is compared
     * with the transactions open; one that does not say is kept as `null`, and
     * a failure that is not fatal keeps nothing.
     *
     * @return void
     */
    public function testKeepsTheConnectionOfEachFatalFailure(): void
    {
        $query = new QueryException('audit', 'insert', [], new \PDOException('SQLSTATE[40001]: Deadlock found when trying to get lock'));

        $exception = self::thrownBy(new StackAuditStore([
            'first'  => CallbackStore::failingWith($query),
            'second' => CallbackStore::failingWith(new \RuntimeException('Deadlock found when trying to get lock')),
            'third'  => CallbackStore::failingWith(new \RuntimeException('Down.')),
        ]));

        self::assertSame(['audit', null], $exception->fatalConnections);
    }

    /**
     * A deadlock in a first destination is flagged as a concurrency error, so
     * it is still fatal to a host transaction.
     *
     * @return void
     */
    public function testAConcurrencyErrorIsFlagged(): void
    {
        $exception = self::thrownBy(new StackAuditStore([
            'database' => CallbackStore::failingWith(new DeadlockException('Deadlock found when trying to get lock')),
            'siem'     => new PlainStore,
        ]));

        self::assertTrue($exception->causedByConcurrency);
        self::assertFalse($exception->causedByLostConnection);
    }

    /**
     * A lost connection in a destination is flagged as one.
     *
     * @return void
     */
    public function testALostConnectionIsFlagged(): void
    {
        $exception = self::thrownBy(new StackAuditStore([
            'database' => CallbackStore::failingWith(new \PDOException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away')),
            'siem'     => new PlainStore,
        ]));

        self::assertFalse($exception->causedByConcurrency);
        self::assertTrue($exception->causedByLostConnection);
    }

    /**
     * A stack with no destination is refused.
     *
     * @return void
     */
    public function testRefusesAnEmptyStack(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A stack store needs at least one destination.');

        new StackAuditStore([]);
    }

    /**
     * Destinations given as a list, without ids, are refused.
     *
     * @return void
     */
    public function testRefusesAListOfDestinations(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A stack store\'s destinations must be keyed by their ids, not listed.');

        new StackAuditStore([new PlainStore, new PlainStore]);
    }

    /**
     * Rows of `[id]`: destination ids the pattern refuses, and a decimal
     * integer, which PHP turns into a numeric key.
     *
     * @return iterable<string, array{0: int|string}>
     */
    public static function provideBadDestinationIds(): iterable
    {
        yield from [
            'upper case'               => ['A'],
            'a leading hyphen'         => ['-a'],
            'a leading dot'            => ['.a'],
            'a leading underscore'     => ['_a'],
            '65 characters'            => [str_repeat('a', 65)],
            'empty'                    => [''],
            'a space'                  => ['a b'],
            'a trailing line feed'     => ["a\n"],
            'a slash'                  => ['a/b'],
            'a decimal integer'        => [5],
            'a decimal integer string' => ['7'],
            'zero'                     => ['0'],
        ];
    }

    /**
     * Each refused destination id fails closed, with the pattern described;
     * a destination keyed by a decimal integer is refused even after a valid
     * one, so the stack is not a list.
     *
     * @param  int|string  $id
     * @return void
     */
    #[DataProvider('provideBadDestinationIds')]
    public function testRefusesABadDestinationId(int|string $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::BAD_ID_MESSAGE);

        new StackAuditStore(['database' => new PlainStore, $id => new PlainStore]);
    }

    /**
     * Rows of `[id]`: destination ids at the edges of the pattern.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGoodDestinationIds(): iterable
    {
        yield from [
            'one letter'          => ['a'],
            'a digit, a letter'   => ['9z'],
            '64 characters'       => [str_repeat('a', 64)],
            'every punctuation'   => ['a.b_c-d'],
            'digits with a zero'  => ['007'],
            'a digit, then words' => ['1st-archive'],
        ];
    }

    /**
     * Each id at the edges of the pattern is kept as given.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideGoodDestinationIds')]
    public function testKeepsAGoodDestinationId(string $id): void
    {
        $store = new PlainStore;

        self::assertSame([$id => $store], (new StackAuditStore([$id => $store]))->destinations());
    }

    /**
     * A member that is not an audit store is refused, naming its id and its
     * type, never its value.
     *
     * @return void
     */
    public function testRefusesAMemberThatIsNoStore(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The stack store\'s destination [siem] must be an audit store, not string.');

        new StackAuditStore(['database' => new PlainStore, 'siem' => self::SECRET]);
    }

    /**
     * A stack among the destinations is refused, so a destination id names one
     * place.
     *
     * @return void
     */
    public function testRefusesANestedStack(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The stack store\'s destination [both] is a stack store; a stack cannot hold another.');

        new StackAuditStore(['database' => new PlainStore, 'both' => new StackAuditStore(['inner' => new PlainStore])]);
    }

    /**
     * Rows of `[destinations, durable]`: a stack is durable exactly when its
     * first destination says it is.
     *
     * @return iterable<string, array{0: array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>, 1: bool}>
     */
    public static function provideFirstDestinations(): iterable
    {
        yield from [
            'database first'           => [['database' => self::database(), 'log' => self::log()], true],
            'log first'                => [['log' => self::log(), 'database' => self::database()], false],
            'plain first'              => [['plain' => new PlainStore, 'database' => self::database()], false],
            'null first'               => [['null' => new NullAuditStore, 'database' => self::database()], false],
            'a durable store first'    => [['remote' => CallbackStore::saying(true), 'log' => self::log()], true],
            'a store saying no, first' => [['remote' => CallbackStore::saying(false), 'database' => self::database()], false],
            'database alone'           => [['database' => self::database()], true],
        ];
    }

    /**
     * The stack asks its first destination, and only that one, whether a return
     * is durable; one without the contract is not.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>  $destinations
     * @param  bool  $durable
     * @return void
     */
    #[DataProvider('provideFirstDestinations')]
    public function testAsksItsFirstDestinationIfItIsDurable(array $destinations, bool $durable): void
    {
        self::assertSame($durable, (new StackAuditStore($destinations))->isDurable());
    }

    /**
     * Rows of `[destinations, connection, participates]`: a stack joins a
     * transaction on a connection exactly when every destination does.
     *
     * @return iterable<string, array{0: array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>, 1: string, 2: bool}>
     */
    public static function provideParticipation(): iterable
    {
        yield from [
            'database alone'                     => [['database' => self::database()], 'testing', true],
            'database alone, another connection' => [['database' => self::database()], 'audit', false],
            'database then log'                  => [['database' => self::database(), 'log' => self::log()], 'testing', false],
            'database then plain'                => [['database' => self::database(), 'plain' => new PlainStore], 'testing', false],
            'plain then database'                => [['plain' => new PlainStore, 'database' => self::database()], 'testing', false],
            'two participating'                  => [['database' => self::database(), 'mirror' => CallbackStore::saying(true, ['testing'])], 'testing', true],
            'two, the second elsewhere'          => [['database' => self::database(), 'mirror' => CallbackStore::saying(true, ['audit'])], 'testing', false],
            'two, the first elsewhere'           => [['mirror' => CallbackStore::saying(true, ['audit']), 'database' => self::database()], 'testing', false],
        ];
    }

    /**
     * The stack asks every destination whether it joins a transaction on the
     * connection, and joins only when all of them do, so a line or a remote
     * write is never mistaken for one that rolls back.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>  $destinations
     * @param  string  $connection
     * @param  bool  $participates
     * @return void
     */
    #[DataProvider('provideParticipation')]
    public function testParticipatesOnlyWhenEveryDestinationDoes(array $destinations, string $connection, bool $participates): void
    {
        self::assertSame($participates, (new StackAuditStore($destinations))->participatesIn($connection));
    }

    /**
     * Rows of `[destinations, accepts]`: a stack keeps attachments exactly when
     * every destination implements the contract and says it does.
     *
     * @return iterable<string, array{0: array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>, 1: bool}>
     */
    public static function provideAttachmentCapabilities(): iterable
    {
        yield from [
            'database alone'               => [['database' => self::database()], true],
            'null alone'                   => [['null' => new NullAuditStore], true],
            'log alone'                    => [['log' => self::log()], false],
            'plain alone'                  => [['plain' => new PlainStore], false],
            'database then null'           => [['database' => self::database(), 'null' => new NullAuditStore], true],
            'database then log'            => [['database' => self::database(), 'log' => self::log()], false],
            'log then database'            => [['log' => self::log(), 'database' => self::database()], false],
            'database then plain'          => [['database' => self::database(), 'plain' => new PlainStore], false],
            'a durable store without it'   => [['database' => self::database(), 'remote' => CallbackStore::saying(true, ['testing'])], false],
            'two saying so'                => [['first' => self::attachmentStore(true), 'second' => self::attachmentStore(true)], true],
            'the second saying not'        => [['first' => self::attachmentStore(true), 'second' => self::attachmentStore(false)], false],
            'the first saying not'         => [['first' => self::attachmentStore(false), 'second' => self::attachmentStore(true)], false],
            'the last of three saying not' => [['first' => self::database(), 'second' => new NullAuditStore, 'third' => self::attachmentStore(false)], false],
        ];
    }

    /**
     * The stack asks every destination whether it keeps attachments, and keeps
     * them only when all of them do, so a bulk record is never handed to a
     * stack one destination of which would lose its manifest; one without the
     * contract keeps none.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>  $destinations
     * @param  bool  $accepts
     * @return void
     */
    #[DataProvider('provideAttachmentCapabilities')]
    public function testAStackAcceptsAttachmentsOnlyWhenEveryDestinationDoes(array $destinations, bool $accepts): void
    {
        $stack = new StackAuditStore($destinations);

        self::assertInstanceOf(AcceptsAttachments::class, $stack);
        self::assertSame($accepts, $stack->acceptsAttachments());
    }

    /**
     * Every destination is handed the very bundle the stack was given, its
     * attachment included, so a database destination keeps the bundle.
     *
     * @return void
     */
    public function testEveryDestinationIsHandedTheBundle(): void
    {
        $bundle   = RecordFactory::finalisedBundle();
        $first    = new PlainStore;
        $second   = new PlainStore;
        $received = [];

        $third = new CallbackStore(static function (FinalisedRecord $record) use (&$received): void {
            $received[] = $record->record->attachment;
        });

        (new StackAuditStore(['database' => $first, 'mirror' => $second, 'archive' => $third]))->store($bundle);

        self::assertNotNull($bundle->record->attachment);
        self::assertSame([$bundle], $first->received());
        self::assertSame([$bundle], $second->received());
        self::assertSame([$bundle->record->attachment], $received);
    }

    /**
     * The destinations come back under their ids, as the very stores given, in
     * the order given.
     *
     * @return void
     */
    public function testKeepsItsDestinationsInOrder(): void
    {
        $siem     = new PlainStore;
        $database = new PlainStore;
        $archive  = CallbackStore::saying(true);

        $destinations = (new StackAuditStore(['siem' => $siem, 'database' => $database, 'archive' => $archive]))->destinations();

        self::assertSame(['siem', 'database', 'archive'], array_keys($destinations));
        self::assertSame(['siem' => $siem, 'database' => $database, 'archive' => $archive], $destinations);
    }

    /**
     * The record is marked sensitive, so a frame of the stack shows no value of
     * it in a trace.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(StackAuditStore::class, 'store'))->getParameters()[0];

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The exception the stack throws when it stores a record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\StackAuditStore  $stack
     * @return \SineMacula\Laravel\AuditLog\Stores\StackDeliveryException
     */
    private static function thrownBy(StackAuditStore $stack): StackDeliveryException
    {
        try {
            $stack->store(self::finalised());
        } catch (StackDeliveryException $exception) {
            return $exception;
        }

        self::fail('Expected the stack to throw.');
    }

    /**
     * A finalised record of an approved invoice, with the properties given.
     *
     * @param  array<string, string>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function finalised(array $properties = ['amount' => '1200.00']): FinalisedRecord
    {
        return new FinalisedRecord(RecordFactory::captured($properties, self::ID), '2026-11-01T12:00:01.000000Z', 1, 'k2026', str_repeat('a', 64));
    }

    /**
     * The database store, with no connection to write to: only what it says of
     * itself is asked.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     */
    private static function database(): AuditStore
    {
        $connections = new ConnectionResolver;
        $ring        = new KeyRing(new IntegritySettings(new Repository([])));

        $tombstones = new PruneTombstones($connections, new NullPruneLedger, new PruneCoverage(new SealSigner($ring)));

        return new DatabaseAuditStore($connections, new RowCodec, new RecordSigner($ring), $tombstones);
    }

    /**
     * The log store, with a log manager that is never asked for a channel.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     */
    private static function log(): AuditStore
    {
        return new LogAuditStore(new LogManager(new Container), new NdjsonFormatter);
    }

    /**
     * A store that keeps nothing and says whether it keeps attachments.
     *
     * @param  bool  $accepts
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     */
    private static function attachmentStore(bool $accepts): AuditStore
    {
        return new readonly class ($accepts) implements AcceptsAttachments {
            /**
             * Constructor.
             *
             * @param  bool  $accepts
             */
            public function __construct(

                /** Whether the store says it keeps attachments. */
                private bool $accepts,
            ) {}

            /**
             * Keep nothing.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                // A store for what it says of itself alone keeps nothing
            }

            /**
             * Whether the store says it keeps attachments.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return $this->accepts;
            }
        };
    }
}
