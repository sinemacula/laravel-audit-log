<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseTransactionsManager as FrameworkTransactionsManager;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\DedicatedSession;
use Tests\TestCase;

/**
 * Feature tests for when a session of its own could not see or write what the
 * storage connection does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DedicatedSession::class)]
final class DedicatedSessionTest extends TestCase
{
    /** @var string The connection each database form is configured on. */
    private const string PROBE = 'dedicated_session_probe';

    /**
     * Forget the probe's connection.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::purge(self::PROBE);

        parent::tearDown();
    }

    /**
     * Rows of `[driver, database, whether it is in-memory]`: each way a
     * database is named.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideDatabases(): iterable
    {
        yield from [
            'the memory name'                       => ['sqlite', ':memory:', true],
            'a URI with the mode first'             => ['sqlite', 'file:audit_session?mode=memory&cache=shared', true],
            'a URI with the mode after another'     => ['sqlite', 'file:audit_session?cache=shared&mode=memory', true],
            'a file'                                => ['sqlite', '/tmp/audit-session.sqlite', false],
            'a URI of a file'                       => ['sqlite', 'file:/tmp/audit-session.sqlite?cache=shared', false],
            'a file named for memory'               => ['sqlite', '/tmp/mode=memory.sqlite', false],
            'another engine named as memory'        => ['mysql', ':memory:', false],
            'another engine with a memory-like URI' => ['pgsql', 'audit?mode=memory', false],
        ];
    }

    /**
     * An in-memory SQLite database is known by each form it is named in, and
     * nothing else is taken for one.
     *
     * @param  string  $driver
     * @param  string  $database
     * @param  bool  $inMemory
     * @return void
     */
    #[DataProvider('provideDatabases')]
    public function testAnInMemoryDatabaseIsKnownByEachForm(string $driver, string $database, bool $inMemory): void
    {
        app(ConfigRepository::class)->set('database.connections.' . self::PROBE, ['driver' => $driver, 'database' => $database, 'host' => '127.0.0.1', 'prefix' => '']);

        self::assertSame($inMemory, DedicatedSession::isInMemory(DB::connection(self::PROBE)));
    }

    /**
     * Only the base transaction the testing manager wraps a test in counts as
     * the testing transaction.
     *
     * @return void
     */
    public function testOnlyTheTestingManagersBaseTransactionIsTheTestingTransaction(): void
    {
        $storage = DB::connection(self::CONNECTION);

        self::assertInstanceOf(FrameworkTransactionsManager::class, app('db.transactions'));
        self::assertNotInstanceOf(DatabaseTransactionsManager::class, app('db.transactions'));
        self::assertFalse(DedicatedSession::isTheTestingTransaction($storage));

        $storage->beginTransaction();

        self::assertFalse(DedicatedSession::isTheTestingTransaction($storage));

        $storage->rollBack();

        $manager = new DatabaseTransactionsManager([self::CONNECTION]);

        $this->app?->instance('db.transactions', $manager);
        $storage->setTransactionManager($manager);

        self::assertFalse(DedicatedSession::isTheTestingTransaction($storage));

        $storage->beginTransaction();

        self::assertTrue(DedicatedSession::isTheTestingTransaction($storage));

        $storage->beginTransaction();

        self::assertFalse(DedicatedSession::isTheTestingTransaction($storage));

        $storage->rollBack();

        $this->app?->forgetInstance('db.transactions');
        $this->app?->offsetUnset('db.transactions');

        self::assertFalse(DedicatedSession::isTheTestingTransaction($storage));

        $storage->rollBack();
    }

    /**
     * A session forces a handle of its own, never a shared persistent one, and
     * keeps every other setting.
     *
     * @return void
     */
    public function testASessionNeverSharesAPersistentHandle(): void
    {
        $config = ['driver' => 'pgsql', 'database' => 'audit', 'options' => [\PDO::ATTR_PERSISTENT => true, \PDO::ATTR_TIMEOUT => 7]];

        $forced = ['driver' => 'pgsql', 'database' => 'audit', 'options' => [\PDO::ATTR_PERSISTENT => false, \PDO::ATTR_TIMEOUT => 7]];

        self::assertSame($forced, DedicatedSession::sessionOptions($config));
        self::assertSame(['driver' => 'mysql', 'options' => [\PDO::ATTR_PERSISTENT => false]], DedicatedSession::sessionOptions(['driver' => 'mysql']));
        self::assertSame(['options' => [\PDO::ATTR_PERSISTENT => false]], DedicatedSession::sessionOptions(['options' => 'x']));
    }

    /**
     * The constructor is private: the class is a utility container only.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DedicatedSession::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(DedicatedSession::class, $instance);
    }
}
