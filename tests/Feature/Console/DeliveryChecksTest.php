<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\NullLogger;
use SineMacula\Laravel\AuditLog\Console\DeliveryChecks;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Fixtures\Database\VersionReportingPdo;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for the delivery checks of `audit-log:check`: the spill channel
 * is configured and does not write to the storage connection, however deeply a
 * stack nests it, a thrown failure needs a store that says it is durable in
 * sync mode, the outbox and deliveries tables are checked in outbox mode only,
 * and the note on the spill channel says whether it is the documented one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryChecks::class)]
final class DeliveryChecksTest extends TestCase
{
    use InteractsWithOutbox;

    /** @var string The channel a test configures and names as the spill channel. */
    private const string CHANNEL = 'audit_spill';

    /** @var string The problem of a `database` channel on the storage connection, by the channel's name. */
    private const string ON_STORAGE = 'The spill channel [%s] writes to the storage connection [testing], so it would fail together with the store.';

    /** @var string The note on a channel that is not the documented one, by its name. */
    private const string NOTE = 'The channel [%s] is not the documented file format, so replaying what it holds is unverified,'
        . ' and whole records in plaintext go to it and to everything it feeds.';

    /** @var string The problem of a store that does not say it is durable while failures are thrown, by its class. */
    private const string NOT_DURABLE = '`audit-log.failure.mode` is `throw`, and the store %s does not say it is durable, so a return could not mean a record is kept.';

    /** @var string What a test's secret carries, and no problem may hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /** @var list<string> Files a test created, removed when it ends. */
    private array $files = [];

    /**
     * Put the outbox back if a test moved it, and remove the files a test
     * created.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeMovedOutbox();

        foreach ($this->files as $file) {

            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * A sync install with the default channel and the default store has no
     * delivery problem.
     *
     * @return void
     */
    public function testASyncInstallHasNoProblems(): void
    {
        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A spill channel the setting names that `logging.channels` does not
     * configure is a problem naming the channel, and nothing else of it is
     * checked.
     *
     * @return void
     */
    public function testAnUnconfiguredChannelIsAProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', 'missing');

        self::assertSame(['The channel [missing] that `audit-log.failure.log_channel` names is not configured in `logging.channels`.'], $this->checks()->problems());
    }

    /**
     * Rows of `[the connection the channel names]`: the storage connection by
     * its name, and by leaving the connection to the default one.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideStorageConnections(): iterable
    {
        yield from [
            'named'          => ['testing'],
            'by the default' => [null],
        ];
    }

    /**
     * A spill channel with the `database` driver on the storage connection is a
     * problem, since a spill there fails together with the store; a channel
     * that names no connection writes to the default one.
     *
     * @param  ?string  $connection
     * @return void
     */
    #[DataProvider('provideStorageConnections')]
    public function testADatabaseChannelOnTheStorageConnectionIsAProblem(?string $connection): void
    {
        $this->spillTo(['driver' => 'database', 'connection' => $connection]);

        self::assertSame([sprintf(self::ON_STORAGE, self::CHANNEL)], $this->checks()->problems());
    }

    /**
     * A spill channel with the `database` driver on another connection than the
     * storage connection is no problem.
     *
     * @return void
     */
    public function testADatabaseChannelOnAnotherConnectionIsNoProblem(): void
    {
        $this->spillTo(['driver' => 'database', 'connection' => 'logs']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * When the setting names no channel, the default channel is the spill
     * channel, and is checked the same way.
     *
     * @return void
     */
    public function testTheDefaultChannelIsTheSpillChannel(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::CHANNEL, ['driver' => 'database']);
        $config->set('logging.default', self::CHANNEL);
        $config->set('audit-log.failure.log_channel', '');

        self::assertSame([sprintf(self::ON_STORAGE, self::CHANNEL)], $this->checks()->problems());
        self::assertSame(sprintf(self::NOTE, self::CHANNEL), $this->checks()->spillNote());
    }

    /**
     * A member of a stack, however deeply nested, with the `database` driver on
     * the storage connection is a problem naming the member.
     *
     * @return void
     */
    public function testADatabaseMemberOfAStackIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.audit_inner', ['driver' => 'stack', 'channels' => ['single', 'audit_db']]);
        $config->set('logging.channels.audit_db', ['driver' => 'database', 'connection' => self::CONNECTION]);

        $this->spillTo(['driver' => 'stack', 'channels' => ['single', 'audit_inner']]);

        self::assertSame([sprintf(self::ON_STORAGE, 'audit_db')], $this->checks()->problems());
    }

    /**
     * A stack's members given as one string separated by commas, as the log
     * manager reads them, are followed too.
     *
     * @return void
     */
    public function testAStackOfMembersInAStringIsFollowed(): void
    {
        app(ConfigRepository::class)->set('logging.channels.audit_db', ['driver' => 'database']);

        $this->spillTo(['driver' => 'stack', 'channels' => 'single, audit_db']);

        self::assertSame([sprintf(self::ON_STORAGE, 'audit_db')], $this->checks()->problems());
    }

    /**
     * Every channel a stack reaches with the `database` driver on the storage
     * connection is listed, in the order the stack names them, past one that
     * writes elsewhere.
     *
     * @return void
     */
    public function testEveryDatabaseChannelOnTheStorageConnectionIsListed(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.audit_elsewhere', ['driver' => 'database', 'connection' => 'logs']);
        $config->set('logging.channels.audit_named', ['driver' => 'database', 'connection' => self::CONNECTION]);
        $config->set('logging.channels.audit_default', ['driver' => 'database']);

        $this->spillTo(['driver' => 'stack', 'channels' => ['audit_elsewhere', 'audit_named', 'audit_default']]);

        self::assertSame([sprintf(self::ON_STORAGE, 'audit_named'), sprintf(self::ON_STORAGE, 'audit_default')], $this->checks()->problems());
    }

    /**
     * A stack member given as a number names the channel of its digits, as the
     * log manager reads it.
     *
     * @return void
     */
    public function testANumberedMemberNamesItsChannel(): void
    {
        app(ConfigRepository::class)->set('logging.channels.42', ['driver' => 'database']);

        $this->spillTo(['driver' => 'stack', 'channels' => [42]]);

        self::assertSame([sprintf(self::ON_STORAGE, '42')], $this->checks()->problems());
    }

    /**
     * Stacks that name each other are followed once each, so the walk ends, and
     * a channel two stacks share is reported once.
     *
     * @return void
     */
    public function testACycleOfStacksEnds(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.audit_other', ['driver' => 'stack', 'channels' => [self::CHANNEL, 'audit_db']]);
        $config->set('logging.channels.audit_db', ['driver' => 'database']);

        $this->spillTo(['driver' => 'stack', 'channels' => ['audit_other', self::CHANNEL, 'audit_db', 'missing']]);

        self::assertSame([sprintf(self::ON_STORAGE, 'audit_db')], $this->checks()->problems());
    }

    /**
     * A stack whose members are not a list or a string, a member that names no
     * channel, such as a logger given as itself, and a member that is not
     * configured give nothing to follow and no problem.
     *
     * @return void
     */
    public function testAStackOfNothingToFollowIsNoProblem(): void
    {
        $this->spillTo(['driver' => 'stack', 'channels' => 42]);

        self::assertSame([], $this->checks()->problems());

        $this->spillTo(['driver' => 'stack', 'channels' => [42, 'missing', ['single'], new NullLogger, null]]);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A member that names no channel stops the walk at nothing: the members
     * after it are still followed.
     *
     * @return void
     */
    public function testAMemberThatNamesNoChannelStopsNoOther(): void
    {
        app(ConfigRepository::class)->set('logging.channels.audit_db', ['driver' => 'database']);

        $this->spillTo(['driver' => 'stack', 'channels' => [new NullLogger, 'audit_db']]);

        self::assertSame([sprintf(self::ON_STORAGE, 'audit_db')], $this->checks()->problems());
    }

    /**
     * Rows of `[a factory of the store, its class]`: stores that do not say a
     * return is durable.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Contracts\AuditStore, 1: class-string}>
     */
    public static function provideStoresThatAreNotDurable(): iterable
    {
        $log = static fn (): LogAuditStore => new LogAuditStore(app(LogManager::class), new NdjsonFormatter);

        yield from [
            'the null store'                    => [static fn (): AuditStore => new NullAuditStore, NullAuditStore::class],
            'a log store'                       => [$log, LogAuditStore::class],
            'a plain store'                     => [static fn (): AuditStore => new PlainStore, PlainStore::class],
            'a stack starting with a log store' => [
                static fn (): AuditStore => new StackAuditStore(['log' => $log(), 'database' => app(DatabaseAuditStore::class)]),
                StackAuditStore::class,
            ],
        ];
    }

    /**
     * Failures thrown in sync mode with a store that does not say it is durable
     * is a problem naming the store's class, since a return could not mean a
     * record is kept.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideStoresThatAreNotDurable')]
    public function testThrowModeWithNoDurableStoreIsAProblem(\Closure $store, string $class): void
    {
        $this->app?->instance(AuditStore::class, $store());

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        self::assertSame([sprintf(self::NOT_DURABLE, $class)], $this->checks()->problems());
    }

    /**
     * Failures thrown with the default store, or a stack whose first
     * destination is durable, are no problem.
     *
     * @return void
     */
    public function testThrowModeWithADurableStoreIsNoProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        self::assertSame([], $this->checks()->problems());

        $this->app?->instance(AuditStore::class, new StackAuditStore(['database' => app(DatabaseAuditStore::class), 'log' => new NullAuditStore]));

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A store that does not say it is durable is no problem while failures are
     * only reported.
     *
     * @return void
     */
    public function testReportModeNeedsNoDurableStore(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * In outbox mode the outbox acknowledges a record, so failures thrown with
     * a store that is not durable are no problem.
     *
     * @return void
     */
    public function testThrowModeInOutboxModeIsNoProblem(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        app(ConfigRepository::class)->set(['audit-log.failure.mode' => 'throw', 'audit-log.delivery.mode' => 'outbox']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * While the integrity settings are malformed the store is not resolved,
     * since that builds the key ring, so a store that is not durable is not
     * reported then.
     *
     * @return void
     */
    public function testThrowModeIsNotCheckedWhileTheIntegritySettingsAreMalformed(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        app(ConfigRepository::class)->set(['audit-log.failure.mode' => 'throw', 'audit-log.integrity.keys' => 'x']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A store that cannot be resolved while failures are thrown is a problem
     * named by the class of what was thrown, never by its message, which names
     * what could not be built.
     *
     * @return void
     */
    public function testAStoreThatCannotBeResolvedIsNamedByItsClass(): void
    {
        $this->app?->bind(AuditStore::class, 'Tests\Missing\\' . str_replace('-', '', ucfirst(self::SENTINEL)));

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $problems = $this->checks()->problems();

        self::assertSame(['The bound store could not be resolved (' . BindingResolutionException::class . ').'], $problems);
        self::assertStringNotContainsString('Sentinel7f3a9c', implode("\n", $problems));
    }

    /**
     * In sync mode the outbox and deliveries tables are not checked, so their
     * absence is no problem.
     *
     * @return void
     */
    public function testTheOutboxTablesAreNotCheckedInSyncMode(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.delivery.outbox.table'      => 'audit_absent_outbox',
            'audit-log.delivery.deliveries_table'  => 'audit_absent_deliveries',
            'audit-log.delivery.outbox.connection' => 'missing',
        ]);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * In outbox mode the tables the shipped migrations created have no problem.
     *
     * @return void
     */
    public function testTheShippedOutboxTablesHaveNoProblemsInOutboxMode(): void
    {
        $this->outboxMode();

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * In outbox mode a missing outbox table is a problem naming the outbox.
     *
     * @return void
     */
    public function testAMissingOutboxTableIsAProblemInOutboxMode(): void
    {
        $this->outboxMode(['audit-log.delivery.outbox.table' => 'audit_absent_outbox']);

        self::assertSame([
            'The outbox table `audit_absent_outbox` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->checks()->problems());
    }

    /**
     * In outbox mode a missing deliveries table is a problem naming the
     * deliveries table, on the storage connection.
     *
     * @return void
     */
    public function testAMissingDeliveriesTableIsAProblemInOutboxMode(): void
    {
        $this->outboxMode(['audit-log.delivery.deliveries_table' => 'audit_absent_deliveries']);

        self::assertSame([
            'The deliveries table `audit_absent_deliveries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->checks()->problems());
    }

    /**
     * In outbox mode an outbox column the table lacks is a problem.
     *
     * @return void
     */
    public function testAWrongOutboxColumnIsAProblem(): void
    {
        Schema::connection(self::CONNECTION)->table('audit_log_outbox', static function (Blueprint $table): void {
            $table->dropColumn('claimed_by');
        });

        $this->outboxMode();

        self::assertSame(['Column `claimed_by` is missing.'], $this->checks()->problems());
    }

    /**
     * An outbox on a connection of its own, created there by the shipped
     * migration, has no problem, and the deliveries table is still read on the
     * storage connection.
     *
     * @return void
     */
    public function testAnOutboxOnItsOwnConnectionIsCheckedThere(): void
    {
        $this->moveOutboxToItsOwnConnection();
        $this->outboxMode();

        self::assertSame([], $this->checks()->problems());

        app(ConfigRepository::class)->set('audit-log.delivery.deliveries_table', 'audit_absent_deliveries');

        self::assertSame([
            'The deliveries table `audit_absent_deliveries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->checks()->problems());
    }

    /**
     * An outbox connection `database.connections` does not configure is a
     * problem naming it, and the deliveries table is still checked.
     *
     * @return void
     */
    public function testAnUnconfiguredOutboxConnectionIsAProblem(): void
    {
        $this->outboxMode(['audit-log.delivery.outbox.connection' => 'missing', 'audit-log.delivery.deliveries_table' => 'audit_absent_deliveries']);

        self::assertSame([
            'The connection [missing] that `audit-log.delivery.outbox.connection` names is not configured in `database.connections`.',
            'The deliveries table `audit_absent_deliveries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->checks()->problems());
    }

    /**
     * Rows of `[the outbox connection's configuration, the problem]`: an outbox
     * connection that cannot be checked, described as the storage connection's
     * would be, under the outbox's name.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string}>
     */
    public static function provideUncheckableOutboxConnections(): iterable
    {
        $path = sys_get_temp_dir() . '/audit-log-missing-outbox-' . getmypid() . '.sqlite';

        yield from [
            'a driver the package does not support' => [
                ['driver' => 'sqlsrv', 'database' => 'audit'],
                'The outbox connection [audit_outbox] uses the sqlsrv driver, which is not supported; use SQLite, MySQL 8.4 or later, or PostgreSQL.',
            ],
            'a database that does not exist' => [
                ['driver' => 'sqlite', 'database' => $path, 'prefix' => ''],
                'The outbox connection [audit_outbox] could not be opened (' . SQLiteDatabaseDoesNotExistException::class . ').',
            ],
        ];
    }

    /**
     * An outbox connection of its own that cannot be checked is the one problem
     * of the outbox, and no table is read on it.
     *
     * @param  array<string, string>  $connection
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideUncheckableOutboxConnections')]
    public function testAnOutboxConnectionThatCannotBeCheckedIsAProblem(array $connection, string $problem): void
    {
        app(ConfigRepository::class)->set('database.connections.audit_outbox', $connection);

        $this->outboxMode(['audit-log.delivery.outbox.connection' => 'audit_outbox']);

        self::assertSame([$problem], $this->checks()->problems());
    }

    /**
     * An outbox connection to a MySQL server the package does not support is a
     * problem in the engine checks' own words, which name no connection, and no
     * table is read on it.
     *
     * @return void
     */
    public function testAnOutboxConnectionToAnUnsupportedServerIsAProblem(): void
    {
        $connection = new MySqlConnection(new VersionReportingPdo('8.0.36'), '', '', ['driver' => 'mysql', 'name' => 'audit_outbox']);

        app(ConfigRepository::class)->set('database.connections.audit_outbox', ['driver' => 'mysql', 'database' => 'audit', 'prefix' => '']);

        $this->app?->make(DatabaseManager::class)->extend('audit_outbox', static fn (): MySqlConnection => $connection);

        $this->outboxMode(['audit-log.delivery.outbox.connection' => 'audit_outbox']);

        $problem = 'The outbox connection [audit_outbox] runs MySQL 8.0.36, which is not supported; use MySQL 8.4 or later (MariaDB is not supported).';

        self::assertSame([$problem], $this->checks()->problems());
    }

    /**
     * An outbox connection whose tables cannot be read is a problem named by
     * the class of what was thrown, never by the statement or the path it
     * binds.
     *
     * @return void
     */
    public function testAConnectionThatCannotBeReadIsNamedByItsClass(): void
    {
        $path = sys_get_temp_dir() . '/audit-log-garbage-outbox-' . getmypid() . '.sqlite';

        file_put_contents($path, str_repeat('not a database ', 512));

        $this->files[] = $path;

        app(ConfigRepository::class)->set('database.connections.garbage', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);

        $this->outboxMode(['audit-log.delivery.outbox.connection' => 'garbage']);

        $problems = $this->checks()->problems();

        self::assertSame(['The outbox connection [garbage] could not be read (Illuminate\Database\QueryException).'], $problems);
        self::assertStringNotContainsString($path, implode("\n", $problems));
    }

    /**
     * A failure reading a table is named as `get_debug_type()` names it, so an
     * anonymous class of a custom driver prints no file path or NUL byte.
     *
     * @return void
     */
    public function testAStatementFailureOfAnAnonymousClassPrintsNoPath(): void
    {
        $this->outboxMode();

        $failure = new class ('Failed.') extends \PDOException {};
        $gate    = new \ArrayObject(['armed' => true]);

        DB::connection(self::CONNECTION)->beforeExecuting(static function () use ($failure, $gate): void {
            if ($gate['armed'] === true) {
                throw $failure;
            }
        });

        $problems = implode("\n", $this->checks()->problems());

        $gate['armed'] = false;

        self::assertStringContainsString('could not be read (PDOException@anonymous)', $problems);
        self::assertStringNotContainsString('.php', $problems);
        self::assertStringNotContainsString("\0", $problems);
    }

    /**
     * In outbox mode a `database` spill channel on a dedicated outbox
     * connection fails together with the insert it stands in for, so it is a
     * problem naming that connection.
     *
     * @return void
     */
    public function testADatabaseChannelOnTheOutboxConnectionIsAProblem(): void
    {
        $this->moveOutboxToItsOwnConnection();
        $this->outboxMode(['audit-log.delivery.outbox.connection' => self::MOVED_OUTBOX_CONNECTION]);
        $this->spillTo(['driver' => 'database', 'connection' => self::MOVED_OUTBOX_CONNECTION]);

        self::assertContains(
            sprintf('The spill channel [%s] writes to the outbox connection [%s], so it would fail together with the outbox.', self::CHANNEL, self::MOVED_OUTBOX_CONNECTION),
            $this->checks()->problems(),
        );
    }

    /**
     * In sync mode there is no outbox write for a channel to fail with,
     * whatever the setting still names.
     *
     * @return void
     */
    public function testInSyncModeTheOutboxConnectionIsNoProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.connection', 'elsewhere');
        app(ConfigRepository::class)->set('database.connections.elsewhere', ['driver' => 'sqlite', 'database' => ':memory:']);

        $this->spillTo(['driver' => 'database', 'connection' => 'elsewhere']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A database channel on the connection the outbox shares with the store is
     * named once, as the storage connection's.
     *
     * @return void
     */
    public function testAnOutboxSharingTheStorageConnectionIsNamedOnce(): void
    {
        $this->outboxMode();
        $this->spillTo(['driver' => 'database', 'connection' => self::CONNECTION]);

        self::assertSame([sprintf(self::ON_STORAGE, self::CHANNEL)], $this->checks()->problems());
    }

    /**
     * A channel in the documented format with no `permission` takes the umask,
     * and says so, since the permission is what guards a file of plaintext
     * records.
     *
     * @return void
     */
    public function testADocumentedChannelWithNoPermissionIsNoted(): void
    {
        $channel = DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill.log');

        unset($channel['permission']);

        $this->spillTo($channel);

        $note = 'The channel [%s] sets no `permission`, so its file of plaintext records takes the umask; set `permission` to 0600.';

        self::assertSame(sprintf($note, self::CHANNEL), $this->checks()->spillNote());
    }

    /**
     * Rows of `[permission, whether a note is due]`.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function providePermissions(): iterable
    {
        yield from [
            'the owner alone'    => [0600, false],
            'the owner, read'    => [0400, false],
            'group can read'     => [0640, true],
            'others can read'    => [0604, true],
            'everyone'           => [0644, true],
            'others can execute' => [0601, true],
        ];
    }

    /**
     * A channel's `permission` must keep out group and others, and the note
     * names the permission it found.
     *
     * @param  int  $permission
     * @param  bool  $noted
     * @return void
     */
    #[DataProvider('providePermissions')]
    public function testAPermissionThatLetsOthersInIsNoted(int $permission, bool $noted): void
    {
        $this->spillTo([...DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill-absent.log'), 'permission' => $permission]);

        $note = $noted
            ? sprintf('The channel [%s] has the `permission` %04o, so group or others can read its plaintext records; set it to 0600.', self::CHANNEL, $permission)
            : null;

        self::assertSame($note, $this->checks()->spillNote());
    }

    /**
     * Monolog applies a permission only when it creates a file, so a file that
     * exists is read too, whatever the setting says.
     *
     * @return void
     */
    public function testAnExistingFileWithALooserPermissionIsNoted(): void
    {
        $file = sys_get_temp_dir() . '/audit-log-spill-' . getmypid() . '.log';

        touch($file);
        chmod($file, 0644);

        $this->files[] = $file;

        $this->spillTo(DocumentedSpillChannel::config($file));

        $note = 'A file of the channel [%s] has the permission 0644, so group or others can read its plaintext records; change it to 0600.';

        self::assertSame(sprintf($note, self::CHANNEL), $this->checks()->spillNote());

        chmod($file, 0600);

        self::assertNull($this->checks()->spillNote());
    }

    /**
     * Rows of `[the dated file's suffix]`: a `daily` channel's path with an
     * extension and without one.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideDailyPaths(): iterable
    {
        yield from [
            'with an extension' => ['.log', '-2026-11-01.log'],
            'with none'         => ['', '-2026-11-01'],
        ];
    }

    /**
     * A `daily` channel's dated files are what exist, so those are read.
     *
     * @param  string  $extension
     * @param  string  $dated
     * @return void
     */
    #[DataProvider('provideDailyPaths')]
    public function testADailyChannelsDatedFilesAreRead(string $extension, string $dated): void
    {
        $base = sys_get_temp_dir() . '/audit-log-daily-' . getmypid();
        $file = $base . $dated;

        touch($file);
        chmod($file, 0644);

        $this->files[] = $file;

        $this->spillTo([...DocumentedSpillChannel::config($base . $extension), 'driver' => 'daily']);

        self::assertStringContainsString('has the permission 0644', (string) $this->checks()->spillNote());
    }

    /**
     * Every dated file is read, so a looser one after a tight one is noted.
     *
     * @return void
     */
    public function testEveryDatedFileIsRead(): void
    {
        $base = sys_get_temp_dir() . '/audit-log-dated-' . getmypid();

        foreach (['-2026-11-01.log' => 0600, '-2026-11-02.log' => 0644] as $dated => $permission) {
            touch($base . $dated);
            chmod($base . $dated, $permission);

            $this->files[] = $base . $dated;
        }

        $this->spillTo([...DocumentedSpillChannel::config($base . '.log'), 'driver' => 'daily']);

        self::assertStringContainsString('has the permission 0644', (string) $this->checks()->spillNote());
    }

    /**
     * Only files with the channel's own extension are its dated files, so a
     * compressed archive or another log beside them is not read.
     *
     * @return void
     */
    public function testOnlyTheChannelsOwnDatedFilesAreRead(): void
    {
        $base = sys_get_temp_dir() . '/audit-log-own-' . getmypid();

        foreach (['-2026-11-01.log.gz', '-2026-11-01.syslog'] as $other) {
            touch($base . $other);
            chmod($base . $other, 0644);

            $this->files[] = $base . $other;
        }

        $this->spillTo([...DocumentedSpillChannel::config($base . '.log'), 'driver' => 'daily']);

        self::assertNull($this->checks()->spillNote());
    }

    /**
     * In outbox mode a storage connection that is not configured is left to the
     * connections subject, which names it.
     *
     * @return void
     */
    public function testAnUnconfiguredStorageConnectionIsLeftToItsSubject(): void
    {
        $this->outboxMode(['audit-log.storage.connection' => 'missing']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * The channel the documentation gives has no note.
     *
     * @return void
     */
    public function testTheDocumentedChannelHasNoNote(): void
    {
        $this->spillTo(DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill.log'));

        self::assertNull($this->checks()->spillNote());
    }

    /**
     * A `daily` channel otherwise as documented has no note, and neither has
     * one that leaves inline line breaks unset, which is off.
     *
     * @return void
     */
    public function testADailyChannelCanBeDocumented(): void
    {
        $this->spillTo([...DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill.log'), 'driver' => 'daily', 'days' => 14]);

        self::assertNull($this->checks()->spillNote());

        $this->spillTo([...DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill.log'), 'formatter_with' => ['format' => "%message%\n"]]);

        self::assertNull($this->checks()->spillNote());
    }

    /**
     * Rows of `[the channel's configuration]`: every way a channel can differ
     * from the documented one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideOtherChannels(): iterable
    {
        $documented = DocumentedSpillChannel::config('/var/log/audit-spill.log');

        yield from [
            'a stack'                         => [['driver' => 'stack', 'channels' => ['single']]],
            'syslog'                          => [['driver' => 'syslog', 'formatter' => LineFormatter::class, 'formatter_with' => $documented['formatter_with']]],
            'single with its default format'  => [['driver' => 'single', 'path' => '/var/log/audit-spill.log']],
            'the message with inline breaks'  => [[...$documented, 'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => true]]],
            'another format'                  => [[...$documented, 'formatter_with' => ['format' => "[%datetime%] %message%\n"]]],
            'the message without a line feed' => [[...$documented, 'formatter_with' => ['format' => '%message%']]],
            'another formatter'               => [[...$documented, 'formatter' => JsonFormatter::class]],
            'formatter settings not a map'    => [[...$documented, 'formatter_with' => "%message%\n"]],
            'inline breaks said as a word'    => [[...$documented, 'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => 'false']]],
        ];
    }

    /**
     * Each channel other than the documented one is noted, by its name, as
     * unverified for replay.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $channel
     * @return void
     */
    #[DataProvider('provideOtherChannels')]
    public function testEachOtherChannelIsNoted(array $channel): void
    {
        $this->spillTo($channel);

        self::assertSame(sprintf(self::NOTE, self::CHANNEL), $this->checks()->spillNote());
    }

    /**
     * A channel that is not configured is noted too, by the name the setting
     * gives it.
     *
     * @return void
     */
    public function testAnUnconfiguredChannelIsNoted(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', 'missing');

        self::assertSame(sprintf(self::NOTE, 'missing'), $this->checks()->spillNote());
    }

    /**
     * With no channel set the default channel is described, which in a default
     * install is a stack and so not the documented one.
     *
     * @return void
     */
    public function testTheDefaultChannelIsNoted(): void
    {
        app(ConfigRepository::class)->set('logging.default', 'stack');

        self::assertSame(sprintf(self::NOTE, 'stack'), $this->checks()->spillNote());
    }

    /**
     * The checks as the container builds them.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\DeliveryChecks
     */
    private function checks(): DeliveryChecks
    {
        $checks = $this->app?->make(DeliveryChecks::class);

        assert($checks instanceof DeliveryChecks);

        return $checks;
    }

    /**
     * Configure the test's channel and name it as the spill channel.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $channel
     * @return void
     */
    private function spillTo(array $channel): void
    {
        app(ConfigRepository::class)->set([
            'logging.channels.' . self::CHANNEL => $channel,
            'audit-log.failure.log_channel'     => self::CHANNEL,
        ]);
    }

    /**
     * Turn the outbox on, with the further settings given.
     *
     * @param  array<string, ?string>  $settings
     * @return void
     */
    private function outboxMode(array $settings = []): void
    {
        app(ConfigRepository::class)->set(['audit-log.delivery.mode' => 'outbox', ...$settings]);
    }
}
