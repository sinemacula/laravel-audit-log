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
 * Feature tests for the delivery checks of `audit-log:check`.
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
     * Put the outbox back if a test moved it and remove the test's files.
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
     * A sync install with the defaults has no delivery problem.
     *
     * @return void
     */
    public function testASyncInstallHasNoProblems(): void
    {
        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A spill channel `logging.channels` does not configure is a problem.
     *
     * @return void
     */
    public function testAnUnconfiguredChannelIsAProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', 'missing');

        self::assertSame(['The channel [missing] that `audit-log.failure.log_channel` names is not configured in `logging.channels`.'], $this->checks()->problems());
    }

    /**
     * Rows of `[the connection the channel names]`: by name and by default.
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
     * A `database` spill channel on the storage connection fails with it.
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
     * A `database` spill channel on another connection is no problem.
     *
     * @return void
     */
    public function testADatabaseChannelOnAnotherConnectionIsNoProblem(): void
    {
        $this->spillTo(['driver' => 'database', 'connection' => 'logs']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * With no channel set, the default channel is checked as the spill channel.
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
     * A nested stack member writing to the storage connection is a problem.
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
     * A stack's comma-separated string of members is followed too.
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
     * Every storage-connection channel a stack reaches is listed, in order.
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
     * A numeric stack member names the channel of its digits.
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
     * Stacks that name each other are followed once each.
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
     * A stack with nothing to follow is no problem.
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
     * A member that names no channel does not stop the walk.
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
     * Rows of `[a factory of the store, its class]`: stores not marked durable.
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
     * Throw mode with a store not marked durable is a problem naming its class.
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
     * Throw mode with the default store or a durable-first stack is no problem.
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
     * Report mode needs no durable store.
     *
     * @return void
     */
    public function testReportModeNeedsNoDurableStore(): void
    {
        $this->app?->instance(AuditStore::class, new PlainStore);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * Outbox mode needs no durable store: the outbox acknowledges the record.
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
     * The store is not resolved while the integrity settings are malformed.
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
     * An unresolvable store is named by its exception class, never its message.
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
     * Sync mode does not check the outbox tables.
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
     * In outbox mode a missing deliveries table is a problem naming it.
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
     * An outbox on its own connection is checked on that connection.
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
     * An unconfigured outbox connection is a problem naming it.
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
     * Rows of `[the outbox connection's configuration, the problem]`.
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
     * An outbox connection that cannot be checked is the outbox's one problem.
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
     * An unsupported MySQL outbox server is a problem and no table is read.
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
     * An unreadable outbox table is named by its exception class alone.
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
     * An anonymous failure class prints no file path or NUL byte.
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
     * A `database` spill channel on the outbox connection is a problem.
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
     * In sync mode the outbox connection setting is ignored.
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
     * A channel on a connection shared by outbox and store is named once.
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
     * A documented channel with no `permission` takes the umask and is noted.
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
     * A `permission` open to group or others is noted, naming it.
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
     * Monolog sets a permission only on create, so existing files are read too.
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
     * Rows of `[the dated file's suffix]`, with an extension and without.
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
     * A compressed archive or another log beside the dated files is not read.
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
     * In outbox mode an unconfigured storage connection is left to its subject.
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
     * A `daily` channel otherwise as documented has no note.
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
     * Rows of `[the channel's configuration]`: each way to differ from docs.
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
     * Each undocumented channel is noted by name as unverified for replay.
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
     * An unconfigured channel is noted by the name the setting gives it.
     *
     * @return void
     */
    public function testAnUnconfiguredChannelIsNoted(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', 'missing');

        self::assertSame(sprintf(self::NOTE, 'missing'), $this->checks()->spillNote());
    }

    /**
     * With no channel set, the default stack is noted as undocumented.
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
