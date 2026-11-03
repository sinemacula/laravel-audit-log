<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for a record whose value reads as one of Laravel's phrases
 * for a deadlock or a lost connection, on the engine the suite runs against: a
 * real failing statement holds the value in its bindings, and a real constraint
 * failure in what the driver quotes, and neither may make an ordinary failure
 * look fatal. The record is still spilled and reported, nothing is thrown under
 * the report rule, and the host's transaction is left usable, its savepoint
 * rolled back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureClassifier::class)]
#[CoversClass(DatabaseAuditStore::class)]
#[CoversClass(Outbox::class)]
final class HostileValuesTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_hostile_host_writes';

    /** @var string A table that does not exist, so the insert really fails. */
    private const string MISSING_TABLE = 'audit_no_such_table';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /**
     * Create the table the host writes to, bind the reporter and capture the
     * spill lines.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();
    }

    /**
     * Roll back any transaction a test left open, and drop the host's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while ($this->host()->transactionLevel() > 0) {
            $this->host()->rollBack();
        }

        Schema::dropIfExists(self::HOST_TABLE);

        parent::tearDown();
    }

    /**
     * Rows of `[phrase]`: what Laravel reads a failure's message for.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePhrases(): iterable
    {
        yield from [
            'a deadlock'        => ['deadlock detected'],
            'MySQL\'s deadlock' => ['Deadlock found when trying to get lock'],
            'a locked database' => ['database is locked'],
            'a lock wait'       => ['Lock wait timeout exceeded; try restarting transaction'],
            'the server gone'   => ['server has gone away'],
            'a lost connection' => ['Lost connection'],
            'a reset socket'    => ['Connection reset by peer'],
            'a broken pipe'     => ['Broken pipe'],
        ];
    }

    /**
     * A statement that really fails, with the phrase among its bindings, inside
     * a host: the record is spilled and reported, nothing is thrown under the
     * report rule, and the host goes on and commits.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('providePhrases')]
    public function testAValueInAFailedStatementsBindingsIsNotFatal(string $phrase): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', self::MISSING_TABLE);

        $this->host()->transaction(function () use ($phrase): void {
            $this->host()->table(self::HOST_TABLE)->insert(['name' => 'before']);

            AuditLog::event(self::CODE)->withProperties(['note' => $phrase])->immediately()->record();

            self::assertSame(1, $this->host()->transactionLevel());

            $this->host()->table(self::HOST_TABLE)->insert(['name' => 'after']);
        });

        self::assertSame(2, $this->host()->table(self::HOST_TABLE)->count());
        self::assertCount(1, $this->spillLines());
        self::assertStringContainsString($phrase, $this->spillLines()[0]);
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
    }

    /**
     * A stack's database destination is read the same way.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('providePhrases')]
    public function testAValueThroughAStackIsNotFatal(string $phrase): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', self::MISSING_TABLE);
        app()->instance(AuditStore::class, new StackAuditStore(['database' => app(DatabaseAuditStore::class)]));

        $this->host()->transaction(function () use ($phrase): void {
            AuditLog::event(self::CODE)->withProperties(['note' => $phrase])->immediately()->record();

            $this->host()->table(self::HOST_TABLE)->insert(['name' => 'after']);
        });

        self::assertSame(1, $this->host()->table(self::HOST_TABLE)->count());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * With no host open the same failure was never fatal: this pins that the
     * phrase changes nothing there either.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('providePhrases')]
    public function testAValueWithNoHostFollowsTheRule(string $phrase): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', self::MISSING_TABLE);

        AuditLog::event(self::CODE)->withProperties(['note' => $phrase])->immediately()->record();

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * A real unique violation whose driver message can quote the value, as
     * PostgreSQL's `DETAIL` and MySQL's duplicate entry do: Laravel must still
     * roll back the savepoint, so the host stays usable and the class stays a
     * unique violation.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('providePhrases')]
    public function testAValueTheDriverQuotesLeavesTheHostUsable(string $phrase): void
    {
        $imported = ['provenance' => 'imported', 'source_id' => 'legacy-app', 'source_record_id' => $phrase];
        $first    = $this->finaliser()->finalise(RecordFactory::withFields($imported));
        $second   = $this->finaliser()->finalise(RecordFactory::withFields($imported));
        $store    = app(DatabaseAuditStore::class);

        $store->store($first);

        $this->host()->transaction(function () use ($store, $second): void {
            try {
                $store->store($second);

                self::fail('Expected the source identity to be refused.');
            } catch (UniqueConstraintViolationException $exception) {
                self::assertFalse((new FailureClassifier)->isConcurrencyError($exception));
                self::assertFalse((new FailureClassifier)->isLostConnection($exception));
                self::assertSame(1, $this->host()->transactionLevel());
            }

            $this->host()->table(self::HOST_TABLE)->insert(['name' => 'after']);
        });

        self::assertSame(1, $this->host()->table(self::HOST_TABLE)->count());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * An outbox insert that really fails inside a host follows the rule too,
     * its savepoint rolled back.
     *
     * @return void
     */
    public function testAFailedOutboxInsertInsideAHostLeavesItUsable(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', self::MISSING_TABLE);

        $this->host()->transaction(function (): void {
            AuditLog::event(self::CODE)->withProperties(['note' => 'deadlock detected'])->immediately()->record();

            $this->host()->table(self::HOST_TABLE)->insert(['name' => 'after']);
        });

        self::assertSame(1, $this->host()->table(self::HOST_TABLE)->count());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * Spill to a channel that writes nowhere.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
    }

    /**
     * The host's connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }
}
