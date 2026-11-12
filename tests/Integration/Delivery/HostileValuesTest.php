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
 * Integration tests for a record whose value matches Laravel's phrases for a
 * deadlock or lost connection, which must not make an ordinary failure look
 * fatal.
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

    /** @var string The spill channel, which writes nowhere; lines are captured as logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The application's reporter. */
    private RecordingExceptionHandler $reporter;

    /**
     * Create the host's table, bind the reporter and capture spill lines.
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
     * A failed statement with the phrase in its bindings inside a host is
     * spilled and reported, and the host commits.
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
     * With no host open the phrase changes nothing.
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
     * A unique violation whose driver message quotes the value still rolls back
     * its savepoint and stays a unique violation.
     *
     * @param  string  $phrase
     * @return void
     */
    #[DataProvider('providePhrases')]
    public function testAValueTheDriverQuotesLeavesTheHostUsable(string $phrase): void
    {
        $imported = ['provenance' => 'imported', 'source_id' => 'legacy-app', 'source_record_id' => $phrase, 'source_digest' => hash('sha256', $phrase)];
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
     * A failed outbox insert inside a host follows the rule and rolls back its
     * savepoint.
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
