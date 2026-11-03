<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxClaim;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Integration tests for the outbox on the engine the suite runs against: one
 * row per insert, alone outside a transaction and in a savepoint inside one;
 * the candidates a drain may claim; a claim that holds only while the row is
 * unfailed, due and unleased; every later change fenced by the claim's token;
 * renewals, retries, failures and requeues; on SQLite, MySQL and PostgreSQL
 * alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Outbox::class)]
#[CoversClass(OutboxClaim::class)]
final class OutboxTest extends TestCase
{
    use InteractsWithOutbox, InteractsWithReadWriteSplit, MockeryPHPUnitIntegration;

    /** @var string The instant the clock is stopped at. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The id rows are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A second id, after the first. */
    private const string SECOND_ID = '01932b4e-8a40-7000-8000-000000000002';

    /** @var string A third id, after the second. */
    private const string THIRD_ID = '01932b4e-8a40-7000-8000-000000000003';

    /** @var string The payload rows hold. */
    private const string PAYLOAD = 'eyJpdiI6ImVuY3J5cHRlZCJ9';

    /** @var string A token no claim wrote. */
    private const string STALE_TOKEN = '00000000-0000-4000-8000-000000000000';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_host_writes';

    /** @var string What a claim's token is: a lower-case UUID. */
    private const string TOKEN_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * Stop the clock and create the table the host transaction writes to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });
    }

    /**
     * Roll back any transaction a failed test left open, then drop what the
     * test added and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->outboxConnection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        $this->removeOutboxProbeTable();
        $this->removeMovedOutbox();
        $this->removeReadWriteSplit();

        Schema::dropIfExists(self::HOST_TABLE);

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An insert is one row under the id, holding the payload, with no attempt,
     * due and created now, unclaimed and not failed.
     *
     * @return void
     */
    public function testInsertsOneRow(): void
    {
        $this->outbox()->insert(self::ID, self::PAYLOAD);

        self::assertSame(1, $this->outboxCount());
        self::assertSame([
            'id'               => self::ID,
            'payload'          => self::PAYLOAD,
            'attempts'         => 0,
            'available_at'     => self::NOW,
            'claimed_until'    => null,
            'claimed_by'       => null,
            'failed_at'        => null,
            'last_error_class' => null,
            'created_at'       => self::NOW,
        ], $this->outboxRow(self::ID));
    }

    /**
     * Outside a transaction the insert opens none: no transaction begins, and
     * the connection is at level 0 throughout.
     *
     * @return void
     */
    public function testAnInsertOutsideATransactionUsesNoSavepoint(): void
    {
        $began  = 0;
        $levels = [];

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $this->outboxConnection()->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$levels): void {
            $levels[] = $connection->transactionLevel();
        });

        $this->outbox()->insert(self::ID, self::PAYLOAD);

        self::assertSame(0, $began);
        self::assertSame([0], $levels);
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Inside a host transaction the insert runs one level deeper, in a
     * savepoint, and the host is back at its own level once it succeeds.
     *
     * @return void
     */
    public function testAnInsertInsideATransactionRunsInASavepoint(): void
    {
        $connection = $this->outboxConnection();
        $inserts    = [];

        $connection->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$inserts): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $inserts[] = $connection->transactionLevel();
        });

        $connection->beginTransaction();

        $this->outbox()->insert(self::ID, self::PAYLOAD);

        self::assertSame([2], $inserts);
        self::assertSame(1, $connection->transactionLevel());

        $connection->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Inside a healthy host transaction an insert that fails on the probe
     * table's `NOT NULL` column propagates, then the host writes again and
     * commits: both host rows exist, and no outbox row does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedInsertLeavesAHealthyHostUsable(): void
    {
        $connection = $this->outboxConnection();

        // Created first: MySQL commits an open transaction on any DDL
        $this->pointOutboxAtProbeTable();

        $connection->beginTransaction();
        $connection->table(self::HOST_TABLE)->insert(['name' => 'before']);

        try {
            $this->outbox()->insert(self::ID, self::PAYLOAD);
            self::fail('Expected the insert to fail.');
        } catch (QueryException $exception) {
            self::assertNotInstanceOf(UniqueConstraintViolationException::class, $exception);
        }

        self::assertSame(1, $connection->transactionLevel());

        $connection->table(self::HOST_TABLE)->insert(['name' => 'after']);
        $connection->commit();

        self::assertSame(['before', 'after'], $connection->table(self::HOST_TABLE)->orderBy('id')->pluck('name')->all());
        self::assertSame(0, $connection->table(self::OUTBOX_PROBE_TABLE)->count());
    }

    /**
     * Outside a transaction a failed insert propagates and leaves no row.
     *
     * @return void
     */
    public function testAFailedInsertOutsideATransactionPropagates(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->expectException(QueryException::class);

        $this->outbox()->insert(self::ID, self::PAYLOAD);
    }

    /**
     * A row inserted inside a transaction goes when the transaction rolls back.
     *
     * @return void
     */
    public function testAnInsertRollsBackWithItsTransaction(): void
    {
        $connection = $this->outboxConnection();

        $connection->beginTransaction();

        $this->outbox()->insert(self::ID, self::PAYLOAD);

        self::assertSame(1, $this->outboxCount());

        $connection->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * On a read/write split the row is inserted on the primary, the replica
     * never sees it, and the outbox still finds it, because it reads the
     * writer.
     *
     * @return void
     */
    public function testTheInsertReachesTheWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateDeliveryTablesOn([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION]);

        $outbox = $this->outbox();

        $outbox->insert(self::ID, self::PAYLOAD);

        self::assertSame(self::SPLIT_CONNECTION, $outbox->connectionName());
        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(DeliveryTables::outboxTable())->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(DeliveryTables::outboxTable())->count());
        self::assertSame([self::ID], $outbox->candidates(10, $this->now()));
        self::assertNotNull($outbox->claim(self::ID, $this->now()));
    }

    /**
     * Moved to a connection of its own, the outbox inserts and reads there, and
     * names that connection.
     *
     * @return void
     */
    public function testTheOutboxIsOnItsOwnConnectionWhenMoved(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $outbox = $this->outbox();

        $outbox->insert(self::ID, self::PAYLOAD);

        self::assertSame(self::MOVED_OUTBOX_CONNECTION, $outbox->connectionName());
        self::assertSame(self::MOVED_OUTBOX_CONNECTION, $outbox->connection()->getName());
        self::assertSame(1, DB::connection(self::MOVED_OUTBOX_CONNECTION)->table(self::MOVED_OUTBOX_TABLE)->count());
        self::assertSame(0, DB::connection(self::CONNECTION)->table(DeliveryTables::DEFAULT_OUTBOX)->count());
        self::assertSame([self::ID], $outbox->candidates(10, $this->now()));
    }

    /**
     * The connection's name is the one the connection gives itself, so a name
     * that selects its writer is named as the connection.
     *
     * @return void
     */
    public function testTheConnectionNameIsTheConnectionsOwn(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.connection', self::CONNECTION . '::write');

        self::assertSame(self::CONNECTION, $this->outbox()->connectionName());
    }

    /**
     * Whether a transaction is open is read from the outbox connection.
     *
     * @return void
     */
    public function testIsInTransactionFollowsTheOutboxConnection(): void
    {
        $outbox = $this->outbox();

        self::assertFalse($outbox->isInTransaction());

        $this->outboxConnection()->beginTransaction();

        self::assertTrue($outbox->isInTransaction());

        $this->outboxConnection()->rollBack();

        self::assertFalse($outbox->isInTransaction());
    }

    /**
     * A connection that is not a database connection is refused, naming it.
     *
     * @return void
     */
    public function testAConnectionWithoutTransactionsIsRefused(): void
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);
        $resolver->shouldReceive('connection')->andReturn(\Mockery::mock(ConnectionInterface::class));

        $outbox = new Outbox($resolver, app(Clock::class), app(DeliverySettings::class));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The outbox connection [testing] is not a database connection that supports transactions.');

        $outbox->connection();
    }

    /**
     * A row that is due, not failed and unclaimed is a candidate.
     *
     * @return void
     */
    public function testACandidateIsDueUnfailedAndUnclaimed(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        self::assertSame([self::ID], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * A failed row is no candidate, however long ago it was due.
     *
     * @return void
     */
    public function testAFailedRowIsNoCandidate(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['available_at' => '2026-11-01T11:00:00.000000Z', 'failed_at' => self::NOW]);

        self::assertSame([], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * A row due after the instant given is no candidate, even a microsecond
     * after it; one due exactly then is.
     *
     * @return void
     */
    public function testARowNotYetDueIsNoCandidate(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['available_at' => '2026-11-01T12:00:00.000001Z']);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD, ['available_at' => self::NOW]);

        self::assertSame([self::SECOND_ID], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * A row whose lease has not passed is no candidate, even when the lease
     * ends this very microsecond.
     *
     * @return void
     */
    public function testALiveLeaseIsNoCandidate(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['claimed_by' => self::STALE_TOKEN, 'claimed_until' => '2026-11-01T12:05:00.000000Z']);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD, ['claimed_by' => self::STALE_TOKEN, 'claimed_until' => self::NOW]);

        self::assertSame([], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * A row whose lease has passed is a candidate again.
     *
     * @return void
     */
    public function testAnExpiredLeaseIsACandidate(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['claimed_by' => self::STALE_TOKEN, 'claimed_until' => '2026-11-01T11:59:59.999999Z']);

        self::assertSame([self::ID], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * Candidates come oldest due first, and rows due together by id.
     *
     * @return void
     */
    public function testCandidatesAreOldestFirst(): void
    {
        $this->seedOutboxRow(self::THIRD_ID, self::PAYLOAD, ['available_at' => '2026-11-01T11:00:00.000000Z']);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD, ['available_at' => '2026-11-01T11:30:00.000000Z']);
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['available_at' => '2026-11-01T11:30:00.000000Z']);

        self::assertSame([self::THIRD_ID, self::ID, self::SECOND_ID], $this->outbox()->candidates(10, $this->now()));
    }

    /**
     * No more candidates are given than the limit, and they are the oldest.
     *
     * @return void
     */
    public function testTheLimitHolds(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD);
        $this->seedOutboxRow(self::THIRD_ID, self::PAYLOAD);

        self::assertSame([self::ID, self::SECOND_ID], $this->outbox()->candidates(2, $this->now()));
        self::assertSame([self::ID], $this->outbox()->candidates(1, $this->now()));
    }

    /**
     * Reading the candidates selects their ids alone, never a payload.
     *
     * @return void
     */
    public function testCandidatesReadNoPayload(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $queries = [];

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$queries): void {
            $queries[] = $query;
        });

        $this->outbox()->candidates(10, $this->now());

        self::assertCount(1, $queries);
        self::assertMatchesRegularExpression('/\Aselect [`"]id[`"] from /', $queries[0]);
        self::assertStringNotContainsString('payload', $queries[0]);
    }

    /**
     * A claim writes a token of its own to the row and a lease that ends
     * `lease_seconds` from now.
     *
     * @return void
     */
    public function testAClaimSetsATokenAndALease(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.lease_seconds', 120);

        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $claim = $this->outbox()->claim(self::ID, $this->now());
        $row   = $this->outboxRow(self::ID);

        self::assertNotNull($claim);
        self::assertSame(self::ID, $claim->id);
        self::assertMatchesRegularExpression(self::TOKEN_PATTERN, $claim->token);
        self::assertSame($claim->token, $row['claimed_by'] ?? null);
        self::assertSame('2026-11-01T12:02:00.000000Z', $row['claimed_until'] ?? null);
    }

    /**
     * A claim counts an attempt on the row, and gives the count, this attempt
     * included.
     *
     * @return void
     */
    public function testAClaimCountsAnAttempt(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['attempts' => 3]);

        $claim = $this->outbox()->claim(self::ID, $this->now());

        self::assertSame(4, $claim?->attempts);
        self::assertSame(4, $this->outboxRow(self::ID)['attempts'] ?? null);
    }

    /**
     * A claim gives the row's payload as it is stored.
     *
     * @return void
     */
    public function testAClaimGivesThePayload(): void
    {
        $payload = str_repeat('x', 70000);

        $this->seedOutboxRow(self::ID, $payload);

        self::assertSame($payload, $this->outbox()->claim(self::ID, $this->now())?->payload);
    }

    /**
     * Each claim writes a new token, so a row reclaimed once its lease passed
     * is owned by the second claim alone.
     *
     * @return void
     */
    public function testEachClaimHasItsOwnToken(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $first = $this->outbox()->claim(self::ID, $this->now());

        $this->moveClockTo('2026-11-01T12:05:00.000001Z');

        $second = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertNotSame($first->token, $second->token);
        self::assertSame($second->token, $this->outboxRow(self::ID)['claimed_by'] ?? null);
        self::assertSame(2, $second->attempts);
    }

    /**
     * A failed row is not claimed, and nothing of it changes.
     *
     * @return void
     */
    public function testAClaimOfAFailedRowIsRefused(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['failed_at' => self::NOW]);

        $before = $this->outboxRow(self::ID);

        self::assertNull($this->outbox()->claim(self::ID, $this->now()));
        self::assertSame($before, $this->outboxRow(self::ID));
    }

    /**
     * A row due after the instant given is not claimed.
     *
     * @return void
     */
    public function testAClaimOfARowNotYetDueIsRefused(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['available_at' => '2026-11-01T12:00:01.000000Z']);

        $before = $this->outboxRow(self::ID);

        self::assertNull($this->outbox()->claim(self::ID, $this->now()));
        self::assertSame($before, $this->outboxRow(self::ID));
    }

    /**
     * A row another claim holds a live lease on is not claimed, and its owner
     * is kept.
     *
     * @return void
     */
    public function testAClaimOfALiveLeaseIsRefused(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $first = $this->outbox()->claim(self::ID, $this->now());

        $this->moveClockTo('2026-11-01T12:05:00.000000Z');

        self::assertNull($this->outbox()->claim(self::ID, $this->now()));
        self::assertSame($first?->token, $this->outboxRow(self::ID)['claimed_by'] ?? null);
        self::assertSame(1, $this->outboxRow(self::ID)['attempts'] ?? null);
    }

    /**
     * A row whose lease has passed is claimed by the next claim.
     *
     * @return void
     */
    public function testAClaimOfAnExpiredLeaseSucceeds(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['attempts' => 1, 'claimed_by' => self::STALE_TOKEN, 'claimed_until' => '2026-11-01T11:59:59.999999Z']);

        $claim = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($claim);
        self::assertSame(2, $claim->attempts);
        self::assertSame($claim->token, $this->outboxRow(self::ID)['claimed_by'] ?? null);
    }

    /**
     * A candidate that another drain claims, fails or deletes before this claim
     * is not claimed.
     *
     * @return void
     */
    public function testACandidateThatChangedBeforeItsClaimIsRefused(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD);
        $this->seedOutboxRow(self::THIRD_ID, self::PAYLOAD);

        $outbox     = $this->outbox();
        $candidates = $outbox->candidates(10, $this->now());
        $table      = $this->outboxConnection()->table(DeliveryTables::outboxTable());

        $outbox->claim(self::ID, $this->now());
        $table->clone()->where('id', self::SECOND_ID)->update(['failed_at' => '2026-11-01 12:00:00.000000']);
        $table->clone()->where('id', self::THIRD_ID)->delete();

        self::assertSame([self::ID, self::SECOND_ID, self::THIRD_ID], $candidates);
        self::assertNull($outbox->claim(self::ID, $this->now()));
        self::assertNull($outbox->claim(self::SECOND_ID, $this->now()));
        self::assertNull($outbox->claim(self::THIRD_ID, $this->now()));
    }

    /**
     * A claim that changes no row reads nothing after its update, so a lost
     * race costs one statement.
     *
     * @return void
     */
    public function testARefusedClaimReadsNothing(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['failed_at' => self::NOW]);

        $queries = [];

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$queries): void {
            $queries[] = strtok($query, ' ');
        });

        self::assertNull($this->outbox()->claim(self::ID, $this->now()));
        self::assertSame(['update'], $queries);
    }

    /**
     * A claim that wins costs its update and one read of the payload.
     *
     * @return void
     */
    public function testAClaimIsAnUpdateAndARead(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $queries = [];

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$queries): void {
            $queries[] = strtok($query, ' ');
        });

        self::assertNotNull($this->outbox()->claim(self::ID, $this->now()));
        self::assertSame(['update', 'select'], $queries);
    }

    /**
     * A row that does not exist is not claimed.
     *
     * @return void
     */
    public function testAClaimOfAMissingRowIsRefused(): void
    {
        self::assertNull($this->outbox()->claim(self::ID, $this->now()));
    }

    /**
     * Rows of `[operation]`: every change a claim may make to its row.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFencedOperations(): iterable
    {
        yield from [
            'a renewal' => ['renew'],
            'a retry'   => ['retry'],
            'a failure' => ['fail'],
            'a delete'  => ['delete'],
        ];
    }

    /**
     * A claim whose token is not the row's (it lost the row to a later claim)
     * changes nothing and says so.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideFencedOperations')]
    public function testAStaleTokenChangesNothing(string $operation): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $owner = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($owner);

        $before = $this->outboxRow(self::ID);

        $this->moveClockTo('2026-11-01T12:01:00.000000Z');

        self::assertFalse($this->apply($operation, new OutboxClaim(self::ID, self::STALE_TOKEN, self::PAYLOAD, 1)));
        self::assertSame($before, $this->outboxRow(self::ID));
    }

    /**
     * The claim whose token is the row's changes the row and says so.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideFencedOperations')]
    public function testTheOwningTokenChangesTheRow(string $operation): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $owner = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($owner);

        $before = $this->outboxRow(self::ID);

        $this->moveClockTo('2026-11-01T12:01:00.000000Z');

        self::assertTrue($this->apply($operation, $owner));
        self::assertNotSame($before, $this->outboxRow(self::ID));
    }

    /**
     * The first owner of a row reclaimed past its lease changes nothing, even
     * though its claim was once the row's.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideFencedOperations')]
    public function testAnOwnerPastItsLeaseLosesTheRowToTheNext(string $operation): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $first = $this->outbox()->claim(self::ID, $this->now());

        $this->moveClockTo('2026-11-01T12:05:00.000001Z');

        $second = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($first);
        self::assertNotNull($second);

        $before = $this->outboxRow(self::ID);

        self::assertFalse($this->apply($operation, $first));
        self::assertSame($before, $this->outboxRow(self::ID));
    }

    /**
     * A renewal extends the lease to `lease_seconds` from now.
     *
     * @return void
     */
    public function testARenewalExtendsTheLease(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $claim = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($claim);

        $this->moveClockTo('2026-11-01T12:04:00.000000Z');

        self::assertTrue($this->outbox()->renew($claim));
        self::assertSame('2026-11-01T12:09:00.000000Z', $this->outboxRow(self::ID)['claimed_until'] ?? null);
        self::assertSame($claim->token, $this->outboxRow(self::ID)['claimed_by'] ?? null);
    }

    /**
     * A renewal within the same microsecond as the claim changes no column,
     * which MySQL counts as no row changed, and the claim still owns the row.
     *
     * @return void
     */
    public function testARenewalAtTheSameInstantStillOwnsTheRow(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $claim = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($claim);
        self::assertTrue($this->outbox()->renew($claim));
        self::assertTrue($this->outbox()->renew($claim));
        self::assertSame('2026-11-01T12:05:00.000000Z', $this->outboxRow(self::ID)['claimed_until'] ?? null);
    }

    /**
     * A renewal that changes a row costs one statement; only one that changes
     * none reads the row again.
     *
     * @return void
     */
    public function testARenewalReadsOnlyWhenItChangesNoRow(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $claim = $this->outbox()->claim(self::ID, $this->now());

        self::assertNotNull($claim);

        $queries = [];

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$queries): void {
            $queries[] = strtok($query, ' ');
        });

        $this->moveClockTo('2026-11-01T12:01:00.000000Z');
        $this->outbox()->renew($claim);
        $this->outbox()->renew(new OutboxClaim(self::ID, self::STALE_TOKEN, self::PAYLOAD, 1));

        // The owner's renewal is the first statement alone; the stale one's is
        // the next two
        self::assertSame(['update', 'update', 'select'], $queries);
    }

    /**
     * A retry releases the claim, makes the row due at the instant given and
     * names the error's class; the row is a candidate again once that instant
     * comes, and not before.
     *
     * @return void
     */
    public function testARetryReleasesTheClaim(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $outbox = $this->outbox();
        $claim  = $outbox->claim(self::ID, $this->now());

        self::assertNotNull($claim);
        self::assertTrue($outbox->retry($claim, new CarbonImmutable('2026-11-01T12:10:00.000000Z'), \RuntimeException::class));

        $row = $this->outboxRow(self::ID);

        self::assertSame('2026-11-01T12:10:00.000000Z', $row['available_at'] ?? null);
        self::assertSame(\RuntimeException::class, $row['last_error_class'] ?? null);
        self::assertNull($row['claimed_by'] ?? null);
        self::assertNull($row['claimed_until'] ?? null);
        self::assertNull($row['failed_at'] ?? null);
        self::assertSame(1, $row['attempts'] ?? null);
        self::assertSame([], $outbox->candidates(10, $this->now()));
        self::assertSame([self::ID], $outbox->candidates(10, new CarbonImmutable('2026-11-01T12:10:00.000000Z')));
    }

    /**
     * A failure keeps the row, with when it failed and the error's class, and
     * releases the claim; the row is never a candidate again.
     *
     * @return void
     */
    public function testAFailureKeepsTheRow(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $outbox = $this->outbox();
        $claim  = $outbox->claim(self::ID, $this->now());

        self::assertNotNull($claim);

        $this->moveClockTo('2026-11-01T12:00:30.000000Z');

        self::assertTrue($outbox->fail($claim, 'undecryptable'));

        $row = $this->outboxRow(self::ID);

        self::assertSame(1, $this->outboxCount());
        self::assertSame(self::PAYLOAD, $row['payload'] ?? null);
        self::assertSame('2026-11-01T12:00:30.000000Z', $row['failed_at'] ?? null);
        self::assertSame('undecryptable', $row['last_error_class'] ?? null);
        self::assertNull($row['claimed_by'] ?? null);
        self::assertNull($row['claimed_until'] ?? null);
        self::assertSame([], $outbox->candidates(10, new CarbonImmutable('2027-01-01T00:00:00.000000Z')));
        self::assertSame([self::ID], $outbox->failedIds());
    }

    /**
     * An error class longer than its column is cut to the column, never
     * refused.
     *
     * @return void
     */
    public function testALongErrorClassIsCutToItsColumn(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD);

        $outbox = $this->outbox();
        $class  = 'App\\' . str_repeat('Nested\\', 40) . 'Failure';
        $first  = $outbox->claim(self::ID, $this->now());
        $second = $outbox->claim(self::SECOND_ID, $this->now());

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertTrue($outbox->retry($first, $this->now(), $class));
        self::assertTrue($outbox->fail($second, $class));

        $cut = substr($class, 0, WriteDiagnostics::CLASS_MAX_BYTES);

        self::assertSame($cut, $this->outboxRow(self::ID)['last_error_class'] ?? null);
        self::assertSame($cut, $this->outboxRow(self::SECOND_ID)['last_error_class'] ?? null);
    }

    /**
     * An error class is cut on a character boundary, so a multibyte name never
     * leaves half a character in the column.
     *
     * @return void
     */
    public function testAnErrorClassIsCutOnACharacterBoundary(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);

        $outbox = $this->outbox();
        $class  = 'App\\' . str_repeat('é', 100);
        $claim  = $outbox->claim(self::ID, $this->now());

        self::assertNotNull($claim);
        self::assertTrue($outbox->fail($claim, $class));

        $stored = $this->outboxRow(self::ID)['last_error_class'] ?? null;

        self::assertSame(mb_strcut($class, 0, WriteDiagnostics::CLASS_MAX_BYTES, 'UTF-8'), $stored);
        self::assertSame(WriteDiagnostics::CLASS_MAX_BYTES - 1, strlen($stored));
    }

    /**
     * A delete removes the claim's row and no other.
     *
     * @return void
     */
    public function testADeleteRemovesOnlyTheClaimedRow(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD);

        $outbox = $this->outbox();
        $claim  = $outbox->claim(self::ID, $this->now());

        self::assertNotNull($claim);
        self::assertTrue($outbox->delete($claim));
        self::assertFalse($outbox->delete($claim));
        self::assertNull($this->outboxRow(self::ID));
        self::assertNotNull($this->outboxRow(self::SECOND_ID));
    }

    /**
     * Requeueing unfails each failed row among the ids, resets its attempts,
     * makes it due now and unclaimed, and keeps its error's class; a row that
     * is not failed, among the ids or not, is left as it is.
     *
     * @return void
     */
    public function testRequeueingClearsOnlyFailedRows(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, [
            'attempts'         => 10,
            'available_at'     => '2026-11-01T09:00:00.000000Z',
            'failed_at'        => '2026-11-01T10:00:00.000000Z',
            'last_error_class' => 'abandoned',
        ]);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD, ['attempts' => 2, 'claimed_by' => self::STALE_TOKEN, 'claimed_until' => '2026-11-01T12:03:00.000000Z']);
        $this->seedOutboxRow(self::THIRD_ID, self::PAYLOAD, ['attempts' => 10, 'failed_at' => '2026-11-01T10:00:00.000000Z']);

        $unfailed = $this->outboxRow(self::SECOND_ID);
        $other    = $this->outboxRow(self::THIRD_ID);

        $this->moveClockTo('2026-11-01T13:00:00.000000Z');

        self::assertSame(1, $this->outbox()->requeueFailed([self::ID, self::SECOND_ID]));

        self::assertSame([
            'id'               => self::ID,
            'payload'          => self::PAYLOAD,
            'attempts'         => 0,
            'available_at'     => '2026-11-01T13:00:00.000000Z',
            'claimed_until'    => null,
            'claimed_by'       => null,
            'failed_at'        => null,
            'last_error_class' => 'abandoned',
            'created_at'       => self::NOW,
        ], $this->outboxRow(self::ID));

        self::assertSame($unfailed, $this->outboxRow(self::SECOND_ID));
        self::assertSame($other, $this->outboxRow(self::THIRD_ID));
    }

    /**
     * A requeued row is claimable again at once.
     *
     * @return void
     */
    public function testARequeuedRowIsACandidateAgain(): void
    {
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['attempts' => 10, 'failed_at' => self::NOW]);

        $outbox = $this->outbox();

        $outbox->requeueFailed([self::ID]);

        self::assertSame([self::ID], $outbox->candidates(10, $this->now()));
        self::assertSame(1, $outbox->claim(self::ID, $this->now())?->attempts);
    }

    /**
     * Requeueing no ids runs no statement and requeues nothing.
     *
     * @return void
     */
    public function testRequeueingNothingRunsNoStatement(): void
    {
        $queries = 0;

        $this->outboxConnection()->beforeExecuting(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame(0, $this->outbox()->requeueFailed([]));
        self::assertSame(0, $queries);
    }

    /**
     * A list of ids longer than one statement binds is requeued in chunks,
     * every failed row of it.
     *
     * @return void
     */
    public function testRequeueingAListLongerThanAChunkRequeuesEveryRow(): void
    {
        $ids  = [];
        $rows = [];

        foreach (range(1, 1201) as $number) {
            $id     = sprintf('01932b4e-8a40-7000-8000-%012d', $number);
            $ids[]  = $id;
            $rows[] = [
                'id'           => $id,
                'payload'      => self::PAYLOAD,
                'attempts'     => 10,
                'available_at' => '2026-11-01 11:00:00.000000',
                'failed_at'    => '2026-11-01 11:00:00.000000',
                'created_at'   => '2026-11-01 11:00:00.000000',
            ];
        }

        foreach (array_chunk($rows, 100) as $chunk) {
            $this->outboxConnection()->table(DeliveryTables::outboxTable())->insert($chunk);
        }

        $statements = 0;

        $this->outboxConnection()->beforeExecuting(static function () use (&$statements): void {
            $statements++;
        });

        self::assertSame(1201, $this->outbox()->requeueFailed($ids));
        self::assertSame(3, $statements);
        self::assertSame([], $this->outbox()->failedIds());
    }

    /**
     * The failed ids are every failed row's, in id order, and no other row's.
     *
     * @return void
     */
    public function testFailedIdsAreOrdered(): void
    {
        $this->seedOutboxRow(self::THIRD_ID, self::PAYLOAD, ['failed_at' => '2026-11-01T09:00:00.000000Z']);
        $this->seedOutboxRow(self::SECOND_ID, self::PAYLOAD);
        $this->seedOutboxRow(self::ID, self::PAYLOAD, ['failed_at' => '2026-11-01T10:00:00.000000Z']);

        self::assertSame([self::ID, self::THIRD_ID], $this->outbox()->failedIds());
    }

    /**
     * The outbox, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\Outbox
     */
    private function outbox(): Outbox
    {
        return app(Outbox::class);
    }

    /**
     * The instant the clock is stopped at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function now(): CarbonImmutable
    {
        return CarbonImmutable::now();
    }

    /**
     * Make the change the operation names with the claim, and return whether
     * the outbox says the claim still owned the row.
     *
     * @param  string  $operation
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return bool
     */
    private function apply(string $operation, OutboxClaim $claim): bool
    {
        $outbox = $this->outbox();

        return match ($operation) {
            'renew' => $outbox->renew($claim),
            'retry' => $outbox->retry($claim, new CarbonImmutable('2026-11-01T12:10:00.000000Z'), \RuntimeException::class),
            'fail'  => $outbox->fail($claim, \RuntimeException::class),
            default => $outbox->delete($claim),
        };
    }
}
