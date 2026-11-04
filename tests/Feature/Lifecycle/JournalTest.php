<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\Journal;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for the journal's writer, on whichever engine the suite runs
 * against: the first row starts the chain and every later one links to the
 * head, at the clock's time, in the configured log, signed; a head that is not
 * the replay's, forged, deleted, replaced or added since it was read, is
 * refused and nothing is appended; the replay returned has accepted the row and
 * the one given is left as it was; a sequence taken outside the lock is a
 * programming error; and the row carries its authority and is written on the
 * maintenance connection, only inside a transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Journal::class)]
final class JournalTest extends TestCase
{
    use WritesTheJournal;

    /** @var string The operation every test runs. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string When every row is appended. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string A hold id. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string A second connection to the worker's database. */
    private const string MAINTENANCE = 'audit_maintenance';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
    }

    /**
     * Put the clock back and forget the second connection.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::purge(self::MAINTENANCE);
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The first row of an empty journal is sequence 1, with no previous HMAC,
     * in the configured log, at the clock's time, under the operation, and its
     * signature verifies.
     *
     * @return void
     */
    public function testTheFirstRowStartsTheChain(): void
    {
        $this->append(JournalKind::POLICY, ['version' => 'config:0123456789abcdef']);

        $rows = $this->journalRows();

        self::assertCount(1, $rows);

        $row = JournalRow::fromRow($rows[0], true);

        self::assertSame(1, $row->sequence);
        self::assertNull($row->previousHmac);
        self::assertSame(app(SealSettings::class)->logId(), $row->logId);
        self::assertSame(JournalKind::POLICY, $row->kind);
        self::assertSame(self::OPERATION, $row->operationId);
        self::assertSame('2026-11-02T09:00:00.123456Z', $row->occurredAt);
        self::assertSame(['version' => 'config:0123456789abcdef'], $row->payloadMap());
        self::assertNull($row->authorityType);
        self::assertTrue(app(JournalSigner::class)->verifies($row));
    }

    /**
     * Each row takes the next sequence and links to the head's HMAC, whether
     * the head was written by an earlier operation or by the same one.
     *
     * @return void
     */
    public function testEachRowLinksToTheHead(): void
    {
        $first = $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        $this->transaction(function (Connection $connection) use ($first): void {
            $replay = $this->replay()->verify($connection);
            $replay = $this->writer()->append($connection, $replay, JournalKind::POLICY, self::OPERATION, null, ['version' => 'config:0000000000000002']);
            $second = $replay->lastAppended();

            self::assertNotNull($second);
            self::assertSame(2, $second->sequence);
            self::assertSame($first->hmac, $second->previousHmac);

            $this->writer()->append($connection, $replay, JournalKind::POLICY, self::OPERATION, null, ['version' => 'config:0000000000000003']);
        });

        $rows = array_map(static fn (array $row): JournalRow => JournalRow::fromRow($row, true), $this->journalRows());

        self::assertSame([1, 2, 3], array_map(static fn (JournalRow $row): int => $row->sequence, $rows));
        self::assertSame($rows[1]->hmac, $rows[2]->previousHmac);
        self::assertSame($rows[0]->hmac, $rows[1]->previousHmac);
        self::assertNotSame($rows[1]->id, $rows[2]->id);
    }

    /**
     * A row forged onto the head, signed under no key the ring holds, is
     * refused by the replay before any append, and nothing is appended onto it.
     *
     * @return void
     */
    public function testItRefusesToChainOntoAForgedHead(): void
    {
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        $forged = $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000002']);

        $this->tamperJournal(2, ['hmac' => str_repeat('a', 64)]);

        $exception = $this->thrownBy(fn () => $this->append(JournalKind::POLICY, ['version' => 'config:0000000000000003']));

        self::assertInstanceOf(JournalBrokenException::class, $exception);
        self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        self::assertSame($forged->id, $exception->rowId);
        self::assertCount(2, $this->journalRows());
    }

    /**
     * Rows of `[what changes the journal after the replay read it]`: a head
     * deleted, a row added, and a head replaced under another HMAC.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(self): mixed}>
     */
    public static function provideChangedHeads(): iterable
    {
        yield from [
            'the head deleted'  => [static fn (self $test): int => $test->journalTableOnStorage()->where('sequence', 2)->delete()],
            'a row added'       => [static fn (self $test): JournalRow => $test->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000009'])],
            'the head replaced' => [static fn (self $test): int => $test->journalTableOnStorage()->where('sequence', 2)->update(['hmac' => str_repeat('b', 64)])],
        ];
    }

    /**
     * A head that is not the replay's, by its sequence or its HMAC, is a gap,
     * found at the stored head, and nothing is appended.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(self): mixed  $change
     * @return void
     */
    #[DataProvider('provideChangedHeads')]
    public function testAppendRefusesAHeadThatIsNotTheReplays(\Closure $change): void
    {
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000002']);

        $head = null;

        $exception = $this->thrownBy(function () use ($change, &$head): void {
            $this->transaction(function (Connection $connection) use ($change, &$head): void {
                $replay = $this->replay()->verify($connection);

                $change($this);

                $head = $this->journalTableOnStorage()->orderByDesc('sequence')->value('id');

                $this->writer()->append($connection, $replay, JournalKind::POLICY, self::OPERATION, null, ['version' => 'config:0000000000000003']);
            });
        });

        self::assertInstanceOf(JournalBrokenException::class, $exception);
        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertIsString($head);
        self::assertSame($head, $exception->rowId);
        self::assertCount(2, $this->journalRows());
    }

    /**
     * A replay of an empty journal refuses to append onto a row written since
     * it read, and one of a journal whose rows were all deleted since refuses
     * to append onto nothing.
     *
     * @return void
     */
    public function testAppendRefusesAnEmptyJournalThatIsNotTheReplays(): void
    {
        $exception = $this->thrownBy(fn () => $this->transaction(function (Connection $connection): void {
            $replay = $this->replay()->verify($connection);

            $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

            $this->writer()->append($connection, $replay, JournalKind::POLICY, self::OPERATION, null, ['version' => 'config:0000000000000002']);
        }));

        self::assertInstanceOf(JournalBrokenException::class, $exception);
        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertSame([], $this->journalRows());

        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        $exception = $this->thrownBy(fn () => $this->transaction(function (Connection $connection): void {
            $replay = $this->replay()->verify($connection);

            $this->journalTableOnStorage()->delete();

            $this->writer()->append($connection, $replay, JournalKind::POLICY, self::OPERATION, null, ['version' => 'config:0000000000000002']);
        }));

        self::assertInstanceOf(JournalBrokenException::class, $exception);
        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertNull($exception->rowId);
        self::assertCount(1, $this->journalRows());
    }

    /**
     * The replay returned has accepted the row: its head is the row, which is
     * its last appended row, and it holds the hold the row placed; the replay
     * given is left as it was.
     *
     * @return void
     */
    public function testAppendReturnsTheReplayThatAcceptedTheRow(): void
    {
        [$before, $after] = $this->transaction(function (Connection $connection): array {
            $before = $this->replay()->verify($connection);
            $after  = $this->writer()->append($connection, $before, JournalKind::HOLD, self::OPERATION, $this->authority(), self::holdPayload(), holdId: self::HOLD);

            return [$before, $after];
        });

        $row = JournalRow::fromRow($this->journalRows()[0], true);

        self::assertNull($before->head());
        self::assertNull($before->lastAppended());
        self::assertSame([], $before->holds());
        self::assertSame([1, $row->hmac], $after->head());
        self::assertSame($row->hmac, $after->lastAppended()?->hmac);
        self::assertSame([self::HOLD], array_map(static fn (Hold $hold): string => $hold->id, $after->holds()));
        self::assertTrue($after->hasPlacedHold(self::HOLD));
        self::assertFalse($before->hasPlacedHold(self::HOLD));
    }

    /**
     * A transition the chain does not allow, a release of a hold never placed,
     * is refused by the replay and nothing is appended.
     *
     * @return void
     */
    public function testAnInvalidTransitionIsRefusedAndNothingIsAppended(): void
    {
        $exception = $this->thrownBy(fn () => $this->append(JournalKind::RELEASE, ['hold_id' => self::HOLD], $this->authority(), self::HOLD));

        self::assertInstanceOf(JournalBrokenException::class, $exception);
        self::assertSame(Finding::JOURNAL_TRANSITION, $exception->finding);
        self::assertSame([], $this->journalRows());
    }

    /**
     * A row already stored at the next sequence, written after the head was
     * read as only an append outside the lock could, makes the insert a
     * programming error that names no value of the row.
     *
     * @return void
     */
    public function testASequenceCollisionIsALogicException(): void
    {
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        $journal = LifecycleTables::journalTable();
        $planted = false;

        DB::listen(function (QueryExecuted $query) use ($journal, &$planted): void {
            if ($planted || !str_contains($query->sql, $journal) || !str_contains($query->sql, 'order by') || !str_contains($query->sql, 'desc')) {
                return;
            }

            $planted = true;

            $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000008']);
        });

        $exception = $this->thrownBy(fn () => $this->append(JournalKind::POLICY, ['version' => 'config:0000000000000009']));

        self::assertTrue($planted);
        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame('The journal was appended to outside the lifecycle lock.', $exception->getMessage());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The row is inserted through the maintenance connection when another is
     * configured, inside the transaction it holds.
     *
     * @return void
     */
    public function testItWritesOnTheMaintenanceConnection(): void
    {
        $this->sameDatabase();

        $journal = LifecycleTables::journalTable();
        $inserts = [];

        DB::listen(static function (QueryExecuted $query) use ($journal, &$inserts): void {
            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, $journal)) {
                return;
            }

            $inserts[] = $query->connectionName;
        });

        $this->append(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        self::assertSame([self::MAINTENANCE], $inserts);
        self::assertCount(1, $this->journalRows());
    }

    /**
     * A row of a kind that carries an authority holds its operator, its reason
     * and its external reference in its own columns, signed.
     *
     * @return void
     */
    public function testTheRowCarriesTheAuthority(): void
    {
        $this->append(JournalKind::HOLD, self::holdPayload(), $this->authority(), self::HOLD);

        $row = JournalRow::fromRow($this->journalRows()[0], true);

        self::assertSame('App\Models\User', $row->authorityType);
        self::assertSame('7', $row->authorityId);
        self::assertSame('case.review', $row->reason);
        self::assertSame('app:ticket-123', $row->externalReference);
        self::assertSame(self::HOLD, $row->holdId);
        self::assertNull($row->sealId);
        self::assertTrue(app(JournalSigner::class)->verifies($row));
    }

    /**
     * A prune row carries the seal it covers, and no authority.
     *
     * @return void
     */
    public function testAPruneRowCarriesItsSeal(): void
    {
        $seal = '01932b4e-c000-7000-8000-000000000001';

        $this->append(JournalKind::PRUNE, ['record' => ['seal_id' => $seal], 'run_id' => 'run-1'], sealId: $seal);

        $row = JournalRow::fromRow($this->journalRows()[0], true);

        self::assertSame($seal, $row->sealId);
        self::assertNull($row->holdId);
        self::assertNull($row->authorityType);
    }

    /**
     * Rows of `[kind, authority given]`: a kind that carries an authority
     * without one, and one that never carries one with one.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: bool, 2: string}>
     */
    public static function provideAuthorityMismatches(): iterable
    {
        yield from [
            'a hold without one'    => [JournalKind::HOLD, false, 'A journal row of the kind `hold` must carry an authority.'],
            'an import without one' => [JournalKind::IMPORT_FINISHED, false, 'A journal row of the kind `import_finished` must carry an authority.'],
            'a policy with one'     => [JournalKind::POLICY, true, 'A journal row of the kind `policy` never carries an authority.'],
            'a prune run with one'  => [JournalKind::PRUNE_RUN, true, 'A journal row of the kind `prune_run` never carries an authority.'],
        ];
    }

    /**
     * A row's authority follows its kind, and a mismatch is a programming error
     * that reads nothing and appends nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  bool  $withAuthority
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideAuthorityMismatches')]
    public function testTheAuthorityFollowsTheKind(JournalKind $kind, bool $withAuthority, string $message): void
    {
        $exception = $this->thrownBy(fn () => $this->append($kind, ['phase' => 'start'], $withAuthority ? $this->authority() : null));

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame($message, $exception->getMessage());
        self::assertSame([], $this->journalRows());
    }

    /**
     * An append outside a transaction is a programming error, and nothing is
     * appended.
     *
     * @return void
     */
    public function testItRefusesOutsideATransaction(): void
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        $payload   = ['version' => 'config:0000000000000001'];
        $exception = $this->thrownBy(fn () => $this->writer()->append($connection, $this->replay(), JournalKind::POLICY, self::OPERATION, null, $payload));

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame('The journal is appended to only inside a lifecycle transaction.', $exception->getMessage());
        self::assertSame([], $this->journalRows());
    }

    /**
     * Append one row of the kind through the journal, in one lifecycle
     * transaction onto the verified journal.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<array-key, mixed>  $payload
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  ?string  $holdId
     * @param  ?string  $sealId
     * @return void
     */
    private function append(JournalKind $kind, array $payload, ?Authority $authority = null, ?string $holdId = null, ?string $sealId = null): void
    {
        $this->transaction(function (Connection $connection) use ($kind, $payload, $authority, $holdId, $sealId): void {
            $this->writer()->append($connection, $this->replay()->verify($connection), $kind, self::OPERATION, $authority, $payload, $sealId, $holdId);
        });
    }

    /**
     * Run the work in one lifecycle transaction and return its result.
     *
     * @template TResult
     *
     * @param  \Closure(\Illuminate\Database\Connection): TResult  $work
     * @return TResult
     */
    private function transaction(\Closure $work): mixed
    {
        return app(MaintenanceTransaction::class)->run(self::OPERATION, $work);
    }

    /**
     * What the call throws, failing the test when it throws nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Expected the call to throw.');
    }

    /**
     * A query of the journal table on the storage connection's writer.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function journalTableOnStorage(): Builder
    {
        return DB::connection(StorageConnection::name())->table(LifecycleTables::journalTable())->useWritePdo();
    }

    /**
     * The journal the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Journal
     */
    private function writer(): Journal
    {
        return app(Journal::class);
    }

    /**
     * A replay of nothing yet, of the configured log.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId());
    }

    /**
     * The authority every hold is placed with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * The payload of a hold of every entry.
     *
     * @return array{hold_id: string, scope: array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>, basis: string, review_by: null}
     */
    private static function holdPayload(): array
    {
        return ['hold_id' => self::HOLD, 'scope' => HoldScope::all()->toArray(), 'basis' => 'legal_claim', 'review_by' => null];
    }

    /**
     * Configure `MAINTENANCE`, a second connection to the worker's database, as
     * the maintenance connection: on SQLite it shares the in-memory database's
     * connection.
     *
     * @return void
     */
    private function sameDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MAINTENANCE, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            return;
        }

        $same = DB::connection(self::MAINTENANCE);

        $same->setPdo($root->getPdo());
        $same->setReadPdo($root->getPdo());
    }
}
