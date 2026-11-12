<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsInsideTheTestingWrapper;
use Tests\TestCase;

/**
 * Integration tests for the read gate's transaction rule on the suite's engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadGate::class)]
final class DisclosureTransactionsTest extends TestCase
{
    use ReadsTheTrail, RunsInsideTheTestingWrapper;

    /** @var string A connection of the outbox's own, on the engine under test. */
    private const string OUTBOX = 'audit_disclosure_outbox';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        parent::tearDown();
    }

    /**
     * Rows of `[terminal call]`: a page and a count.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)}>
     */
    public static function provideTerminals(): iterable
    {
        yield from [
            'a page'  => [static fn (AuditTrail $trail): TrailPage => $trail->cursorPaginate()],
            'a count' => [static fn (AuditTrail $trail): int => $trail->count()],
        ];
    }

    /**
     * A read inside `DB::transaction()` is refused before anything runs.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $terminal
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testARefusedReadRunsNoQuery(\Closure $terminal): void
    {
        $this->bindReading();

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(3);

        $storage    = StorageConnection::resolvedName();
        $trail      = app(AuditTrail::class)->visibleTo($this->viewer());
        $refusal    = null;
        $statements = new class {
            /** @var list<string> The statements run while it listens, in order. */
            public array $ran = [];

            /** @var bool Whether it keeps the statements run. */
            public bool $listening = false;
        };

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($statements): void {
            if (!$statements->listening) {
                return;
            }

            $statements->ran[] = $query->sql;
        });

        DB::connection($storage)->transaction(static function () use ($terminal, $trail, &$refusal, $statements): void {
            $statements->listening = true;

            try {
                $terminal($trail);
            } catch (AuditReadRefusedException $exception) {
                $refusal = $exception;
            } finally {
                $statements->listening = false;
            }
        });

        self::assertInstanceOf(AuditReadRefusedException::class, $refusal);
        self::assertSame(AuditReadRefusedException::inTransaction($storage)->getMessage(), $refusal->getMessage());
        self::assertSame([], $statements->ran);
        self::assertSame([], $policy->asked());
    }

    /**
     * Under the testing manager the gate admits reads in the base transaction.
     *
     * @return void
     */
    public function testUnderTheTestingManagerTheGateEnters(): void
    {
        $this->insideTheTestingWrapper(DB::connection(StorageConnection::resolvedName()), function (Connection $connection): void {
            $this->gate()->enter();

            $connection->beginTransaction();

            try {
                $this->gate()->enter();

                self::fail('Expected a read inside the test\'s own transaction to be refused.');
            } catch (AuditReadRefusedException $exception) {
                self::assertSame(AuditReadRefusedException::inTransaction((string) $connection->getName())->getMessage(), $exception->getMessage());
            } finally {
                $connection->rollBack();
            }

            $this->gate()->confirmDurable();
        });
    }

    /**
     * An outbox connection of its own is judged by its own transaction.
     *
     * @return void
     */
    public function testAnOutboxOnAnotherConnectionIsJudgedByItsOwnTransaction(): void
    {
        $config = app(ConfigRepository::class);
        $outbox = DB::connection(self::OUTBOX);

        $config->set('audit-log.delivery.mode', 'outbox');

        $outbox->beginTransaction();

        try {
            $this->gate()->enter();

            self::fail('Expected a read inside the outbox connection\'s transaction to be refused.');
        } catch (AuditReadRefusedException $exception) {
            self::assertSame(AuditReadRefusedException::inTransaction(self::OUTBOX)->getMessage(), $exception->getMessage());
        }

        $config->set('audit-log.delivery.mode', 'sync');

        $this->gate()->enter();

        $outbox->commit();

        $config->set('audit-log.delivery.mode', 'outbox');

        $this->gate()->enter();

        self::assertSame(0, $outbox->transactionLevel());
    }

    /**
     * Put the outbox on a copy of the storage connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OUTBOX, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'outbox_']);
        $config->set('audit-log.delivery.outbox.connection', self::OUTBOX);
    }

    /**
     * The gate, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadGate
     */
    private function gate(): ReadGate
    {
        return app(ReadGate::class);
    }
}
