<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\PendingDeliveries;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for outbox mode under the documented grants and the outbox
 * mode grants, on MySQL and PostgreSQL; SQLite has no privileges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(Replayer::class)]
#[CoversClass(PendingDeliveries::class)]
final class LeastPrivilegeOutboxTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses, which is the storage and the outbox connection. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses, which is the maintenance connection. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var list<string> The placeholders this test creates a login for. */
    private const array LOGINS = ['audit_writer', 'audit_maintenance', 'audit_verifier'];

    /** @var string When every operation runs. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every stored entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string The destination of a store that is not a stack. */
    private const string DESTINATION = 'store';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /** @var bool Whether the store refuses what the drain delivers. */
    private bool $storeIsDown = false;

    /**
     * Create this worker's logins, grant them as documented, add the writer's
     * outbox mode grants, and connect as them in outbox mode.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root = $this->root();

        if ($root->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        foreach (self::LOGINS as $placeholder) {
            self::createLogin($root, $this->names[$placeholder]);
        }

        self::runDocumentedGrants($root, $this->names);
        $this->grantOutboxMode();
        self::connectAs(self::WRITER, self::CONNECTION, $this->names[self::WRITER]);
        self::connectAs(self::MAINTENANCE, self::CONNECTION, $this->names[self::MAINTENANCE]);

        app(ConfigRepository::class)->set([
            'audit-log.storage.connection'             => self::WRITER,
            'audit-log.storage.maintenance_connection' => self::MAINTENANCE,
            'audit-log.delivery.mode'                  => DeliveryMode::OUTBOX->value,
            'audit-log.retention.after_days'           => 30,
        ]);

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Close the logins' connections, drop the logins, and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->names !== []) {

            foreach ([self::WRITER, self::MAINTENANCE] as $connection) {
                DB::purge($connection);
            }

            foreach (self::LOGINS as $placeholder) {
                self::dropLogin($this->root(), $this->names[$placeholder]);
            }
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The writer records into the outbox, fails a drain, and replays the row
     * to one stored entry with a delivered receipt.
     *
     * @return void
     */
    public function testAWriterWithTheOutboxGrantsRecordsDrainsAndReplays(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        app()->instance(AuditStore::class, new CallbackStore(function (FinalisedRecord $record): void {
            if ($this->storeIsDown) {
                throw new \DomainException('The store is down.');
            }

            app(DatabaseAuditStore::class)->store($record);
        }));

        $id = AuditLog::event('invoice.approved')->immediately()->record()->id;

        self::assertSame(1, $this->root()->table(DeliveryTables::outboxTable())->where('id', $id)->count());

        $this->storeIsDown = true;

        self::assertSame(1, Artisan::call('audit-log:drain'), Artisan::output());
        self::assertNotNull($this->root()->table(DeliveryTables::outboxTable())->where('id', $id)->value('failed_at'));
        self::assertSame(\DomainException::class, $this->root()->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->value('last_error_class'));

        $this->storeIsDown = false;

        self::assertSame(0, Artisan::call('audit-log:replay', ['--outbox' => true]), Artisan::output());
        self::assertSame(0, $this->root()->table(DeliveryTables::outboxTable())->count());
        self::assertSame([$id], self::strings($this->root()->table(EntrySettings::table())->pluck('id')->all()));

        $receipt = (array) $this->root()->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->sole();

        self::assertSame(self::DESTINATION, $receipt['destination']);
        self::assertNotNull($receipt['delivered_at']);
        self::assertNull($receipt['last_error_class']);
    }

    /**
     * The maintenance user prunes, deleting the delivered entry's receipt, and
     * defers an entry still in the outbox and one with an undelivered receipt.
     *
     * @return void
     */
    public function testTheMaintenanceUserPrunesAndDefersPendingDeliveries(): void
    {
        $queued      = $this->storeEntry();
        $undelivered = $this->storeEntry();
        $delivered   = $this->storeEntry();

        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]), Artisan::output());

        $this->root()->table(DeliveryTables::outboxTable())->insert([
            'id'           => $queued,
            'payload'      => 'payload',
            'attempts'     => 0,
            'available_at' => '2026-12-02 12:00:00.000000',
            'created_at'   => '2026-12-02 12:00:00.000000',
        ]);

        $this->root()->table(DeliveryTables::deliveriesTable())->insert([
            ['entry_id' => $undelivered, 'destination' => 'siem', 'attempts' => 3, 'first_attempted_at' => '2026-12-02 12:00:01.000000', 'delivered_at' => null, 'last_error_class' => \RuntimeException::class],
            ['entry_id' => $delivered, 'destination' => 'siem', 'attempts' => 1, 'first_attempted_at' => '2026-12-02 12:00:01.000000', 'delivered_at' => '2026-12-02 12:00:02.000000', 'last_error_class' => null],
        ]);

        $result = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 2, true], [$result->status, $result->deleted, $result->pendingDelivery, $result->recorded]);
        self::assertEqualsCanonicalizing([$queued, $undelivered], self::strings($this->root()->table(EntrySettings::table())->pluck('id')->all()));
        self::assertSame([$undelivered], self::strings($this->root()->table(DeliveryTables::deliveriesTable())->pluck('entry_id')->all()));
        self::assertSame(1, $this->root()->table(DeliveryTables::outboxTable())->where('id', $queued)->count());
    }

    /**
     * Grant the writer the role matrix's outbox mode privileges: `SELECT`,
     * `INSERT`, `UPDATE` and `DELETE` on the outbox and all but `DELETE` on the
     * receipts.
     *
     * @return void
     */
    private function grantOutboxMode(): void
    {
        $root   = $this->root();
        $writer = $this->names[self::WRITER];
        $grants = [DeliveryTables::outboxTable() => 'SELECT, INSERT, UPDATE, DELETE', DeliveryTables::deliveriesTable() => 'SELECT, INSERT, UPDATE'];

        foreach ($grants as $table => $privileges) {
            $root->statement($root->getDriverName() === 'mysql'
                ? sprintf('GRANT %s ON `%s`.`%s` TO \'%s\'@\'%%\'', $privileges, $root->getDatabaseName(), $table, $writer)
                : sprintf('GRANT %s ON "%s" TO "%s"', $privileges, $table, $writer));
        }
    }

    /**
     * Store a record past retention through the writer, and return its id.
     *
     * @return string
     */
    private function storeEntry(): string
    {
        $finalised = (new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class)))->finalise(RecordFactory::withFields(['occurred_at' => self::OLD]));

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * The worker's own connection, as the tables' owner.
     *
     * @return \Illuminate\Database\Connection
     */
    private function root(): Connection
    {
        return DB::connection(self::CONNECTION);
    }
}
