<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the store under a `SELECT` and `INSERT` writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class LeastPrivilegeWriterTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The connection the least-privilege login writes through. */
    private const string WRITER = 'audit_writer';

    /** @var string The login's password. */
    private const string PASSWORD = 'audit-writer-password';

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The login this worker creates. */
    private string $login = '';

    /**
     * Create the least-privilege login as the storage connection, on MySQL and
     * PostgreSQL only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $token       = getenv('TEST_TOKEN');
        $this->login = 'audit_writer_' . ($token === false || $token === '' ? '0' : $token);

        $this->dropLogin();
        $this->createLogin();

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::WRITER, [
            ...$config->array('database.connections.' . self::CONNECTION),
            'username' => $this->login,
            'password' => self::PASSWORD,
        ]);

        $config->set('audit-log.storage.connection', self::WRITER);
    }

    /**
     * Close the writer's connection and drop the login.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->login !== '') {

            $writer = DB::connection(self::WRITER);

            while ($writer->transactionLevel() > 0) {
                $writer->rollBack();
            }

            DB::purge(self::WRITER);

            $this->dropLogin();
        }

        parent::tearDown();
    }

    /**
     * A minimal writer stores records and resolves their duplicates.
     *
     * @return void
     */
    public function testAWriterGrantedOnlyWhatTheStoreNeedsStoresAndResolvesDuplicates(): void
    {
        $first  = $this->finalised(self::ID);
        $second = $this->finalised('01932b4e-8a40-7000-8000-000000000002');
        $writer = $this->writer();

        $this->store()->store($first);
        $this->store()->store($first);

        $writer->beginTransaction();

        $this->store()->store($second);
        $this->store()->store($second);
        $this->store()->store($first);

        $writer->commit();

        self::assertSame(self::WRITER, $this->storageConnection()->getName());
        self::assertSame(2, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * A minimal writer stores bundles and resolves their duplicates.
     *
     * @return void
     */
    public function testAWriterGrantedOnlyWhatTheStoreNeedsStoresABundle(): void
    {
        $first  = $this->finaliser()->finalise(RecordFactory::bundled());
        $second = $this->finaliser()->finalise(RecordFactory::bundled(5));
        $writer = $this->writer();

        $this->store()->store($first);
        $this->store()->store($first);

        $writer->beginTransaction();

        $this->store()->store($second);
        $this->store()->store($second);
        $this->store()->store($first);

        $writer->commit();

        self::assertSame(self::WRITER, $this->storageConnection()->getName());
        self::assertSame(2, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
        self::assertSame(2, DB::connection(self::CONNECTION)->table(EntrySettings::artifactsTable())->count());
    }

    /**
     * The engine refuses the writer any update or delete of an entry.
     *
     * @return void
     */
    public function testTheWriterIsRefusedUpdatesAndDeletes(): void
    {
        $finalised = $this->finalised(self::ID);
        $writer    = $this->writer();

        $this->store()->store($finalised);

        $refusals = [
            'update' => static fn () => $writer->table(EntrySettings::table())->where('id', self::ID)->update(['outcome' => 'failure']),
            'delete' => static fn () => $writer->table(EntrySettings::table())->where('id', self::ID)->delete(),
        ];

        foreach ($refusals as $statement => $refusal) {
            try {
                $refusal();

                self::fail("Expected the writer's {$statement} to be refused.");
            } catch (QueryException $exception) {
                self::assertSame($writer->getDriverName() === 'mysql' ? '42000' : '42501', $exception->getCode(), "The {$statement}.");
            }
        }

        self::assertSame(1, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
        self::assertSame($finalised->hmac, DB::connection(self::CONNECTION)->table(EntrySettings::table())->value('hmac'));
        self::assertSame('success', DB::connection(self::CONNECTION)->table(EntrySettings::table())->value('outcome'));
    }

    /**
     * The engine refuses the writer any update or delete of an artifact.
     *
     * @return void
     */
    public function testTheWriterIsRefusedArtifactUpdatesAndDeletes(): void
    {
        $bundle     = $this->finaliser()->finalise(RecordFactory::bundled());
        $writer     = $this->writer();
        $attachment = $bundle->record->attachment;

        self::assertNotNull($attachment);

        $this->store()->store($bundle);

        $refusals = [
            'update' => static fn () => $writer->table(EntrySettings::artifactsTable())->where('id', $attachment->id)->update(['member_count' => 4]),
            'delete' => static fn () => $writer->table(EntrySettings::artifactsTable())->where('id', $attachment->id)->delete(),
        ];

        foreach ($refusals as $statement => $refusal) {
            try {
                $refusal();

                self::fail("Expected the writer's {$statement} of an artifact to be refused.");
            } catch (QueryException $exception) {
                self::assertSame($writer->getDriverName() === 'mysql' ? '42000' : '42501', $exception->getCode(), "The {$statement}.");
            }
        }

        $stored = (array) DB::connection(self::CONNECTION)->table(EntrySettings::artifactsTable())->sole();

        self::assertSame($attachment->id, $stored['id']);
        self::assertSame($attachment->digest, $stored['digest']);
        self::assertSame('3', (string) $stored['member_count']);
    }

    /**
     * On MySQL the locking read needs only `SELECT`, unlike `FOR UPDATE`.
     *
     * @return void
     */
    public function testOnMySqlTheLockingReadNeedsOnlySelect(): void
    {
        $writer = $this->writer();

        if ($writer->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL resolves a duplicate inside a transaction with a locking read.');
        }

        $finalised = $this->finalised(self::ID);

        $this->store()->store($finalised);

        $writer->beginTransaction();

        $this->store()->store($finalised);

        $forUpdate = static fn () => $writer->table(EntrySettings::table())->where('id', self::ID)->lockForUpdate()->first();
        $refusal   = rescue($forUpdate, static fn (\Throwable $exception): \Throwable => $exception, false);

        self::assertInstanceOf(QueryException::class, $refusal);
        self::assertSame(1142, $refusal->errorInfo[1] ?? null);

        $writer->rollBack();

        self::assertSame(1, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * Create the login with `SELECT` and `INSERT` on entries and artifacts.
     *
     * @return void
     */
    private function createLogin(): void
    {
        $root     = DB::connection(self::CONNECTION);
        $tables   = [EntrySettings::table(), EntrySettings::artifactsTable()];
        $database = $root->getDatabaseName();

        if ($root->getDriverName() === 'mysql') {
            $root->statement(sprintf('CREATE USER \'%s\'@\'%%\' IDENTIFIED BY \'%s\'', $this->login, self::PASSWORD));

            foreach ($tables as $table) {
                $root->statement(sprintf('GRANT SELECT, INSERT ON `%s`.`%s` TO \'%s\'@\'%%\'', $database, $table, $this->login));
            }

            return;
        }

        $root->statement(sprintf('CREATE ROLE %s LOGIN PASSWORD \'%s\'', $this->login, self::PASSWORD));
        $root->statement(sprintf('GRANT CONNECT ON DATABASE "%s" TO %s', $database, $this->login));
        $root->statement(sprintf('GRANT USAGE ON SCHEMA public TO %s', $this->login));

        foreach ($tables as $table) {
            $root->statement(sprintf('GRANT SELECT, INSERT ON "%s" TO %s', $table, $this->login));
        }
    }

    /**
     * Drop the login and its privileges, when it exists.
     *
     * @return void
     */
    private function dropLogin(): void
    {
        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() === 'mysql') {
            $root->statement(sprintf('DROP USER IF EXISTS \'%s\'@\'%%\'', $this->login));

            return;
        }

        if ($root->scalar('select count(*) from pg_roles where rolname = ?', [$this->login]) === 0) {
            return;
        }

        $root->statement(sprintf('DROP OWNED BY %s', $this->login));
        $root->statement(sprintf('DROP ROLE %s', $this->login));
    }

    /**
     * The least-privilege writer's connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function writer(): Connection
    {
        return DB::connection(self::WRITER);
    }

    /**
     * A captured record under the id, finalised on the frozen clock.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(string $id): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(id: $id));
    }
}
