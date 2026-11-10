<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\TestCase;

/**
 * Integration tests for the installation's identity, on whichever engine the
 * suite runs against: the migrations seed the id, and one that was lost is
 * written once, through the storage connection, as a JSON object of a
 * lower-case UUID version 7 at the caller's instant; a first write that loses a
 * race reads the winner's id and replaces nothing; confirming it reads nothing
 * more when both connections are one, writes a missing one, and refuses a
 * maintenance connection that reaches no id, or another one, with a message
 * naming no value; checking it does the same but writes nothing, refusing a
 * missing id; and a malformed value reads as absent and is never replaced.
 *
 * A maintenance connection that reaches the same database is a second
 * connection to the worker's database, sharing the in-memory database's own
 * connection on SQLite, where each connection would otherwise open a database
 * of its own. One that reaches another database has a table prefix of its own,
 * so it reads another state table, as a second database would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InstallationIdentity::class)]
final class InstallationIdentityTest extends TestCase
{
    /** @var string A second connection to the worker's database. */
    private const string SAME = 'audit_same';

    /** @var string A connection that reaches another installation's state table. */
    private const string OTHER = 'audit_other';

    /** @var string The id another installation holds. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000abcd';

    /** @var string When the id is written. */
    private const string AT = '2026-11-01 12:34:56.789012';

    /** @var string The refusal of a storage connection that reads no installation id. */
    private const string ABSENT = 'The storage connection reaches no installation id; the package\'s migrations seed it, and `audit-log:seal` writes'
        . ' it when it is missing.';

    /** @var string The refusal of a storage connection that reads a malformed installation id. */
    private const string MALFORMED = 'The installation id the storage connection reads is malformed; it is never replaced, so it must be restored.';

    /** @var string A lower-case UUID version 7. */
    private const string UUID_V7 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /**
     * Drop the other installation's state table and forget both connections.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (app(ConfigRepository::class)->has('database.connections.' . self::OTHER)) {
            DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable());
        }

        DB::purge(self::SAME);
        DB::purge(self::OTHER);

        parent::tearDown();
    }

    /**
     * The first `ensure()` on an installation that lost its seeded id writes
     * the id, a lower-case UUID version 7 in a JSON object `{id}`, at the
     * instant given in UTC to the microsecond; a second returns the same id and
     * writes nothing.
     *
     * @return void
     */
    public function testEnsureWritesTheIdOnce(): void
    {
        $this->forgetTheSeededId();

        $identity = $this->identity();
        $at       = new \DateTimeImmutable('2026-11-01 13:34:56.789012', new \DateTimeZone('Europe/Paris'));
        $id       = $identity->ensure($at);

        self::assertMatchesRegularExpression(self::UUID_V7, $id);
        self::assertSame($id, $identity->ensure(new \DateTimeImmutable('2027-01-01 00:00:00')));

        $rows = $this->state()->where('name', InstallationIdentity::NAME)->get(['value', 'updated_at'])->all();

        self::assertCount(1, $rows);
        self::assertSame(['id' => $id], json_decode((string) $rows[0]->value, true));
        self::assertSame(self::AT, $rows[0]->updated_at);
        self::assertSame($id, $identity->idThrough(self::CONNECTION));
    }

    /**
     * The id's time is the caller's instant, so the id sorts by when the
     * installation was first seen.
     *
     * @return void
     */
    public function testTheIdIsDrawnAtTheCallersInstant(): void
    {
        $this->forgetTheSeededId();

        $at = new \DateTimeImmutable(self::AT, new \DateTimeZone('UTC'));
        $id = $this->identity()->ensure($at);

        $milliseconds = hexdec(substr(str_replace('-', '', $id), 0, 12));

        self::assertSame((int) $at->format('Uv'), $milliseconds);
    }

    /**
     * Two connections to one database read one id, and a first write that loses
     * a race, to a write another process makes between its read and its insert,
     * reads the winner's id instead, which is never replaced.
     *
     * @return void
     */
    public function testTheFirstWriteWinsAndIsNeverReplaced(): void
    {
        $this->forgetTheSeededId();
        $this->sameDatabase();

        $winner = '01932b4e-9000-7000-8000-00000000beef';
        $racing = true;

        DB::listen(static function (QueryExecuted $query) use (&$racing, $winner): void {
            if (!$racing || $query->connectionName !== self::CONNECTION || !str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $racing = false;

            DB::connection(self::SAME)->table(IntegrityTables::stateTable())->insert([
                'name'       => InstallationIdentity::NAME,
                'value'      => json_encode(['id' => $winner]),
                'updated_at' => '2026-11-01 00:00:00.123456',
            ]);
        });

        self::assertSame($winner, $this->identity()->ensure(self::at()));
        self::assertFalse($racing);
        self::assertSame($winner, $this->identityOn(self::SAME)->ensure(self::at()));
        self::assertSame(1, $this->state()->where('name', InstallationIdentity::NAME)->count());
        self::assertSame('2026-11-01 00:00:00.123456', $this->state()->where('name', InstallationIdentity::NAME)->value('updated_at'));
    }

    /**
     * With no maintenance connection of its own, or one that names the storage
     * connection, confirming reads the id once, through the storage connection,
     * and makes no second read.
     *
     * @return void
     */
    public function testConfirmPassesThroughOneConnection(): void
    {
        $identity = $this->identity();

        $identity->ensure(self::at());

        foreach ([null, self::CONNECTION] as $maintenance) {

            app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', $maintenance);

            $statements = $this->statementsDuring(static fn () => $identity->confirm(new \DateTimeImmutable('2026-11-02 00:00:00')));

            self::assertSame([self::CONNECTION], $statements, var_export($maintenance, true));
        }
    }

    /**
     * On an installation that lost its seeded id, confirming writes the id
     * through the storage connection, then reads the same one through a
     * maintenance connection to the same database.
     *
     * @return void
     */
    public function testConfirmWritesAMissingId(): void
    {
        $this->forgetTheSeededId();
        $this->sameDatabase();

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::SAME);

        self::assertSame(0, $this->state()->count());

        $statements = $this->statementsDuring(fn () => $this->identity()->confirm(self::at()));

        self::assertSame(1, $this->state()->where('name', InstallationIdentity::NAME)->count());
        self::assertSame([self::CONNECTION, self::CONNECTION, self::CONNECTION, self::SAME], $statements);
        self::assertNotNull($this->identity()->idThrough(self::SAME));
    }

    /**
     * A maintenance connection that reaches a database with no id is refused,
     * though the storage connection holds one.
     *
     * @return void
     */
    public function testConfirmRefusesAMaintenanceConnectionReachingNoId(): void
    {
        $this->otherDatabase(null);

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        $this->expectException(InstallationMismatchException::class);
        $this->expectExceptionMessage('The maintenance connection reaches no installation id; it must reach the storage connection\'s database.');

        $this->identity()->confirm(self::at());
    }

    /**
     * A maintenance connection that reaches another installation, holding an id
     * of its own, is refused, and neither id is changed.
     *
     * @return void
     */
    public function testConfirmRefusesConnectionsReachingDifferentDatabases(): void
    {
        $this->otherDatabase(json_encode(['id' => self::OTHER_ID], JSON_THROW_ON_ERROR));

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        $identity = $this->identity();

        try {
            $identity->confirm(self::at());
            self::fail('Expected the connections to be refused.');
        } catch (InstallationMismatchException $exception) {
            self::assertSame('The storage and maintenance connections reach different installations.', $exception->getMessage());
        }

        self::assertSame(self::OTHER_ID, $identity->idThrough(self::OTHER));
        self::assertNotSame(self::OTHER_ID, $identity->idThrough(self::CONNECTION));
    }

    /**
     * Neither refusal names an id or a connection: an operator reads it beside
     * logs another may see.
     *
     * @return void
     */
    public function testTheRefusalNamesNoValue(): void
    {
        foreach ([null, json_encode(['id' => self::OTHER_ID], JSON_THROW_ON_ERROR)] as $value) {

            $this->otherDatabase($value);

            app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

            try {
                $this->identity()->confirm(self::at());
                self::fail('Expected the connections to be refused.');
            } catch (InstallationMismatchException $exception) {
                $id = (string) $this->identity()->idThrough(self::CONNECTION);

                foreach ([self::OTHER_ID, $id, self::OTHER, self::CONNECTION] as $named) {
                    self::assertStringNotContainsString($named, $exception->getMessage());
                }
            }
        }
    }

    /**
     * The migrations seed the id, so `ensure()` returns the seeded one and
     * writes nothing.
     *
     * @return void
     */
    public function testEnsureReturnsTheSeededId(): void
    {
        $seeded = $this->state()->get()->all();
        $id     = $this->identity()->idThrough(self::CONNECTION);

        self::assertNotNull($id);
        self::assertSame($id, $this->identity()->ensure(self::at()));
        self::assertEquals($seeded, $this->state()->get()->all());
    }

    /**
     * Checking reads the seeded id once, through the storage connection, and
     * then the same through a maintenance connection to the same database,
     * writing nothing.
     *
     * @return void
     */
    public function testCheckReadsTheIdAndWritesNothing(): void
    {
        $this->sameDatabase();

        $seeded   = $this->state()->get()->all();
        $identity = $this->identity();

        self::assertSame([self::CONNECTION], $this->statementsDuring(static fn () => $identity->check()));

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::SAME);

        self::assertSame([self::CONNECTION, self::SAME], $this->statementsDuring(static fn () => $identity->check()));
        self::assertEquals($seeded, $this->state()->get()->all());
    }

    /**
     * Checking an installation that lost its id refuses it, naming no value,
     * and writes nothing: the one statement is a read.
     *
     * @return void
     */
    public function testCheckRefusesAMissingIdAndWritesNothing(): void
    {
        $this->forgetTheSeededId();

        $sql = [];

        DB::listen(static function (QueryExecuted $query) use (&$sql): void {
            $sql[] = strtolower($query->sql);
        });

        try {
            $this->identity()->check();
            self::fail('Expected the missing id to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(self::ABSENT, $exception->getMessage());
        }

        self::assertCount(1, $sql);
        self::assertStringStartsWith('select', $sql[0]);
        self::assertSame(0, $this->state()->count());
    }

    /**
     * Checking refuses a maintenance connection that reaches no id, or another
     * installation's, as confirming does, and changes neither id.
     *
     * @return void
     */
    public function testCheckRefusesAMaintenanceConnectionReachingNoIdOrAnother(): void
    {
        $refusals = [
            'The maintenance connection reaches no installation id; it must reach the storage connection\'s database.',
            'The storage and maintenance connections reach different installations.',
        ];

        foreach ([null, json_encode(['id' => self::OTHER_ID], JSON_THROW_ON_ERROR)] as $index => $value) {

            $this->otherDatabase($value);

            app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

            $seeded = $this->state()->get()->all();

            try {
                $this->identity()->check();
                self::fail('Expected the connections to be refused.');
            } catch (InstallationMismatchException $exception) {
                self::assertSame($refusals[$index], $exception->getMessage());
            }

            self::assertEquals($seeded, $this->state()->get()->all());
            self::assertSame($value === null ? 0 : 1, DB::connection(self::OTHER)->table(IntegrityTables::stateTable())->count());
        }
    }

    /**
     * The row a new id is written as names the id's row, holds a JSON object
     * `{id}` of a lower-case UUID version 7 drawn at the instant given, and is
     * stamped with that instant in UTC to the microsecond.
     *
     * @return void
     */
    public function testTheRowIsANewIdAtTheInstant(): void
    {
        $row = InstallationIdentity::row(new \DateTimeImmutable('2026-11-01 13:34:56.789012', new \DateTimeZone('Europe/Paris')));
        $id  = json_decode($row['value'], true);

        self::assertSame(['name', 'value', 'updated_at'], array_keys($row));
        self::assertSame(InstallationIdentity::NAME, $row['name']);
        self::assertSame(self::AT, $row['updated_at']);
        self::assertIsArray($id);
        self::assertSame(['id'], array_keys($id));
        self::assertIsString($id['id']);
        self::assertMatchesRegularExpression(self::UUID_V7, $id['id']);
        self::assertSame((int) self::at()->format('Uv'), hexdec(substr(str_replace('-', '', $id['id']), 0, 12)));
        self::assertNotSame($row['value'], InstallationIdentity::row(self::at())['value']);
    }

    /**
     * Rows of `[value]`: stored values that hold no installation id.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield from [
            'not JSON'            => ['not json'],
            'a list'              => ['["01932b4e-9000-7000-8000-00000000abcd"]'],
            'an empty object'     => ['{}'],
            'a number for the id' => ['{"id":5}'],
            'not a UUID'          => ['{"id":"installation-1"}'],
            'an upper-case UUID'  => ['{"id":"01932B4E-9000-7000-8000-00000000ABCD"}'],
            'a padded UUID'       => ['{"id":"01932b4e-9000-7000-8000-00000000abcd "}'],
            'another field'       => ['{"id":"01932b4e-9000-7000-8000-00000000abcd","at":"2026-11-01"}'],
        ];
    }

    /**
     * A stored value that holds no installation id reads as absent through any
     * connection; `ensure()` and `check()` refuse it rather than replacing it,
     * and the value is left as it was.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testAMalformedValueReadsAsAbsent(string $value): void
    {
        $this->state()->where('name', InstallationIdentity::NAME)->update(['value' => $value]);

        $identity = $this->identity();

        self::assertNull($identity->idThrough(self::CONNECTION));

        try {
            $identity->ensure(self::at());
            self::fail('Expected the malformed id to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(self::MALFORMED, $exception->getMessage());
        }

        try {
            $identity->check();
            self::fail('Expected the malformed id to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(self::MALFORMED, $exception->getMessage());
        }

        self::assertSame($value, $this->state()->where('name', InstallationIdentity::NAME)->value('value'));
    }

    /**
     * A malformed value the maintenance connection reads is absent, so the
     * maintenance connection is refused as reaching no id.
     *
     * @return void
     */
    public function testAMalformedValueThroughTheMaintenanceConnectionIsAbsent(): void
    {
        $this->otherDatabase('{"id":"installation-1"}');

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        $this->expectException(InstallationMismatchException::class);
        $this->expectExceptionMessage('The maintenance connection reaches no installation id');

        $this->identity()->confirm(self::at());
    }

    /**
     * The id is read through the writer, never a replica, so one written a
     * moment ago is never read as absent and written again.
     *
     * @return void
     */
    public function testItReadsThroughTheWriter(): void
    {
        $identity = $this->identity();
        $id       = $identity->ensure(self::at());

        DB::connection(self::CONNECTION)->setReadPdo(static function (): never {
            throw new \LogicException('The id must not be read from a replica.');
        });

        try {
            self::assertSame($id, $identity->ensure(self::at()));
            self::assertSame($id, $identity->idThrough(self::CONNECTION));
        } finally {
            DB::connection(self::CONNECTION)->setReadPdo(null);
        }
    }

    /**
     * The identity, on the application's connections.
     *
     * @return \SineMacula\Laravel\AuditLog\Database\InstallationIdentity
     */
    private function identity(): InstallationIdentity
    {
        return new InstallationIdentity($this->database());
    }

    /**
     * The identity, with the storage connection the one named.
     *
     * @param  string  $connection
     * @return \SineMacula\Laravel\AuditLog\Database\InstallationIdentity
     */
    private function identityOn(string $connection): InstallationIdentity
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', $connection);

        return $this->identity();
    }

    /**
     * The application's database manager.
     *
     * @return \Illuminate\Database\DatabaseManager
     */
    private function database(): DatabaseManager
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        return $database;
    }

    /**
     * When the id is written.
     *
     * @return \DateTimeImmutable
     */
    private function at(): \DateTimeImmutable
    {
        return new \DateTimeImmutable(self::AT, new \DateTimeZone('UTC'));
    }

    /**
     * Delete the id the migrations seed, as an installation that lost it.
     *
     * @return void
     */
    private function forgetTheSeededId(): void
    {
        $this->state()->where('name', InstallationIdentity::NAME)->delete();
    }

    /**
     * A query of the worker's state table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function state(): Builder
    {
        return DB::connection(self::CONNECTION)->table(IntegrityTables::stateTable());
    }

    /**
     * Configure `SAME`, a second connection to the worker's database: on SQLite
     * it shares the in-memory database's connection.
     *
     * @return void
     */
    private function sameDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::SAME, $config->array('database.connections.' . self::CONNECTION));

        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            return;
        }

        $same = DB::connection(self::SAME);

        $same->setPdo($root->getPdo());
        $same->setReadPdo($root->getPdo());
    }

    /**
     * Configure `OTHER`, a connection to another installation's state table,
     * holding the value given under the installation id's name, or none.
     *
     * @param  ?string  $value
     * @return void
     */
    private function otherDatabase(?string $value): void
    {
        $config = app(ConfigRepository::class);

        DB::purge(self::OTHER);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        $schema = DB::connection(self::OTHER)->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        if ($value === null) {
            return;
        }

        DB::connection(self::OTHER)->table(IntegrityTables::stateTable())->insert([
            'name'       => InstallationIdentity::NAME,
            'value'      => $value,
            'updated_at' => '2026-10-01 00:00:00.000000',
        ]);
    }

    /**
     * The connection of each statement the work runs, in order, on any
     * connection.
     *
     * @param  \Closure(): void  $work
     * @return list<string>
     */
    private function statementsDuring(\Closure $work): array
    {
        $connections = [];

        DB::listen(static function (QueryExecuted $query) use (&$connections): void {
            $connections[] = $query->connectionName;
        });

        $work();

        return $connections;
    }
}
