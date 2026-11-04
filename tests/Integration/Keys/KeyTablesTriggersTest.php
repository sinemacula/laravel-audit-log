<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use Tests\Concerns\RunsDocumentedSql;
use Tests\TestCase;

/**
 * Integration tests for the triggers the storage note documents for the owners'
 * key tables, run exactly as written on whichever engine the suite runs
 * against: they install; a key use and an owner marker are never updated or
 * deleted, by anyone; a subject key is never deleted, its immutable columns
 * never change, and it moves only from live to superseded, from live or
 * superseded to erased, or is rewrapped, while an erased key is never changed
 * again; on MySQL and PostgreSQL only the maintenance user changes a key, and
 * on SQLite, which has no users, the transitions hold for whoever runs them;
 * and on PostgreSQL none of the three is truncated.
 *
 * On MySQL and PostgreSQL the documented grants, the key block's included, are
 * run for the logins this worker creates, `audit_writer_<token>`,
 * `audit_maintenance_<token>` and `audit_verifier_<token>`, which are dropped
 * when the test ends, as the key triggers are. A test that proves a trigger
 * refuses what the grants would refuse first grants the privilege beyond the
 * documentation. The tests cover documented SQL, not a class of the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class KeyTablesTriggersTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The connection the verifier's login uses. */
    private const string VERIFIER = 'audit_verifier';

    /** @var string The id of the key a test stores. */
    private const string KEY_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The id of the erasure that tombstones a key. */
    private const string ERASURE_ID = '01932b4e-e000-7000-8000-000000000001';

    /** @var string A wrapped key no stored key has. */
    private const string REWRAPPED = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

    /** @var array<string, int|string|null> Each immutable subject key column, in order, with a value no stored key has. */
    private const array IMMUTABLE_KEY_COLUMNS = [
        'id'          => '01932b4e-9000-7000-8000-00000000ffff',
        'owner_type'  => 'another-owner',
        'owner_id'    => '43',
        'tenant_type' => null,
        'tenant_id'   => null,
        'category'    => 'another',
        'unit'        => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'generation'  => 9,
        'created_at'  => '2026-01-01 00:00:00.000000',
        'key_id'      => 'other',
        'hmac'        => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    ];

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /**
     * Run the documented grants, the key block's after the others, for this
     * worker's logins, where the engine has users, then the documented key
     * triggers.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root   = $this->root();
        $driver = $root->getDriverName();

        if ($driver !== 'sqlite') {
            $this->names = self::documentedNames($root);

            foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
                self::createLogin($root, $this->names[$placeholder]);
            }

            self::runDocumentedSql($root, $driver . '-grants', $this->names);
            self::runDocumentedSql($root, 'keys-grants:' . $driver, $this->names);

            foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
                self::connectAs($placeholder, self::CONNECTION, $this->names[$placeholder]);
            }
        }

        self::runDocumentedSql($root, 'keys-triggers:' . $driver, $this->names);
    }

    /**
     * Drop the documented key triggers, close the logins' connections and drop
     * the logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $root   = $this->root();
        $driver = $root->getDriverName();
        $sql    = self::documentedSql('keys-triggers:' . $driver);

        foreach (self::documentedTriggers($sql) as $trigger => $table) {
            $root->unprepared(sprintf($driver === 'pgsql' ? 'DROP TRIGGER IF EXISTS %s ON %s' : 'DROP TRIGGER IF EXISTS %s', $trigger, $table));
        }

        foreach (self::documentedFunctions($sql) as $function) {
            $root->unprepared(sprintf('DROP FUNCTION IF EXISTS %s() CASCADE', $function));
        }

        foreach ($this->names === [] ? [] : [self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            DB::purge($placeholder);

            self::dropLogin($root, $this->names[$placeholder]);
        }

        parent::tearDown();
    }

    /**
     * Every documented key trigger is installed on the three key tables, and no
     * other: an update and a delete trigger on each, and on PostgreSQL a
     * truncate trigger too.
     *
     * @return void
     */
    public function testTheDocumentedKeyTriggersInstall(): void
    {
        $driver     = $this->root()->getDriverName();
        $documented = array_keys(self::documentedTriggers(self::documentedSql('keys-triggers:' . $driver)));

        sort($documented);

        self::assertSame($documented, $this->installedTriggers([KeyTables::subjectKeysTable(), KeyTables::ownerErasuresTable(), KeyTables::keyUsesTable()]));
        self::assertCount($driver === 'pgsql' ? 9 : 6, $documented);
    }

    /**
     * A key use is never updated or deleted, by the tables' owner nor, on MySQL
     * and PostgreSQL, by the writer or the maintenance user granted both beyond
     * the documented grants: the triggers have no exception, and the row is
     * left as it was.
     *
     * @return void
     */
    public function testAKeyUseRowCannotBeUpdatedOrDeleted(): void
    {
        $table = KeyTables::keyUsesTable();
        $row   = ['key_id' => self::KEY_ID, 'entry_id' => '01932b4e-a000-7000-8000-000000000001'];

        $this->root()->table($table)->insert($row);

        foreach ($this->everyone('UPDATE, DELETE', $table) as $connection) {
            self::assertRefusedByATrigger(static fn () => $connection->table($table)->update(['entry_id' => '01932b4e-a000-7000-8000-000000000002']), $table, 'UPDATE');
            self::assertRefusedByATrigger(static fn () => $connection->table($table)->delete(), $table, 'DELETE');
        }

        self::assertEquals([(object) $row], $this->root()->table($table)->get()->all());
    }

    /**
     * An owner marker is never updated or deleted, by the tables' owner nor, on
     * MySQL and PostgreSQL, by the writer or the maintenance user granted both
     * beyond the documented grants, so an owner's history of erasures and
     * reinstatements only grows.
     *
     * @return void
     */
    public function testAnOwnerMarkerCannotBeUpdatedOrDeleted(): void
    {
        $table = KeyTables::ownerErasuresTable();

        $this->root()->table($table)->insert(self::markerRow());

        $before = $this->root()->table($table)->first();

        foreach ($this->everyone('UPDATE, DELETE', $table) as $connection) {
            self::assertRefusedByATrigger(static fn () => $connection->table($table)->update(['transition' => 'reinstated']), $table, 'UPDATE');
            self::assertRefusedByATrigger(static fn () => $connection->table($table)->update(['generation_floor' => 0]), $table, 'UPDATE');
            self::assertRefusedByATrigger(static fn () => $connection->table($table)->delete(), $table, 'DELETE');
        }

        self::assertEquals($before, $this->root()->table($table)->first());
    }

    /**
     * A subject key is never deleted, in any state, by the tables' owner nor,
     * on MySQL and PostgreSQL, by any user granted `DELETE` beyond the
     * documented grants, the maintenance user included: an erasure destroys a
     * key by updating its row.
     *
     * @return void
     */
    public function testASubjectKeyCannotBeDeleted(): void
    {
        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert([
            self::keyRow(1),
            self::keyRow(2, ['state' => 'superseded']),
            self::keyRow(3, ['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]),
        ]);

        foreach ($this->everyone('DELETE', $table) as $connection) {
            for ($number = 1; $number <= 3; $number++) {
                $id = self::keyId($number);

                self::assertRefusedByATrigger(static fn () => $connection->table($table)->where('id', $id)->delete(), $table, 'DELETE');
            }
        }

        self::assertSame(3, $this->root()->table($table)->count());
    }

    /**
     * Rows of `[column, value]`: each immutable subject key column changed to a
     * value no stored key has, the tenant's pair to null.
     *
     * @return iterable<string, array{0: string, 1: int|string|null}>
     */
    public static function provideImmutableKeyColumns(): iterable
    {
        foreach (self::IMMUTABLE_KEY_COLUMNS as $column => $value) {
            yield $column => [$column, $value];
        }
    }

    /**
     * A change to any immutable column of a live key is refused, even by the
     * user who may change a key, granted the column beyond the documented
     * grants on MySQL and PostgreSQL, alone or with an allowed transition, and
     * the key is left as it was.
     *
     * @param  string  $column
     * @param  int|string|null  $value
     * @return void
     */
    #[DataProvider('provideImmutableKeyColumns')]
    public function testASubjectKeysImmutableFieldsCannotChange(string $column, int|string|null $value): void
    {
        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert(self::keyRow(1));
        $this->grantBeyondTheDocumentation('UPDATE', $table, self::MAINTENANCE);

        $before  = $this->key();
        $changer = $this->changer()->table($table)->where('id', self::keyId(1));

        self::assertRefusedByATrigger(static fn () => $changer->clone()->update([$column => $value]), $table, 'UPDATE');
        self::assertRefusedByATrigger(static fn () => $changer->clone()->update([$column => $value, 'state' => 'superseded']), $table, 'UPDATE');
        self::assertEquals($before, $this->key());
    }

    /**
     * Rows of `[state, wrapped key, wrapping key id, erasure]`: what an erased
     * key could be reopened to, a live or a superseded key with a wrapped key,
     * its erasure kept or cleared.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: ?string}>
     */
    public static function provideReopenings(): iterable
    {
        yield from [
            'live, the erasure cleared'       => ['live', self::REWRAPPED, 'k2026', null],
            'live, the erasure kept'          => ['live', self::REWRAPPED, 'k2026', self::ERASURE_ID],
            'superseded, the erasure cleared' => ['superseded', self::REWRAPPED, 'k2026', null],
            'superseded, the erasure kept'    => ['superseded', self::REWRAPPED, 'k2026', self::ERASURE_ID],
        ];
    }

    /**
     * An erased key never holds a key again, whatever it would be reopened to,
     * even by the user who may change a key: its generation stays destroyed,
     * and a reinstated owner gets a new one.
     *
     * @param  string  $state
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  ?string  $erasure
     * @return void
     */
    #[DataProvider('provideReopenings')]
    public function testAnErasedKeyNeverReopens(string $state, string $wrapped, string $wrapKeyId, ?string $erasure): void
    {
        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert(self::keyRow(1, ['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]));

        $before  = $this->key();
        $changes = ['state' => $state, 'wrapped_key' => $wrapped, 'wrap_key_id' => $wrapKeyId, 'erasure_id' => $erasure];
        $changer = $this->changer()->table($table)->where('id', self::keyId(1));

        self::assertRefusedByATrigger(static fn () => $changer->clone()->update($changes), $table, 'UPDATE');
        self::assertEquals($before, $this->key());
    }

    /**
     * An erased key is refused every update, by the user who may change a key
     * too: its erasure moved or cleared, its wrapping key's id changed or
     * cleared, a wrapped key given back while it stays erased, and even an
     * update that writes back what it holds.
     *
     * @return void
     */
    public function testAnErasedRowCannotBeChangedAtAll(): void
    {
        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert(self::keyRow(1, ['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]));

        $before  = $this->key();
        $changer = $this->changer()->table($table)->where('id', self::keyId(1));
        $updates = [
            ['erasure_id' => '01932b4e-e000-7000-8000-000000000002'],
            ['erasure_id' => null],
            ['wrap_key_id' => 'k2027'],
            ['wrap_key_id' => null],
            ['wrapped_key' => self::REWRAPPED],
            ['state' => 'erased'],
        ];

        foreach ($updates as $update) {
            self::assertRefusedByATrigger(static fn () => $changer->clone()->update($update), $table, 'UPDATE');
        }

        self::assertEquals($before, $this->key());
    }

    /**
     * Rows of `[columns the key starts with, changes, whether the trigger
     * allows them]`: the three transitions, from each state they start from,
     * and every near miss of them.
     *
     * @return iterable<string, array{0: array<string, string>, 1: array<string, ?string>, 2: bool}>
     */
    public static function provideTransitions(): iterable
    {
        $superseded = ['state' => 'superseded'];
        $erase      = ['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID];
        $rewrap     = ['wrapped_key' => self::REWRAPPED, 'wrap_key_id' => 'k2027'];

        yield from [
            'live to superseded, the wrapped key kept' => [[], ['state' => 'superseded'], true],
            'live to erased'                           => [[], $erase, true],
            'superseded to erased'                     => [$superseded, $erase, true],
            'a live key rewrapped'                     => [[], $rewrap, true],
            'a superseded key rewrapped'               => [$superseded, $rewrap, true],
            'superseded back to live'                  => [$superseded, ['state' => 'live'], false],
            'erased keeping its wrapped key'           => [[], ['state' => 'erased', 'erasure_id' => self::ERASURE_ID], false],
            'erased without an erasure'                => [[], ['state' => 'erased', 'wrapped_key' => null], false],
            'erased dropping its wrapping key id'      => [[], [...$erase, 'wrap_key_id' => null], false],
            'erased under another wrapping key id'     => [[], [...$erase, 'wrap_key_id' => 'k2027'], false],
            'superseded without a wrapped key'         => [[], ['state' => 'superseded', 'wrapped_key' => null], false],
            'superseded naming an erasure'             => [[], ['state' => 'superseded', 'erasure_id' => self::ERASURE_ID], false],
            'rewrapped without a wrapping key id'      => [[], ['wrapped_key' => self::REWRAPPED, 'wrap_key_id' => null], false],
            'a live key losing its wrapped key'        => [[], ['wrapped_key' => null], false],
            'a superseded key losing its wrapped key'  => [$superseded, ['wrapped_key' => null], false],
            'a live key naming an erasure'             => [[], ['erasure_id' => self::ERASURE_ID], false],
            'an unknown state'                         => [[], ['state' => 'revoked'], false],
        ];
    }

    /**
     * Only the three transitions pass, made by the user who may change a key:
     * live to superseded, live or superseded to erased with no wrapped key, the
     * wrapping key's id kept and an erasure named, and a rewrap that keeps the
     * state; every near miss is refused and leaves the key as it was.
     *
     * @param  array<string, string>  $from
     * @param  array<string, ?string>  $changes
     * @param  bool  $allowed
     * @return void
     */
    #[DataProvider('provideTransitions')]
    public function testOnlyTheAllowedTransitionsPass(array $from, array $changes, bool $allowed): void
    {
        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert(self::keyRow(1, $from));

        $before  = $this->key();
        $changer = $this->changer()->table($table)->where('id', self::keyId(1));

        if (!$allowed) {
            self::assertRefusedByATrigger(static fn () => $changer->clone()->update($changes), $table, 'UPDATE');
            self::assertEquals($before, $this->key());

            return;
        }

        self::assertSame(1, $changer->clone()->update($changes));
        self::assertSame($changes, (array) $this->root()->table($table)->where('id', self::keyId(1))->first(array_keys($changes)));
    }

    /**
     * A rotation may supersede a live key and rewrap it under another wrapping
     * key in the same statement, and the superseded key may then be rewrapped
     * again and erased.
     *
     * @return void
     */
    public function testARotationMayRewrapInTheSameStatement(): void
    {
        $table   = KeyTables::subjectKeysTable();
        $changer = $this->changer()->table($table)->where('id', self::keyId(1));
        $read    = fn (): array => (array) $this->root()->table($table)->where('id', self::keyId(1))->first(['state', 'wrapped_key', 'wrap_key_id', 'erasure_id']);

        $this->root()->table($table)->insert(self::keyRow(1));

        self::assertSame(1, $changer->clone()->update(['state' => 'superseded', 'wrapped_key' => self::REWRAPPED, 'wrap_key_id' => 'k2027']));
        self::assertSame(['state' => 'superseded', 'wrapped_key' => self::REWRAPPED, 'wrap_key_id' => 'k2027', 'erasure_id' => null], $read());

        self::assertSame(1, $changer->clone()->update(['wrapped_key' => str_repeat('C', 80), 'wrap_key_id' => 'k2028']));
        self::assertSame(1, $changer->clone()->update(['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]));
        self::assertSame(['state' => 'erased', 'wrapped_key' => null, 'wrap_key_id' => 'k2028', 'erasure_id' => self::ERASURE_ID], $read());
    }

    /**
     * On MySQL and PostgreSQL only the maintenance user changes a key: the
     * tables' owner, and the writer and the verifier granted `UPDATE` beyond
     * the documented grants, are refused each transition by the trigger, while
     * the maintenance user makes it.
     *
     * @return void
     */
    public function testOnlyTheMaintenanceRoleMayChangeAKey(): void
    {
        $this->skipOnSqlite();

        $table = KeyTables::subjectKeysTable();

        $this->root()->table($table)->insert([self::keyRow(1), self::keyRow(2)]);
        $this->grantBeyondTheDocumentation('UPDATE', $table, self::WRITER);
        $this->grantBeyondTheDocumentation('UPDATE', $table, self::VERIFIER);

        $transitions = [
            ['state' => 'superseded'],
            ['wrapped_key' => self::REWRAPPED, 'wrap_key_id' => 'k2027'],
            ['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID],
        ];

        foreach ([$this->root(), DB::connection(self::WRITER), DB::connection(self::VERIFIER)] as $connection) {
            foreach ($transitions as $transition) {
                self::assertRefusedByATrigger(static fn () => $connection->table($table)->where('id', self::keyId(1))->update($transition), $table, 'UPDATE');
            }
        }

        $maintenance = DB::connection(self::MAINTENANCE)->table($table)->where('id', self::keyId(2));

        foreach ($transitions as $transition) {
            self::assertSame(1, $maintenance->clone()->update($transition));
        }

        self::assertSame(['live', 'erased'], $this->root()->table($table)->orderBy('id')->pluck('state')->all());
    }

    /**
     * On SQLite, which has no users, whoever changes a key makes the allowed
     * transitions, and is refused every other change exactly as the maintenance
     * user is elsewhere.
     *
     * @return void
     */
    public function testOnSqliteTheTransitionsAreHeldWithoutRoles(): void
    {
        if ($this->root()->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite holds the transitions with no role check.');
        }

        $table = KeyTables::subjectKeysTable();
        $key   = $this->root()->table($table)->where('id', self::keyId(1));

        $this->root()->table($table)->insert(self::keyRow(1));

        self::assertSame(1, $key->clone()->update(['state' => 'superseded']));
        self::assertRefusedByATrigger(static fn () => $key->clone()->update(['state' => 'live']), $table, 'UPDATE');
        self::assertSame(1, $key->clone()->update(['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]));
        self::assertRefusedByATrigger(static fn () => $key->clone()->update(['state' => 'live', 'wrapped_key' => self::REWRAPPED, 'erasure_id' => null]), $table, 'UPDATE');
        self::assertSame('erased', $key->clone()->value('state'));
    }

    /**
     * The triggers never refuse an insert: on MySQL and PostgreSQL the writer
     * inserts a key and a key use and the maintenance user a marker, under the
     * documented grants, and on SQLite whoever does inserts all three.
     *
     * @return void
     */
    public function testInsertsAreNeverRefused(): void
    {
        $writer      = $this->names === [] ? $this->root() : DB::connection(self::WRITER);
        $maintenance = $this->names === [] ? $this->root() : DB::connection(self::MAINTENANCE);

        self::assertTrue($writer->table(KeyTables::subjectKeysTable())->insert(self::keyRow(1)));
        self::assertTrue($writer->table(KeyTables::keyUsesTable())->insert(['key_id' => self::KEY_ID, 'entry_id' => '01932b4e-a000-7000-8000-000000000001']));
        self::assertTrue($maintenance->table(KeyTables::ownerErasuresTable())->insert(self::markerRow()));

        foreach ([KeyTables::subjectKeysTable(), KeyTables::keyUsesTable(), KeyTables::ownerErasuresTable()] as $table) {
            self::assertSame(1, $this->root()->table($table)->count(), $table);
        }
    }

    /**
     * Rows of `[table]`: each key table the PostgreSQL truncate triggers are
     * on.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTruncatedTables(): iterable
    {
        yield from [
            'the subject keys'   => [KeyTables::DEFAULT_SUBJECT_KEYS],
            'the owner erasures' => [KeyTables::DEFAULT_OWNER_ERASURES],
            'the key uses'       => [KeyTables::DEFAULT_KEY_USES],
        ];
    }

    /**
     * On PostgreSQL a `TRUNCATE`, which no row trigger sees, is refused by the
     * statement trigger, even for the tables' owner, and every row stays.
     *
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideTruncatedTables')]
    public function testATruncateIsRefusedOnPostgres(string $table): void
    {
        $root = $this->root();

        if ($root->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL has the truncate triggers; MySQL refuses it by the grants.');
        }

        $root->table(KeyTables::subjectKeysTable())->insert(self::keyRow(1));
        $root->table(KeyTables::ownerErasuresTable())->insert(self::markerRow());
        $root->table(KeyTables::keyUsesTable())->insert(['key_id' => self::KEY_ID, 'entry_id' => '01932b4e-a000-7000-8000-000000000001']);

        self::assertRefusedByATrigger(static fn () => $root->statement(sprintf('TRUNCATE %s', $table)), $table, 'TRUNCATE');
        self::assertSame(1, $root->table($table)->count());
    }

    /**
     * The id of the numbered key.
     *
     * @param  int  $number
     * @return string
     */
    private static function keyId(int $number): string
    {
        return sprintf('01932b4e-9000-7000-8000-%012d', $number);
    }

    /**
     * A live key of a tenant's unit with every column a key must have, numbered
     * so its id and unit are its own, with the given columns replaced.
     *
     * @param  int  $number
     * @param  array<string, int|string|null>  $columns
     * @return array<string, int|string|null>
     */
    private static function keyRow(int $number, array $columns = []): array
    {
        return [
            'id'          => self::keyId($number),
            'owner_type'  => 'customer',
            'owner_id'    => '42',
            'tenant_type' => 'organisation',
            'tenant_id'   => 'org_1',
            'category'    => 'billing',
            'unit'        => hash('sha256', 'unit-' . $number),
            'generation'  => 1,
            'state'       => 'live',
            'wrapped_key' => str_repeat('A', 80),
            'wrap_key_id' => 'k2026',
            'created_at'  => '2026-11-01 12:00:00.000000',
            'erasure_id'  => null,
            'key_id'      => 'k2026',
            'hmac'        => str_repeat('c', 64),
            ...$columns,
        ];
    }

    /**
     * An erasure marker of the key's owner, as the erasure's journal row names
     * it.
     *
     * @return array<string, int|string>
     */
    private static function markerRow(): array
    {
        return [
            'id'               => self::ERASURE_ID,
            'owner_type'       => 'customer',
            'owner_id'         => '42',
            'transition'       => 'erased',
            'generation_floor' => 1,
            'journal_sequence' => 7,
            'created_at'       => '2026-11-01 12:00:00.000000',
        ];
    }

    /**
     * The stored key the tests change, as the tables' owner reads it.
     *
     * @return ?object
     */
    private function key(): ?object
    {
        return $this->root()->table(KeyTables::subjectKeysTable())->where('id', self::keyId(1))->first();
    }

    /**
     * The connection that may change a key: the maintenance user's on MySQL and
     * PostgreSQL, and the tables' owner's on SQLite, which has no users.
     *
     * @return \Illuminate\Database\Connection
     */
    private function changer(): Connection
    {
        return $this->names === [] ? $this->root() : DB::connection(self::MAINTENANCE);
    }

    /**
     * Every connection a refusal is proven for: the tables' owner's, and on
     * MySQL and PostgreSQL the writer's and the maintenance user's, each
     * granted the privileges on the table beyond the documented grants, so a
     * refusal there is the trigger's.
     *
     * @param  string  $privileges
     * @param  string  $table
     * @return list<\Illuminate\Database\Connection>
     */
    private function everyone(string $privileges, string $table): array
    {
        if ($this->names === []) {
            return [$this->root()];
        }

        $this->grantBeyondTheDocumentation($privileges, $table, self::WRITER);
        $this->grantBeyondTheDocumentation($privileges, $table, self::MAINTENANCE);

        return [$this->root(), DB::connection(self::WRITER), DB::connection(self::MAINTENANCE)];
    }

    /**
     * Grant the placeholder's login privileges on the table beyond the
     * documented grants, on an engine with users.
     *
     * @param  string  $privileges
     * @param  string  $table
     * @param  string  $placeholder
     * @return void
     */
    private function grantBeyondTheDocumentation(string $privileges, string $table, string $placeholder): void
    {
        if ($this->names === []) {
            return;
        }

        $root = $this->root();

        $root->statement($root->getDriverName() === 'mysql'
            ? sprintf('GRANT %s ON `%s`.`%s` TO \'%s\'@\'%%\'', $privileges, $this->names['app_db'], $table, $this->names[$placeholder])
            : sprintf('GRANT %s ON "%s" TO "%s"', $privileges, $table, $this->names[$placeholder]));
    }

    /**
     * The names of the triggers installed on the given tables, sorted bytewise,
     * whatever order the engine's collation gives.
     *
     * @param  list<string>  $tables
     * @return list<string>
     */
    private function installedTriggers(array $tables): array
    {
        $connection = $this->root();
        $in         = implode(', ', array_fill(0, count($tables), '?'));

        $query = match ($connection->getDriverName()) {
            'mysql' => "select trigger_name as name from information_schema.triggers where trigger_schema = database() and event_object_table in ({$in})",
            'pgsql' => 'select t.tgname as name from pg_trigger t join pg_class c on c.oid = t.tgrelid'
                . " where c.relnamespace = current_schema()::regnamespace and not t.tgisinternal and c.relname in ({$in})",
            default => "select name from sqlite_master where type = 'trigger' and tbl_name in ({$in})",
        };

        /** @var list<object{name: string}> $triggers */
        $triggers = $connection->select($query, $tables);
        $names    = array_map(static fn (object $trigger): string => $trigger->name, $triggers);

        sort($names);

        return $names;
    }

    /**
     * Skip the test on SQLite, which has no users.
     *
     * @return void
     */
    private function skipOnSqlite(): void
    {
        if ($this->root()->getDriverName() !== 'sqlite') {
            return;
        }

        self::markTestSkipped('SQLite has no users or privileges.');
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
