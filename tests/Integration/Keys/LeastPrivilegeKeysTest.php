<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use Tests\Concerns\RunsDocumentedSql;
use Tests\TestCase;

/**
 * Integration tests for the owners' key tables under the grants the storage
 * note documents, run exactly as written by the tables' owner, the key block
 * after the others, on MySQL and PostgreSQL: the writer inserts and reads keys
 * and key uses, reads the owner markers, and updates, deletes or marks nothing;
 * the maintenance user tombstones, supersedes and rewraps a key through its
 * four mutable columns alone, inserts markers, reads the key uses, and deletes
 * nothing; the verifier reads all three and writes none; and each takes the
 * advisory lock key creation and erasure exclude each other with, which needs
 * no grant.
 *
 * Each worker creates logins of its own, `audit_writer_<token>`,
 * `audit_maintenance_<token>` and `audit_verifier_<token>`, which the
 * documented grants name and which are dropped when the test ends. A refusal is
 * the engine's privilege error, never a trigger's, since no trigger is
 * installed. SQLite has no privileges, so these tests are skipped there. The
 * tests cover documented SQL, not a class of the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LeastPrivilegeKeysTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The connection the verifier's login uses. */
    private const string VERIFIER = 'audit_verifier';

    /** @var string The id of the erasure that tombstones a key. */
    private const string ERASURE_ID = '01932b4e-e000-7000-8000-000000000001';

    /** @var string The id of the entry a key use names. */
    private const string ENTRY_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The key the owner lock of a test's owner is taken under, on MySQL. */
    private const string LOCK_NAME = 'audit_log_owner_0123456789abcdef0123456789abcdef';

    /** @var int The key the owner lock of a test's owner is taken under, on PostgreSQL. */
    private const int LOCK_KEY = 1234567890123;

    /** @var string How many advisory locks the session holds, on PostgreSQL. */
    private const string HELD_LOCKS = 'select count(*) from pg_locks where locktype = \'advisory\' and pid = pg_backend_pid()';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /**
     * Create this worker's logins and run the documented grants for them as the
     * tables' owner, the key block after the others, on MySQL and PostgreSQL
     * only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root   = $this->root();
        $driver = $root->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

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

    /**
     * Close the logins' connections, rolling back what any left open, and drop
     * the logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->names === [] ? [] : [self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            $connection = DB::connection($placeholder);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            DB::purge($placeholder);

            self::dropLogin($this->root(), $this->names[$placeholder]);
        }

        parent::tearDown();
    }

    /**
     * The writer inserts a key and a key use and reads both back, as key
     * creation and the store do, and is refused by the grants any update of a
     * key, of each of its columns included, any update of a key use, and the
     * delete of either.
     *
     * @return void
     */
    public function testTheWriterInsertsAndReadsKeysAndKeyUsesAndUpdatesNothing(): void
    {
        $driver  = $this->root()->getDriverName();
        $keys    = DB::connection(self::WRITER)->table(KeyTables::subjectKeysTable());
        $keyUses = DB::connection(self::WRITER)->table(KeyTables::keyUsesTable());

        self::assertTrue($keys->clone()->insert(self::keyRow(1)));
        self::assertTrue($keyUses->clone()->insert(['key_id' => self::keyId(1), 'entry_id' => self::ENTRY_ID]));
        self::assertSame('live', $keys->clone()->where('id', self::keyId(1))->value('state'));
        self::assertSame(1, $keyUses->clone()->where('key_id', self::keyId(1))->count());

        foreach (['state' => 'superseded', 'wrapped_key' => null, 'wrap_key_id' => null, 'erasure_id' => self::ERASURE_ID, 'hmac' => str_repeat('e', 64)] as $column => $value) {
            $update = static fn () => $keys->clone()->where('id', self::keyId(1))->update([$column => $value]);

            self::assertRefusedByTheGrants($update, $driver, "The writer's update of a key's {$column}");
        }

        self::assertRefusedByTheGrants(static fn () => $keys->clone()->delete(), $driver, 'The writer\'s delete of a key');
        self::assertRefusedByTheGrants(static fn () => $keyUses->clone()->update(['entry_id' => self::keyId(9)]), $driver, 'The writer\'s update of a key use');
        self::assertRefusedByTheGrants(static fn () => $keyUses->clone()->delete(), $driver, 'The writer\'s delete of a key use');
        self::assertSame(['live', str_repeat('A', 80)], array_values((array) $this->root()->table(KeyTables::subjectKeysTable())->first(['state', 'wrapped_key'])));
    }

    /**
     * The writer reads the owner's markers, as key creation does before it
     * creates a key, and is refused by the grants the insert, the update and
     * the delete of one.
     *
     * @return void
     */
    public function testTheWriterReadsMarkersAndWritesNone(): void
    {
        $driver  = $this->root()->getDriverName();
        $markers = DB::connection(self::WRITER)->table(KeyTables::ownerErasuresTable());

        $this->root()->table(KeyTables::ownerErasuresTable())->insert(self::markerRow(1));

        self::assertSame('erased', $markers->clone()->where('owner_type', 'customer')->where('owner_id', '42')->orderByDesc('journal_sequence')->value('transition'));
        self::assertRefusedByTheGrants(static fn () => $markers->clone()->insert(self::markerRow(2)), $driver, 'The writer\'s insert of a marker');
        self::assertRefusedByTheGrants(static fn () => $markers->clone()->update(['transition' => 'reinstated']), $driver, 'The writer\'s update of a marker');
        self::assertRefusedByTheGrants(static fn () => $markers->clone()->delete(), $driver, 'The writer\'s delete of a marker');
        self::assertSame(1, $this->root()->table(KeyTables::ownerErasuresTable())->count());
    }

    /**
     * The maintenance user supersedes a key and rewraps it in one statement,
     * rewraps it again and tombstones it, through the four mutable columns
     * alone, and reads the key uses an erasure finds the entries through; it is
     * refused by the grants an update of any other column, the insert of a key
     * or a key use, and the delete of a key, a key use or a marker.
     *
     * @return void
     */
    public function testTheMaintenanceUserTombstonesAndRewrapsAndDeletesNothing(): void
    {
        $driver      = $this->root()->getDriverName();
        $maintenance = DB::connection(self::MAINTENANCE);
        $key         = $maintenance->table(KeyTables::subjectKeysTable())->where('id', self::keyId(1));

        $this->root()->table(KeyTables::subjectKeysTable())->insert(self::keyRow(1));
        $this->root()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::keyId(1), 'entry_id' => self::ENTRY_ID]);
        $this->root()->table(KeyTables::ownerErasuresTable())->insert(self::markerRow(1));

        self::assertSame([self::ENTRY_ID], $maintenance->table(KeyTables::keyUsesTable())->where('key_id', self::keyId(1))->pluck('entry_id')->all());
        self::assertSame(1, $key->clone()->update(['state' => 'superseded', 'wrapped_key' => str_repeat('B', 80), 'wrap_key_id' => 'k2027']));
        self::assertSame(1, $key->clone()->update(['wrapped_key' => str_repeat('C', 80), 'wrap_key_id' => 'k2028']));
        self::assertSame(1, $key->clone()->update(['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID]));

        $immutable = [
            'id'         => self::keyId(9),
            'owner_id'   => '43',
            'unit'       => str_repeat('e', 64),
            'generation' => 9,
            'created_at' => '2026-01-01 00:00:00.000000',
            'key_id'     => 'other',
            'hmac'       => str_repeat('e', 64),
        ];

        foreach ($immutable as $column => $value) {
            self::assertRefusedByTheGrants(static fn () => $key->clone()->update([$column => $value]), $driver, "The maintenance user's update of a key's {$column}");
        }

        $refusals = [
            'insert a key'     => static fn () => $maintenance->table(KeyTables::subjectKeysTable())->insert(self::keyRow(2)),
            'delete a key'     => static fn () => $key->clone()->delete(),
            'insert a key use' => static fn () => $maintenance->table(KeyTables::keyUsesTable())->insert(['key_id' => self::keyId(2), 'entry_id' => self::ENTRY_ID]),
            'update a key use' => static fn () => $maintenance->table(KeyTables::keyUsesTable())->update(['entry_id' => self::keyId(9)]),
            'delete a key use' => static fn () => $maintenance->table(KeyTables::keyUsesTable())->delete(),
            'update a marker'  => static fn () => $maintenance->table(KeyTables::ownerErasuresTable())->update(['generation_floor' => 0]),
            'delete a marker'  => static fn () => $maintenance->table(KeyTables::ownerErasuresTable())->delete(),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The maintenance user's attempt to {$what}");
        }

        $stored = $this->root()->table(KeyTables::subjectKeysTable())->first(['state', 'wrapped_key', 'wrap_key_id', 'erasure_id']);

        self::assertSame(['erased', null, 'k2028', self::ERASURE_ID], array_values((array) $stored));
        self::assertSame(1, $this->root()->table(KeyTables::keyUsesTable())->count());
        self::assertSame(1, $this->root()->table(KeyTables::ownerErasuresTable())->count());
    }

    /**
     * The maintenance user inserts an owner's markers, an erasure and then its
     * reinstatement, inside a transaction as an erasure writes one with its
     * journal row, and reads the latest back.
     *
     * @return void
     */
    public function testTheMaintenanceUserInsertsMarkers(): void
    {
        $maintenance = DB::connection(self::MAINTENANCE);

        $maintenance->transaction(static function (Connection $connection): void {
            $connection->table(KeyTables::ownerErasuresTable())->insert(self::markerRow(1));
        });

        self::assertTrue($maintenance->table(KeyTables::ownerErasuresTable())->insert([...self::markerRow(2), 'transition' => 'reinstated']));
        self::assertSame('reinstated', $maintenance->table(KeyTables::ownerErasuresTable())->orderByDesc('journal_sequence')->value('transition'));
        self::assertSame(2, $this->root()->table(KeyTables::ownerErasuresTable())->count());
    }

    /**
     * The verifier reads the keys, the markers and the key uses, as the key
     * store's verification does, and is refused by the grants every write of
     * each.
     *
     * @return void
     */
    public function testTheVerifierOnlyReads(): void
    {
        $driver   = $this->root()->getDriverName();
        $verifier = DB::connection(self::VERIFIER);

        $this->root()->table(KeyTables::subjectKeysTable())->insert(self::keyRow(1));
        $this->root()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::keyId(1), 'entry_id' => self::ENTRY_ID]);
        $this->root()->table(KeyTables::ownerErasuresTable())->insert(self::markerRow(1));

        $writes = [
            KeyTables::subjectKeysTable()   => [self::keyRow(2), ['state' => 'superseded']],
            KeyTables::ownerErasuresTable() => [self::markerRow(2), ['transition' => 'reinstated']],
            KeyTables::keyUsesTable()       => [['key_id' => self::keyId(2), 'entry_id' => self::ENTRY_ID], ['entry_id' => self::keyId(9)]],
        ];

        foreach ($writes as $table => [$row, $update]) {
            self::assertSame(1, $verifier->table($table)->count(), $table);
            self::assertRefusedByTheGrants(static fn () => $verifier->table($table)->insert($row), $driver, "The verifier's insert into {$table}");
            self::assertRefusedByTheGrants(static fn () => $verifier->table($table)->update($update), $driver, "The verifier's update of {$table}");
            self::assertRefusedByTheGrants(static fn () => $verifier->table($table)->delete(), $driver, "The verifier's delete from {$table}");
        }
    }

    /**
     * Each user takes and releases the owner lock with no grant beyond the
     * documented ones: on PostgreSQL a transaction-scoped advisory lock under a
     * bounded wait, released when the transaction ends, and on MySQL a named
     * lock, released by name.
     *
     * @return void
     */
    public function testTheAdvisoryLocksNeedNoGrant(): void
    {
        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            $connection = DB::connection($placeholder);

            if ($connection->getDriverName() === 'mysql') {
                self::assertEquals(1, $connection->scalar('select get_lock(?, 10)', [self::LOCK_NAME]), $placeholder);
                self::assertEquals(1, $connection->scalar('select release_lock(?)', [self::LOCK_NAME]), $placeholder);

                continue;
            }

            $connection->transaction(static function (Connection $connection) use ($placeholder): void {
                $connection->statement('set local lock_timeout = \'10s\'');
                $connection->select('select pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

                self::assertEquals(1, $connection->scalar(self::HELD_LOCKS), $placeholder);
            });

            self::assertEquals(0, $connection->scalar(self::HELD_LOCKS), $placeholder);
        }
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
     * so its id and unit are its own.
     *
     * @param  int  $number
     * @return array<string, int|string|null>
     */
    private static function keyRow(int $number): array
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
        ];
    }

    /**
     * An erasure marker of the test's owner, numbered so its id and journal
     * sequence are its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function markerRow(int $number): array
    {
        return [
            'id'               => sprintf('01932b4e-e000-7000-8000-%012d', $number),
            'owner_type'       => 'customer',
            'owner_id'         => '42',
            'transition'       => 'erased',
            'generation_floor' => 1,
            'journal_sequence' => $number,
            'created_at'       => '2026-11-01 12:00:00.000000',
        ];
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
