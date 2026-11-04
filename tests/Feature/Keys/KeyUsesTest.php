<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use Tests\TestCase;

/**
 * Feature tests for the key uses on the storage connection, on whichever
 * engine the suite runs against: one row per distinct key of an entry, sorted,
 * and none for a key that is no canonical lower-case UUID; rows inserted many
 * to a statement and never more than the engine's share of placeholders
 * allows; nothing inserted for no rows; and a row already there surfacing as
 * the unique violation it is, never ignored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUses::class)]
final class KeyUsesTest extends TestCase
{
    /** @var string The entry every row names. */
    private const string ENTRY = '01932b4e-1000-7000-8000-000000000001';

    /** @var string A key. */
    private const string FIRST = '01932b4e-9000-7000-8000-000000000001';

    /** @var string Another key, sorting after the first. */
    private const string SECOND = '01932b4e-9000-7000-8000-000000000002';

    /** @var list<array{0: string, 1: int}> Each statement run since the test began listening, with its number of bindings. */
    private array $statements = [];

    /**
     * An entry has one row per distinct key its envelopes name, sorted by key,
     * each naming the entry, and they are stored as they are given.
     *
     * @return void
     */
    public function testOneRowPerDistinctKeyOfTheEntry(): void
    {
        $rows = KeyUses::rowsFor(self::ENTRY, [self::SECOND, self::FIRST, self::SECOND]);

        self::assertSame([
            ['key_id' => self::FIRST, 'entry_id' => self::ENTRY],
            ['key_id' => self::SECOND, 'entry_id' => self::ENTRY],
        ], $rows);

        KeyUses::insert(self::storage(), $rows);

        self::assertSame($rows, self::storedRows());
        self::assertSame([], KeyUses::rowsFor(self::ENTRY, []));
    }

    /**
     * A key that is not a canonical lower-case UUID has no row, whatever
     * encrypter named it: a reference of another form, an upper-case UUID and a
     * UUID in braces; an entry id that is no canonical lower-case UUID is
     * refused.
     *
     * @return void
     */
    public function testANonUuidKeyHasNoRow(): void
    {
        self::assertSame(
            [['key_id' => self::FIRST, 'entry_id' => self::ENTRY]],
            KeyUses::rowsFor(self::ENTRY, ['vault:transit/users/42', strtoupper(self::SECOND), '{' . self::SECOND . '}', '', self::FIRST]),
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A key use\'s entry id must be a lower-case UUID.');

        KeyUses::rowsFor(strtoupper(self::ENTRY), [self::FIRST]);
    }

    /**
     * Rows are inserted as many to a statement as the engine's share of
     * placeholders allows, 400 on SQLite and 10,000 elsewhere, two placeholders
     * each, so one more than a statement holds takes two, and every row is
     * stored.
     *
     * @return void
     */
    public function testRowsAreInsertedUnderThePlaceholderLimit(): void
    {
        self::assertSame(400, KeyUses::SQLITE_ROWS_PER_STATEMENT);
        self::assertSame(10000, KeyUses::ROWS_PER_STATEMENT);
        self::assertLessThan(65535, 2 * KeyUses::ROWS_PER_STATEMENT);
        self::assertLessThan(999, 2 * KeyUses::SQLITE_ROWS_PER_STATEMENT);

        $storage = self::storage();
        $limit   = KeyUses::rowsPerStatement($storage);

        self::assertSame($storage->getDriverName() === 'sqlite' ? 400 : 10000, $limit);

        $rows = array_map(static fn (int $index): array => ['key_id' => self::FIRST, 'entry_id' => sprintf('01932b4e-1000-7000-8000-%012d', $index)], range(1, $limit + 1));

        $this->listen();

        KeyUses::insert($storage, $rows);

        self::assertSame([2 * $limit, 2], array_column($this->statements, 1));
        self::assertSame($limit + 1, $storage->table(KeyTables::keyUsesTable())->count());
    }

    /**
     * No rows insert nothing.
     *
     * @return void
     */
    public function testNoRowsInsertNothing(): void
    {
        $this->listen();

        KeyUses::insert(self::storage(), []);

        self::assertSame([], $this->statements);
    }

    /**
     * A row already stored is never ignored: inserting it again surfaces as a
     * unique violation, and the statement is a plain insert.
     *
     * @return void
     */
    public function testADuplicateRowSurfacesAsAViolation(): void
    {
        $rows = KeyUses::rowsFor(self::ENTRY, [self::FIRST]);

        KeyUses::insert(self::storage(), $rows);

        $this->listen();

        $refused = null;

        try {
            KeyUses::insert(self::storage(), KeyUses::rowsFor(self::ENTRY, [self::SECOND, self::FIRST]));
        } catch (\Throwable $exception) {
            $refused = $exception;
        }

        self::assertInstanceOf(UniqueConstraintViolationException::class, $refused, 'The duplicate was not refused.');
        self::assertStringStartsWith('insert into ', strtolower($refused->getSql()));
        self::assertStringNotContainsStringIgnoringCase('ignore', $refused->getSql());
        self::assertStringNotContainsStringIgnoringCase('on conflict', $refused->getSql());
        self::assertStringNotContainsStringIgnoringCase('on duplicate', $refused->getSql());

        self::assertSame($rows, self::storedRows());
    }

    /**
     * Each engine's share is chosen by the connection's driver: SQLite's for
     * SQLite, and the larger for MySQL and PostgreSQL.
     *
     * @return void
     */
    public function testEachEngineHasItsShare(): void
    {
        foreach (['sqlite' => 400, 'mysql' => 10000, 'pgsql' => 10000] as $driver => $limit) {
            $connection = \Mockery::mock(Connection::class);

            $connection->allows('getDriverName')->andReturn($driver);

            self::assertSame($limit, KeyUses::rowsPerStatement($connection), $driver);
        }
    }

    /**
     * The constructor is private: the class is a utility container only.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(KeyUses::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(KeyUses::class, $instance);
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function storage(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * Every stored row, by key and then entry.
     *
     * @return list<array{key_id: string, entry_id: string}>
     */
    private static function storedRows(): array
    {
        $rows = self::storage()->table(KeyTables::keyUsesTable())->orderBy('key_id')->orderBy('entry_id')->get(['key_id', 'entry_id']);

        return array_values(array_map(static fn (object $row): array => ['key_id' => (string) $row->key_id, 'entry_id' => (string) $row->entry_id], $rows->all()));
    }

    /**
     * Record every statement the storage connection runs from now on, with its
     * number of bindings.
     *
     * @return void
     */
    private function listen(): void
    {
        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->statements[] = [$query->sql, count($query->bindings)];
        });
    }
}
