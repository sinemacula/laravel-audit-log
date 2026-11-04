<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\KeyUseCheck;
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use Tests\TestCase;

/**
 * Feature tests for the check that the key uses of a segment's entries are
 * complete, on whichever engine the suite runs against: an entry one of whose
 * keys has no key use naming it is missing, in the order given, whatever key
 * uses other entries have; an entry or a key that is not a canonical UUID is
 * never asked for; and the entries' key uses are read by entry on the writer,
 * one statement for each 500 entries and none for none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUseCheck::class)]
final class KeyUseCheckTest extends TestCase
{
    /** @var string A key. */
    private const string FIRST_KEY = '01932b4e-9000-7000-8000-000000000001';

    /** @var string Another key. */
    private const string SECOND_KEY = '01932b4e-9000-7000-8000-000000000002';

    /**
     * An entry with a key use for each of its keys is not missing; one short of
     * a key use for any of its keys is, though another entry has a key use of
     * that key, and the entries are named in the order given.
     *
     * @return void
     */
    public function testAnEntryShortOfAKeyUseIsMissing(): void
    {
        $complete = self::entryId();
        $short    = self::entryId();
        $none     = self::entryId();

        $this->insertUses([[$complete, self::FIRST_KEY], [$complete, self::SECOND_KEY], [$short, self::FIRST_KEY]]);

        $missing = $this->check()->missing([
            $none     => [self::FIRST_KEY],
            $complete => [self::FIRST_KEY, self::SECOND_KEY],
            $short    => [self::FIRST_KEY, self::SECOND_KEY],
        ]);

        self::assertSame([$none, $short], $missing);
    }

    /**
     * The entries' key uses are read through the entry index on the writer, one
     * statement for each 500 entries: 501 entries take two, and the last
     * entry's missing key use is found in the second.
     *
     * @return void
     */
    public function testTheEntriesAreChunked(): void
    {
        $expected = [];
        $uses     = [];

        for ($index = 0; $index <= KeyUseCheck::BATCH; $index++) {
            $entryId            = self::entryId();
            $expected[$entryId] = [self::FIRST_KEY];
            $uses[]             = [$entryId, self::FIRST_KEY];
        }

        $last = array_key_last($expected);

        array_pop($uses);

        $this->insertUses($uses);

        $statements = $this->listen();
        $missing    = $this->check()->missing($expected);

        self::assertSame([$last], $missing);
        self::assertCount(2, $statements);
        self::assertStringContainsString(KeyTables::keyUsesTable(), $statements[0]);
        self::assertMatchesRegularExpression('/\bentry_id\W* in \(/', $statements[0]);
    }

    /**
     * No entry asks for nothing: no statement is run.
     *
     * @return void
     */
    public function testNoEntryRunsNoStatement(): void
    {
        $statements = $this->listen();

        self::assertSame([], $this->check()->missing([]));
        self::assertSame([], $statements->getArrayCopy());
    }

    /**
     * An entry whose id is not a canonical lower-case UUID, and a key that is
     * not one, are never asked for, since no key use names either; an entry
     * naming no such key needs none, and nothing is read.
     *
     * @return void
     */
    public function testOnlyCanonicalIdsAreAskedFor(): void
    {
        $statements = $this->listen();

        $missing = $this->check()->missing([
            'legacy-0042'               => [self::FIRST_KEY],
            strtoupper(self::entryId()) => [self::FIRST_KEY],
            self::entryId()             => ['k-1', strtoupper(self::SECOND_KEY)],
        ]);

        self::assertSame([], $missing);
        self::assertSame([], $statements->getArrayCopy());
    }

    /**
     * A key use is read on the writer, so a replica's lag never reads as a
     * missing one.
     *
     * @return void
     */
    public function testTheKeyUsesAreReadOnTheWriter(): void
    {
        $entryId = self::entryId();

        $this->insertUses([[$entryId, self::FIRST_KEY]]);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The key-use check read the replica.');
        });

        self::assertSame([], $this->check()->missing([$entryId => [self::FIRST_KEY]]));
        self::assertSame([$entryId], $this->check()->missing([$entryId => [self::SECOND_KEY]]));
    }

    /**
     * A key-use check from the container's connections.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyUseCheck
     */
    private function check(): KeyUseCheck
    {
        return new KeyUseCheck(app(DatabaseManager::class));
    }

    /**
     * Store the key uses, each an entry and a key.
     *
     * @param  list<array{0: string, 1: string}>  $uses
     * @return void
     */
    private function insertUses(array $uses): void
    {
        $connection = DB::connection(StorageConnection::name());
        $rows       = array_map(static fn (array $use): array => ['key_id' => $use[1], 'entry_id' => $use[0]], $uses);

        KeyUses::insert($connection, $rows);
    }

    /**
     * Record every statement the storage connection runs from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function listen(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }

    /**
     * A fresh entry id.
     *
     * @return string
     */
    private static function entryId(): string
    {
        return Str::uuid7()->toString();
    }
}
