<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the store on a read/write split storage connection
 * whose replica lags behind the primary: the insert reaches the writer, and so
 * does the lookup that resolves a duplicate, which a replica would answer
 * without the row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class WriterConnectionTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithReadWriteSplit;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * Make the read/write split the storage connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->useReadWriteSplit();
    }

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * The record is inserted on the primary, and the replica never sees it.
     *
     * @return void
     */
    public function testTheInsertReachesTheWriter(): void
    {
        $this->store()->store($this->finaliser()->finalise(RecordFactory::captured(id: self::ID)));

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->where('id', self::ID)->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * A row seeded on the primary alone is found by the duplicate's lookup, so
     * storing the same record again succeeds; a replica read would find no row
     * and propagate the insert's own exception instead.
     *
     * @return void
     */
    public function testTheDuplicateLookupReadsTheWriter(): void
    {
        $finalised = $this->finaliser()->finalise(RecordFactory::captured(id: self::ID));

        DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->insert((new RowCodec)->encode($finalised));

        $this->store()->store($finalised);

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(EntrySettings::table())->count());
        self::assertNull(DB::connection(self::SPLIT_CONNECTION)->table(EntrySettings::table())->where('id', self::ID)->first());
    }
}
