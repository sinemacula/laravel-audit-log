<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Casts\UtcInstant;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\TestCase;

/**
 * Integration tests for reading entries through the read model on the engine
 * the suite runs against: every column of a stored row as the model reads it,
 * the times as UTC instants with their microseconds whatever the application's
 * time zone, and a table and connection of the application's choosing.
 *
 * Rows are seeded with literal `DB::table()->insert()` statements, never
 * through the row codec or the store, so the test reads what an engine returns
 * for what was written, not what the package wrote.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditEntry::class)]
#[CoversClass(UtcInstant::class)]
final class AuditEntryReadTest extends TestCase
{
    /** @var string The default entries table. */
    private const string TABLE = 'audit_log_entries';

    /** @var string A storage connection of the application's own. */
    private const string STORAGE = 'audit_store';

    /** @var string A table of the application's own. */
    private const string CUSTOM_TABLE = 'tenant_audit_entries';

    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string The id of the seeded entry. */
    private const string ID = '0192f5a0-7c1e-7000-8000-00000000000a';

    /** @var array<string, int|string|null> The seeded entry's columns, as literal stored values; JSON keys in the order MySQL keeps them (shorter first). */
    private const array ROW = [
        'id'                => self::ID,
        'record_version'    => 1,
        'event'             => 'invoice.approved',
        'event_version'     => 3,
        'category'          => 'billing',
        'outcome'           => 'denied',
        'reason'            => 'policy.limit',
        'actor_type'        => 'user',
        'actor_id'          => '42',
        'subject_type'      => 'invoice',
        'subject_id'        => 'inv-1001',
        'principal_type'    => 'service',
        'principal_id'      => 'svc-9',
        'tenant_type'       => 'team',
        'tenant_id'         => '7',
        'credential_id'     => 'cred-3',
        'guard'             => 'api',
        'session_id'        => 'app-session-5',
        'request_id'        => 'req-1',
        'trace_id'          => '4bf92f3577b34da6a3ce929d0e0e4736',
        'correlation_id'    => 'app:ticket-123',
        'origin'            => 'queue',
        'provenance'        => 'imported',
        'source_id'         => 'billing-app',
        'source_region'     => 'eu-west-1',
        'source_record_id'  => 'legacy-77',
        'import_batch_id'   => '0192f5a0-7c1e-7000-8000-0000000000ff',
        'source_digest'     => 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
        'ip'                => '2001:db8::1',
        'user_agent'        => 'Navigateur Été/1.0',
        'context'           => '{"7":"numeric key","flags":[1,2],"nested":{"a":null}}',
        'properties'        => '{"lines":3,"amount":"10.00"}',
        'occurred_at'       => '2026-11-01 12:00:00.100000',
        'recorded_at'       => '2026-11-01 23:59:59.999999',
        'integrity_version' => 1,
        'key_id'            => 'd0123456789abcdef',
        'hmac'              => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    ];

    /** @var string The application time zone before the test, restored after it. */
    private string $applicationTimezone = 'UTC';

    /** @var string The default time zone before the test, restored after it. */
    private string $defaultTimezone = 'UTC';

    /**
     * Remember the time zones, so a test may change them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->applicationTimezone = app(ConfigRepository::class)->string('app.timezone', 'UTC');
        $this->defaultTimezone     = date_default_timezone_get();
    }

    /**
     * Restore the time zones after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        app(ConfigRepository::class)->set('app.timezone', $this->applicationTimezone);
        date_default_timezone_set($this->defaultTimezone);

        parent::tearDown();
    }

    /**
     * Every column of a row the engine stored reads back through the model as
     * written: the strings unchanged, the versions as integers, the JSON
     * columns as arrays, numeric keys and nested nulls kept, and the times in
     * the package's form, PostgreSQL's dropped trailing zeros restored.
     *
     * @return void
     */
    public function testReadsTheEntryWrittenOnEveryEngine(): void
    {
        DB::table(self::TABLE)->insert(self::ROW);

        $entry = AuditEntry::query()->findOrFail(self::ID);

        self::assertSame([
            ...self::ROW,
            'context'     => [7 => 'numeric key', 'flags' => [1, 2], 'nested' => ['a' => null]],
            'properties'  => ['lines' => 3, 'amount' => '10.00'],
            'occurred_at' => '2026-11-01T12:00:00.100000Z',
            'recorded_at' => '2026-11-01T23:59:59.999999Z',
        ], $entry->toArray());
    }

    /**
     * With the application's and PHP's time zones far from UTC, a stored time
     * still reads as the UTC instant it names, to the microsecond.
     *
     * @return void
     */
    public function testTimesReadAsUtcWithMicrosecondsWhateverTheApplicationTimeZone(): void
    {
        app(ConfigRepository::class)->set('app.timezone', 'Pacific/Auckland');
        date_default_timezone_set('Pacific/Auckland');

        DB::table(self::TABLE)->insert(self::ROW);

        $entry = AuditEntry::query()->findOrFail(self::ID);

        self::assertSame('UTC', $entry->occurred_at->getTimezone()->getName());
        self::assertSame('UTC', $entry->recorded_at->getTimezone()->getName());
        self::assertSame('2026-11-01 12:00:00.100000', $entry->occurred_at->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-11-01 23:59:59.999999', $entry->recorded_at->format('Y-m-d H:i:s.u'));
        self::assertSame(1793534400, $entry->occurred_at->getTimestamp());
        self::assertSame(999999, $entry->recorded_at->micro);
    }

    /**
     * With a table and a storage connection of the application's own, the model
     * reads the entry from that table on that connection, and nothing from the
     * default table on the default connection.
     *
     * @return void
     */
    public function testReadsFromACustomTableAndConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::STORAGE, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'store_']);
        $config->set('audit-log.storage.connection', self::STORAGE);
        $config->set('audit-log.entries.table', self::CUSTOM_TABLE);

        $migration = $this->loadMigration();

        $migration->up(); // @phpstan-ignore method.notFound

        try {
            DB::connection(self::STORAGE)->table(self::CUSTOM_TABLE)->insert(self::ROW);

            $entry = AuditEntry::query()->findOrFail(self::ID);

            self::assertSame(self::STORAGE, $entry->getConnectionName());
            self::assertSame(self::CUSTOM_TABLE, $entry->getTable());
            self::assertSame('invoice.approved', $entry->event);
            self::assertSame('2026-11-01T12:00:00.100000Z', $entry->occurred_at->format('Y-m-d\TH:i:s.u\Z'));
            self::assertSame(1, AuditEntry::query()->count());
            self::assertSame(0, DB::connection(self::CONNECTION)->table(self::TABLE)->count());
        } finally {
            $migration->down(); // @phpstan-ignore method.notFound
        }

        self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::CUSTOM_TABLE));
    }

    /**
     * Require the shipped anonymous-class migration file and return the
     * resulting `Migration` instance.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function loadMigration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('Entries migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
