<?php

declare(strict_types = 1);

namespace Tests\Integration\Testing;

use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportSnapshot;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Integration tests for an application's own test suite, which wraps each test
 * in `DatabaseTransactions` and records, reads and exports against the database
 * store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
#[CoversClass(ReadGate::class)]
#[CoversClass(ExportSnapshot::class)]
final class ConsumerTestHarnessTest extends TestCase
{
    use DatabaseTransactions, InteractsWithAuditStore, ReadsTheTrail;

    /** @var string The code the application records. */
    private const string CODE = 'invoice.approved';

    /** @var string The directory each test exports to, made for it alone. */
    private string $directory = '';

    /**
     * Let every viewer see every entry, and make the export directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->allowEverything();

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-harness-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the export directory and what was written to it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $path) {
            if (!is_file($path)) {
                continue;
            }

            unlink($path);
        }

        rmdir($this->directory);

        parent::tearDown();
    }

    /**
     * A record made by a route is stored by the time the response returns.
     *
     * @return void
     */
    public function testARecordFromARouteIsStoredAtOnce(): void
    {
        Route::post('/invoices/42/approve', static fn (): string => AuditLog::record(self::CODE)->id);

        $id = (string) $this->post('/invoices/42/approve')->assertOk()->baseResponse->getContent();

        self::assertSame(1, $this->storageConnection()->transactionLevel());
        self::assertSame('http', $this->storedRow($id)['origin']);
    }

    /**
     * A transaction rolled back inside the wrapper drops its record and keeps
     * the one made before it.
     *
     * @return void
     */
    public function testANestedRollbackDropsTheRecord(): void
    {
        $kept       = AuditLog::record(self::CODE)->id;
        $connection = $this->storageConnection();

        $connection->beginTransaction();

        AuditLog::record(self::CODE);

        $connection->rollBack();

        self::assertSame(1, $connection->transactionLevel());
        self::assertSame(1, $this->entryCount());
        self::assertSame($kept, $this->storedRow($kept)['id']);
    }

    /**
     * A count returns what is stored and records the read.
     *
     * @return void
     */
    public function testACountReturnsAndIsRecorded(): void
    {
        AuditLog::record(self::CODE);
        AuditLog::record(self::CODE);

        self::assertSame(2, AuditLog::trail()->visibleTo($this->viewer())->forEvent(self::CODE)->count());

        $counted = $this->readRecords('audit_log.trail_counted');

        self::assertCount(1, $counted);
        self::assertSame(2, self::propertiesOf($counted[0])['returned'] ?? null);
    }

    /**
     * An export is written and recorded, and verifying it finds nothing.
     *
     * @return void
     */
    public function testAnExportVerifies(): void
    {
        AuditLog::record(self::CODE);
        AuditLog::record(self::CODE);

        $path   = $this->directory . '/trail.ndjson';
        $trail  = AuditLog::trail()->visibleTo($this->viewer());
        $result = $trail->forEvent(self::CODE)->export($path);

        self::assertSame(2, $result->lines);
        self::assertFileExists($path . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([$result->entryId], array_map(self::idOf(...), $this->readRecords('audit_log.trail_exported')));

        $verification = $trail->verifyExport($path);

        self::assertTrue($verification->isVerified());
        self::assertSame($result->entryId, $verification->entryId);
        self::assertCount(1, $this->readRecords('audit_log.export_verified'));
    }
}
