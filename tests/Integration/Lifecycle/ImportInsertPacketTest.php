<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\DefinesEvents;
use Tests\TestCase;

/**
 * Integration tests for an import chunk of large rows against MySQL's
 * `max_allowed_packet`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportWriter::class)]
final class ImportInsertPacketTest extends TestCase
{
    use DefinesEvents;

    /** @var string The memory limit the test runs under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The lines of the file: one chunk of the least `import.chunk`. */
    private const int LINES = 100;

    /** @var int The longest strings in each line's retained property, inside the default line bound of 1 MiB. */
    private const int STRINGS = 950;

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /** @var string The import file. */
    private string $path = '';

    /**
     * Skip all but MySQL, raise the memory limit, and retain 1 MiB of
     * properties.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection(StorageConnection::name())->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL bounds a statement by max_allowed_packet.');
        }

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        $config = app(ConfigRepository::class);

        $config->set('audit-log.source.id', 'app-eu-1');
        $config->set('audit-log.import.chunk', self::LINES);
        $config->set('audit-log.redaction.max_bytes', 1048576);

        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        self::define(EventDefinition::for('invoice.approved')->category('finance')->retain('memo'));
    }

    /**
     * Remove the file, put the clock back and restore the memory limit, never
     * below what is held: PHP refuses that.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->path !== '') {
            @unlink($this->path);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();

        if ($this->memoryLimit === '') {
            return;
        }

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));
    }

    /**
     * A chunk larger than the packet is inserted in groups that each fit it.
     *
     * @return void
     */
    public function testAChunkOfLargeRowsFitsThePacket(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $inserts    = [];

        DB::listen(static function (QueryExecuted $query) use (&$inserts): void {
            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $inserts[] = array_sum(array_map(static fn (mixed $value): int => is_scalar($value) ? strlen((string) $value) : 0, $query->bindings));
        });

        $result = app(AuditImporter::class)->import(ImportSource::fromFile($this->importFile(), 'crm-eu'), new Authority(Reference::of('App\Models\User', '7'), 'case.review'));
        $packet = $connection->scalar('select @@global.max_allowed_packet');

        self::assertIsNumeric($packet);
        self::assertGreaterThan((int) $packet, array_sum($inserts));
        self::assertLessThanOrEqual(ImportWriter::BYTES_PER_INSERT, max(0, ...$inserts));
        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame(self::LINES, $result->imported);
        self::assertSame(self::LINES, $connection->table(EntrySettings::table())->count());
    }

    /**
     * Write a file of lines `rec-1` onwards, each with one large property.
     *
     * @return string
     */
    private function importFile(): string
    {
        $this->path = (string) tempnam(sys_get_temp_dir(), 'import-insert-packet-');

        $file = fopen($this->path, 'wb');

        self::assertIsResource($file);

        for ($number = 1; $number <= self::LINES; $number++) {
            fwrite($file, json_encode([
                'format'           => 'audit-log-import/v1',
                'source_record_id' => 'rec-' . $number,
                'occurred_at'      => '2026-10-01T09:00:00.000001Z',
                'event'            => 'invoice.approved',
                'outcome'          => 'success',
                'category'         => 'finance',
                'properties'       => ['memo' => array_fill(0, self::STRINGS, str_repeat('x', FieldPolicy::STRING_MAX_BYTES))],
            ], JSON_THROW_ON_ERROR) . "\n");
        }

        fclose($file);

        return $this->path;
    }
}
