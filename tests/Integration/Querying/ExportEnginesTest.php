<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ExportBundle;
use SineMacula\Laravel\AuditLog\Querying\Exporter;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportSnapshot;
use SineMacula\Laravel\AuditLog\Querying\ExportVerifier;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsArtifacts;
use Tests\TestCase;

/**
 * Integration tests for exporting the trail while another process writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Exporter::class)]
#[CoversClass(ExportVerifier::class)]
#[CoversClass(ExportSnapshot::class)]
final class ExportEnginesTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail, RunsKilledChildren, SeedsArtifacts;

    /** @var string The gate this process opens once the export's bound has been read. */
    private const string BOUND = 'bound';

    /** @var string The gate the child opens once its row is committed. */
    private const string COMMITTED = 'committed';

    /** @var string The file the child names the entry it committed in. */
    private const string IDS = 'ids';

    /** @var int The rows of a chunk, the least the setting takes. */
    private const int CHUNK = 100;

    /** @var string The pattern of the statement that reads an export's bound. */
    private const string BOUND_STATEMENT = '/order by .recorded_at. desc, .id. desc limit 1$/';

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /**
     * Bind the read path, reveal every entry, chunk by 100, make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();

        app(ConfigRepository::class)->set('audit-log.export.chunk', self::CHUNK);

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-export-engines-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory, then the children's files after the rollback.
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

        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Rows of `[format]`: each format an export is written in.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat}>
     */
    public static function provideFormats(): iterable
    {
        yield from [
            'NDJSON' => [ExportFormat::NDJSON],
            'OCSF'   => [ExportFormat::OCSF],
            'CEF'    => [ExportFormat::CEF],
        ];
    }

    /**
     * An export in each format verifies on the engine with no finding.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return void
     */
    #[DataProvider('provideFormats')]
    public function testAnExportVerifiesOnEveryEngine(ExportFormat $format): void
    {
        $this->seedEntries(self::CHUNK + 5);
        $this->seedBundle(2);

        $result       = $this->trail()->export($this->target(), $format);
        $verification = $this->trail()->verifyExport($this->target());

        self::assertSame(self::CHUNK + 6, $result->lines);
        self::assertSame([], $verification->findings);
        self::assertSame($result->entryId, $verification->entryId);
        self::assertSame(self::CHUNK + 6, $verification->lines);
    }

    /**
     * A row another process commits after the bound is read is not exported.
     *
     * @return void
     */
    public function testARowCommittedDuringTheExportIsNotExported(): void
    {
        $seeded = $this->seedEntries(250);
        $at     = $this->storedRow($seeded[200])['recorded_at'];

        self::assertIsString($at);

        $child = $this->startChild(function () use ($at): void {
            $this->awaitGate(self::BOUND);
            $this->appendToChildFile(self::IDS, $this->seedEntry([], $at));
            $this->openGate(self::COMMITTED);
        });

        $this->onBound(function (): void {
            $this->openGate(self::BOUND);
            $this->awaitGate(self::COMMITTED);
        });

        $result = $this->trail()->export($this->target());

        $this->assertKilled($this->waitForChild($child));

        $committed = $this->childFileLines(self::IDS);

        self::assertCount(1, $committed);
        self::assertSame(250, $result->lines);
        self::assertSame($seeded, $this->exportedIds());
        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());

        $this->trail()->forEvent('invoice.approved')->export($this->again());

        self::assertCount(251, $this->exportedIds($this->again()));
        self::assertContains($committed[0], array_slice($this->exportedIds($this->again()), 200, 2));
    }

    /**
     * The manifest names the engine's snapshot, never the testing transaction.
     *
     * @return void
     */
    public function testTheManifestNamesTheEnginesSnapshot(): void
    {
        $this->seedEntries(3);
        $this->trail()->export($this->target());

        $name     = StorageConnection::resolvedName();
        $storage  = DB::connection($name);
        $driver   = $storage->getDriverName();
        $manifest = $this->manifest();
        $lines    = $this->lines();
        $first    = json_decode($lines[0], true, 513, JSON_THROW_ON_ERROR);
        $last     = json_decode($lines[2], true, 513, JSON_THROW_ON_ERROR);

        self::assertIsArray($first);
        self::assertIsArray($last);
        self::assertSame([
            'connection'  => $name,
            'consistency' => ExportSnapshot::CONSISTENCY[$driver] ?? null,
            'database'    => $storage->getDatabaseName(),
            'engine'      => $driver,
            'table'       => EntrySettings::table(),
        ], $manifest['snapshot']);
        self::assertNotSame(ExportSnapshot::TESTING_TRANSACTION, $manifest['snapshot']['consistency'] ?? null);
        self::assertSame([3, [$first['recorded_at'], $first['id']], [$last['recorded_at'], $last['id']]], [$manifest['lines'], $manifest['first'], $manifest['last']]);
    }

    /**
     * Entries of one microsecond across chunks export once each, in id order.
     *
     * @return void
     */
    public function testIdenticalRecordedTimesExportOnce(): void
    {
        $ids = [];

        for ($index = 0; $index < 250; $index++) {
            $ids[] = $this->seedEntry([], self::FIRST_SEEDED_AT);
        }

        sort($ids, SORT_STRING);

        $this->trail()->export($this->target());

        self::assertSame($ids, $this->exportedIds());
        self::assertTrue($this->trail()->verifyExport($this->target())->isVerified());
    }

    /**
     * Once an export ends, no connection it made is left open.
     *
     * @return void
     */
    public function testTheExportsSessionIsGoneOnceItEnds(): void
    {
        $this->seedEntries(2);

        $sessions = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$sessions): void {
            $sessions[$query->connectionName] = true;
        });

        $before = array_keys(DB::getConnections());

        $this->trail()->export($this->target());

        $made = array_diff(array_keys($sessions), $before, [StorageConnection::resolvedName()]);

        self::assertNotSame([], $made);
        self::assertSame([], array_values(array_intersect($made, array_keys(DB::getConnections()))));
    }

    /**
     * Put SQLite on a WAL file shared across the fork, since a rollback journal
     * would block the child's commit.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $config->set($key . '.journal_mode', 'wal');
    }

    /**
     * The trail the tests read, for the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer());
    }

    /**
     * Where the tests export to.
     *
     * @return string
     */
    private function target(): string
    {
        return $this->directory . '/trail.ndjson';
    }

    /**
     * Where the tests export a second time.
     *
     * @return string
     */
    private function again(): string
    {
        return $this->directory . '/again.ndjson';
    }

    /**
     * The lines of the export at the path, or the target, without line feeds.
     *
     * @param  ?string  $path
     * @return list<string>
     */
    private function lines(?string $path = null): array
    {
        $contents = (string) file_get_contents($path ?? $this->target());

        return $contents === '' ? [] : explode("\n", substr($contents, 0, -1));
    }

    /**
     * The ids the export at the path, or the target, holds, in order.
     *
     * @param  ?string  $path
     * @return list<string>
     */
    private function exportedIds(?string $path = null): array
    {
        return array_map(static function (string $line): string {
            $decoded = json_decode($line, true, 513, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);
            self::assertIsString($decoded['id'] ?? null);

            return $decoded['id'];
        }, $this->lines($path));
    }

    /**
     * The fields of the manifest the target's bundle carries.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     */
    private function manifest(): array
    {
        $bundle = ExportBundle::decode((string) file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));

        self::assertNotNull($bundle);

        $read = ExportManifest::read($bundle['manifest']);

        self::assertNotNull($read);

        return $read['fields'];
    }

    /**
     * Run the callback once, right after an export's bound has been read.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function onBound(\Closure $callback): void
    {
        $ran = false;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$ran, $callback): void {
            if ($ran || preg_match(self::BOUND_STATEMENT, $query->sql) !== 1) {
                return;
            }

            $ran = true;

            $callback();
        });
    }
}
