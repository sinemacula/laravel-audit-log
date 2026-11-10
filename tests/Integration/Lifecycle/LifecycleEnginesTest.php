<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for the lifecycle as the package ships it, on whichever
 * engine the suite runs against: a hold keeps its entries through a prune, its
 * release lets the next prune take them, and verification passes after each,
 * the seal holding a record of each prune; an import held on its start keeps
 * its batch through a prune that takes the entries beside it, until the hold is
 * released, after which the same file imports as new rows; and a pruned entry
 * put back below the package is found `resurrected`.
 *
 * Every operation goes through `AuditLog::lifecycle()` or a command, on the
 * provider's default bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
#[CoversClass(AuditLifecycle::class)]
final class LifecycleEnginesTest extends TestCase
{
    /** @var string When every run starts. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string When an entry within thirty days happened. */
    private const string RECENT = '2026-12-10T10:00:00.000000Z';

    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, name this installation's source, keep every category
     * thirty days and report to a recording handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $config = app(ConfigRepository::class);

        $config->set('audit-log.source.id', 'app-eu-1');
        $config->set('audit-log.retention.after_days', 30);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Roll back any transaction a test left open, put the clock back and remove
     * the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * On each engine a hold keeps its entry through a prune that takes the
     * entry beside it, and verification passes; once it is released, the next
     * prune takes the entry it kept, the seal holds a record of each prune, and
     * verification passes again with the seal `pruned`.
     *
     * @return void
     */
    public function testHoldPruneReleasePruneVerifiesOnEachEngine(): void
    {
        $held   = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->seal();

        $hold  = AuditLog::lifecycle()->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')), self::authority(), HoldBasis::LEGAL_CLAIM);
        $first = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1, true], [$first->status, $first->deleted, $first->held, $first->recorded]);
        self::assertSame(self::sorted([$held, $kept]), $this->present([$held, $pruned, $kept]));
        self::assertSame([0, ['pruned']], $this->verify());

        $release = AuditLog::lifecycle()->release($hold->hold->id, self::authority());
        $second  = AuditLog::lifecycle()->prune();

        self::assertTrue($release->recorded);
        self::assertSame([PruneStatus::COMPLETE, 1, 0], [$second->status, $second->deleted, $second->held]);
        self::assertSame([$kept], $this->present([$held, $pruned, $kept]));
        self::assertSame([], AuditLog::lifecycle()->holds());

        self::assertCount(2, app(PruneLedger::class)->recordsFor($this->sealOf($kept)));
        self::assertSame([0, ['pruned']], $this->verify());
    }

    /**
     * On each engine an import held on its start keeps every entry of its
     * batch, past retention on arrival, through a prune that takes the entry
     * beside them; once the hold is released the next prune takes them, the
     * same file then imports as new rows, and verification passes throughout.
     *
     * @return void
     */
    public function testAnImportThenAPruneOfItsBatchUnderAHoldOnEachEngine(): void
    {
        $other  = $this->storeEntry(self::OLD);
        $file   = $this->importFile(['rec-1', 'rec-2', 'rec-3']);
        $source = ImportSource::fromFile($file, self::SOURCE, 'eu-west-1');
        $import = AuditLog::lifecycle()->import($source, self::authority(), hold: true, basis: HoldBasis::REGULATORY);

        self::assertSame([ImportStatus::COMPLETE, 3, 3, true], [$import->status, $import->imported, $import->pastRetention, $import->recorded]);
        self::assertNotNull($import->hold);

        $batch = $this->batchIds((string) $import->batchId);

        $this->seal();

        $held = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 3], [$held->status, $held->deleted, $held->held]);
        self::assertSame([], $this->present([$other]));
        self::assertSame($batch, $this->present($batch));
        self::assertSame([0, ['pruned']], $this->verify());

        AuditLog::lifecycle()->release($import->hold->id, self::authority());

        $released = AuditLog::lifecycle()->prune();

        self::assertSame([PruneStatus::COMPLETE, 3], [$released->status, $released->deleted]);
        self::assertSame([], $this->present($batch));

        $again = AuditLog::lifecycle()->import($source, self::authority());

        self::assertSame([ImportStatus::COMPLETE, 3, 0], [$again->status, $again->imported, $again->duplicates]);
        self::assertSame([], array_values(array_intersect($batch, $this->batchIds((string) $again->batchId))));

        $this->seal();

        self::assertSame(0, $this->verify()[0]);
    }

    /**
     * On each engine an entry pruned under a signed record and then put back
     * below the package, as a restore or a direct insert would, is found:
     * verification calls its seal `incomplete`, `resurrected` at that entry,
     * and fails.
     *
     * @return void
     */
    public function testAResurrectedPrunedRowIsFoundOnEachEngine(): void
    {
        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->seal();

        $stored = (array) $this->storage()->table(EntrySettings::table())->where('id', $pruned)->first();

        self::assertSame(1, AuditLog::lifecycle()->prune()->deleted);
        self::assertSame([0, ['pruned']], $this->verify());

        $this->storage()->table(EntrySettings::table())->insert($stored);

        self::assertSame(self::sorted([$pruned, $kept]), $this->present([$pruned, $kept]));

        Artisan::call('audit-log:verify', ['--json' => true]);

        $segment = $this->segments(Artisan::output())[0] ?? [];

        self::assertSame(['incomplete', 'resurrected', $pruned], [$segment['integrity'] ?? null, $segment['finding'] ?? null, $segment['first_bad_id'] ?? null]);
        self::assertSame([1, ['incomplete']], $this->verify());
    }

    /**
     * On each engine a second prune after a pruned entry was put back never
     * deletes it again: the seal is skipped, no second record sets its member,
     * and verification still reports it `resurrected`, never `prune_record`.
     *
     * @return void
     */
    public function testAResurrectedPrunedRowIsNeverPrunedAgainOnEachEngine(): void
    {
        $pruned = $this->storeEntry(self::OLD);
        $kept   = $this->storeEntry(self::RECENT);

        $this->seal();

        $stored = (array) $this->storage()->table(EntrySettings::table())->where('id', $pruned)->first();

        self::assertSame(1, AuditLog::lifecycle()->prune()->deleted);

        $this->storage()->table(EntrySettings::table())->insert($stored);

        $again = AuditLog::lifecycle()->prune();

        self::assertSame([0, 1], [$again->deleted, $again->skippedSeals]);
        self::assertSame(self::sorted([$pruned, $kept]), $this->present([$pruned, $kept]));

        Artisan::call('audit-log:verify', ['--json' => true]);

        $segment = $this->segments(Artisan::output())[0] ?? [];

        self::assertSame(['incomplete', 'resurrected', $pruned], [$segment['integrity'] ?? null, $segment['finding'] ?? null, $segment['first_bad_id'] ?? null]);
    }

    /**
     * Store a captured record with the fields given over its own, happening at
     * the instant given and recorded at the test's time, and return its id.
     *
     * @param  string  $occurredAt
     * @param  array<string, ?string>  $fields
     * @return string
     */
    private function storeEntry(string $occurredAt, array $fields = []): string
    {
        $record    = RecordFactory::withFields(['occurred_at' => $occurredAt, ...$fields]);
        $finalised = (new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * Seal every entry recorded so far through `audit-log:seal --sweep`.
     *
     * @return void
     */
    private function seal(): void
    {
        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]), Artisan::output());
    }

    /**
     * Run `audit-log:verify --json` and return its exit code and each segment's
     * integrity, in order.
     *
     * @return array{0: int, 1: list<string>}
     *
     * @phpstan-impure
     */
    private function verify(): array
    {
        $exit = Artisan::call('audit-log:verify', ['--json' => true]);

        return [$exit, array_map(static fn (array $segment): string => (string) $segment['integrity'], $this->segments(Artisan::output()))];
    }

    /**
     * The segments `audit-log:verify --json` wrote, in order.
     *
     * @param  string  $printed
     * @return list<array<array-key, scalar|null>>
     */
    private function segments(string $printed): array
    {
        $segments = [];

        foreach (array_filter(explode("\n", $printed), static fn (string $line): bool => str_starts_with($line, '{')) as $line) {
            $decoded = json_decode($line, true);

            if (!is_array($decoded) || ($decoded['type'] ?? null) !== 'segment') {
                continue;
            }

            $segments[] = array_map(static fn (mixed $value): bool|float|int|string|null => is_scalar($value) ? $value : null, $decoded);
        }

        return $segments;
    }

    /**
     * The id of the seal that holds the entry.
     *
     * @param  string  $entryId
     * @return string
     */
    private function sealOf(string $entryId): string
    {
        $sealId = $this->storage()->table(IntegrityTables::membersTable())->where('entry_id', $entryId)->value('checkpoint_id');

        self::assertIsString($sealId);

        return $sealId;
    }

    /**
     * The ids of the stored entries of the batch, sorted.
     *
     * @param  string  $batchId
     * @return list<string>
     */
    private function batchIds(string $batchId): array
    {
        return self::sorted(self::strings($this->storage()->table(EntrySettings::table())->where('import_batch_id', $batchId)->pluck('id')->all()));
    }

    /**
     * The ids among those given whose entries are still stored, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        return self::sorted(self::strings($this->storage()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all()));
    }

    /**
     * A file of a line of the import format for each record id, each past
     * retention, and its path.
     *
     * @param  list<string>  $recordIds
     * @return string
     */
    private function importFile(array $recordIds): string
    {
        $lines = array_map(static fn (string $recordId): string => (string) json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-10-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
        ]), $recordIds);

        $path = (string) tempnam(sys_get_temp_dir(), 'lifecycle-engines-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The authority every operation is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * The strings given, sorted bytewise.
     *
     * @param  list<string>  $strings
     * @return list<string>
     */
    private static function sorted(array $strings): array
    {
        sort($strings, SORT_STRING);

        return $strings;
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function storage(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
