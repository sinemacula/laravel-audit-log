<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Stores entries and seals them, as the package does, and reads back what the
 * seals hold: finalised records stored through the database store at the times
 * a test chooses, a sealer built from the container's collaborators on a clock
 * a test may freeze, the stored seals as raw rows, and an explicit key ring.
 *
 * A sealer runs on the container's clock until `sealAt()` freezes its own, so
 * entries a test records through the package are sealed, and a test that pins
 * the seal's times freezes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SealsEntries
{
    /** @var string When the first of the entries stored together is recorded, unless a test gives another time. */
    protected const string ENTRIES_RECORDED_AT = '2026-11-01 12:00:00.000000';

    /** @var ?\Tests\Fixtures\Support\FrozenClock The clock sealers run on, once a test has frozen it. */
    private ?FrozenClock $sealingClock = null;

    /**
     * Store the number of finalised records through the database store, the
     * first recorded at the time given, in UTC, and each next one microsecond
     * later, each occurring when it is recorded. With a key id, they are signed
     * under that key of the ring, which is the current key only while they are
     * stored.
     *
     * @param  int  $count
     * @param  string  $recordedAt
     * @param  ?string  $keyId
     * @return list<string>
     */
    protected function storeEntries(int $count, string $recordedAt = self::ENTRIES_RECORDED_AT, ?string $keyId = null): array
    {
        $config  = app(ConfigRepository::class);
        $current = $config->get('audit-log.integrity.current');
        $first   = new CarbonImmutable($recordedAt, 'UTC');
        $ids     = [];

        if ($keyId !== null) {
            $config->set('audit-log.integrity.current', $keyId);
        }

        try {
            for ($index = 0; $index < $count; $index++) {
                $ids[] = $this->storeOne($first->addMicroseconds($index), null);
            }
        } finally {
            $config->set('audit-log.integrity.current', $current);
        }

        return $ids;
    }

    /**
     * Store one finalised record through the database store, recorded at the
     * time given, in UTC, under the id given or a fresh one, and return its id.
     *
     * @param  string  $recordedAt
     * @param  ?string  $id
     * @return string
     */
    protected function storeEntryAt(string $recordedAt, ?string $id = null): string
    {
        return $this->storeOne(new CarbonImmutable($recordedAt, 'UTC'), $id);
    }

    /**
     * Freeze the clock every sealer this test builds runs on at the time given,
     * in UTC.
     *
     * @param  string  $at
     * @return void
     */
    protected function sealAt(string $at): void
    {
        $this->sealingClock = FrozenClock::at($at);
    }

    /**
     * A sealer built from the container's collaborators, the installation's
     * identity among them, on the frozen clock when the test has frozen one,
     * and on the container's clock otherwise.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Sealer
     */
    protected function sealer(): Sealer
    {
        $clock    = $this->sealingClock ?? app(Clock::class);
        $database = app(DatabaseManager::class);
        $settings = app(SealSettings::class);
        $writer   = new CheckpointWriter($database, app(SealSigner::class), $settings, $clock);

        return new Sealer($writer, app(IntegrityProgress::class), $settings, app(FailureClassifier::class), $clock, $database, new InstallationIdentity($database));
    }

    /**
     * Seal every entry no seal holds yet, whatever its age, recorded no later
     * than the sealer's clock: a sweep from the beginning of the table, its
     * saved cursor forgotten first.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealResult
     */
    protected function sealAll(): SealResult
    {
        app(IntegrityProgress::class)->forget(IntegrityProgress::SWEEP_CURSOR);

        return $this->sealer()->sweep();
    }

    /**
     * Every stored seal as its raw row, by sequence: each column as the engine
     * returns it, a scalar or `null`.
     *
     * @return list<array<string, scalar|null>>
     */
    protected function seals(): array
    {
        $seals = DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->orderBy('sequence')->get()->all();

        /** @var list<array<string, scalar|null>> $rows */
        $rows = array_map(static fn (object $seal): array => (array) $seal, $seals);

        return $rows;
    }

    /**
     * The ids of the entries the seal holds, in id order.
     *
     * @param  string  $sealId
     * @return list<string>
     */
    protected function membersOf(string $sealId): array
    {
        $members = DB::connection(StorageConnection::name())
            ->table(IntegrityTables::membersTable())
            ->where('checkpoint_id', $sealId)
            ->orderBy('entry_id')
            ->pluck('entry_id')
            ->all();

        self::assertContainsOnlyString($members);

        return array_values($members);
    }

    /**
     * Configure an explicit key ring of the keys given, by id, signing under
     * the current one.
     *
     * @param  array<string, string>  $keys
     * @param  string  $current
     * @return void
     */
    protected function useRing(array $keys, string $current): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.keys', $keys);
        $config->set('audit-log.integrity.current', $current);
    }

    /**
     * Store one record recorded and occurring at the instant, under the id
     * given or a fresh one, and return its id.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @param  ?string  $id
     * @return string
     */
    private function storeOne(CarbonImmutable $at, ?string $id): string
    {
        $instant   = StoredTime::format($at);
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured(id: $id, occurredAt: $instant));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }
}
