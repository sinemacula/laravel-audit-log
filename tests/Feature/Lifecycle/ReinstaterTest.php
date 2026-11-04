<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Reinstater;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for reinstating an erased owner, on whichever engine the suite
 * runs against: a `reinstate` row and a `reinstated` marker under the row's id,
 * at the erasure's floor, committed together; an owner that is not erased
 * refused, writing nothing; a marker the verified chain does not back refused
 * as a broken journal, writing nothing; the next key above the floor and an
 * erased generation never reopened; and the installation confirmed before the
 * lock.
 *
 * Owners are erased by hand, as an erasure commits it, and their next keys made
 * through the key creator, so the eraser and the encrypter are not relied on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Reinstater::class)]
final class ReinstaterTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string When every operation runs. */
    private const string NOW = '2026-11-04 10:00:00.123456';

    /** @var string The operation every reinstatement runs under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The connection a test points the maintenance connection at when it must reach another database. */
    private const string OTHER = 'audit_other';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
    }

    /**
     * Roll back any transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An erased owner is reinstated: a `reinstate` row naming the operation,
     * the authority, the owner's fingerprint under the ring's signing key and
     * the erasure's floor, appended after the erasure; the result names the row
     * and is committed but not yet recorded.
     *
     * @return void
     */
    public function testAnErasedOwnerIsReinstatedAndJournalled(): void
    {
        $this->makeSubjectKey(self::owner());

        $erasure = $this->eraseByHand(self::owner());
        $result  = $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        $rows = $this->journalRows();
        $row  = JournalRow::fromRow($rows[count($rows) - 1], true);

        self::assertCount(2, $rows);
        self::assertSame(JournalKind::REINSTATE, $row->kind);
        self::assertSame($erasure->sequence + 1, $row->sequence);
        self::assertSame(self::OPERATION, $row->operationId);
        self::assertSame(['App\Models\User', '7', 'case.review', 'app:ticket-123'], [$row->authorityType, $row->authorityId, $row->reason, $row->externalReference]);
        self::assertSame(CanonicalEncoder::encode(['owner_fingerprint' => $fingerprint, 'fingerprint_key' => $fingerprintKey, 'generation_floor' => 1]), $row->payload);

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertSame($row->id, $result->reinstatementId);
        self::assertSame([$fingerprint, $fingerprintKey, 1], [$result->fingerprint, $result->fingerprintKey, $result->generationFloor]);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
    }

    /**
     * The `reinstated` marker shares its journal row's id, sequence and time,
     * keeps the erasure's floor, and is now the owner's latest.
     *
     * @return void
     */
    public function testTheMarkerNamesItsJournalRow(): void
    {
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());

        $result = $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());
        $marker = app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner());
        $rows   = $this->journalRows();
        $row    = JournalRow::fromRow($rows[count($rows) - 1], false);

        self::assertNotNull($marker);
        self::assertSame($result->reinstatementId, $marker->id);
        self::assertSame($row->id, $marker->id);
        self::assertSame(MarkerTransition::REINSTATED, $marker->transition);
        self::assertSame($row->sequence, $marker->journalSequence);
        self::assertSame($row->occurredAt, $marker->createdAt);
        self::assertSame(1, $marker->generationFloor);
        self::assertSame(['App\Models\User', '42'], [$marker->owner->type, $marker->owner->id]);
        self::assertSame(2, $this->markerCount());
    }

    /**
     * An owner never erased, and one already reinstated, is refused
     * `not_erased`, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANotErasedOwnerIsRefused(): void
    {
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());
        $this->reinstateByHand(self::owner());

        foreach ([self::owner(), Reference::of('App\Models\User', '43')] as $owner) {
            $journal = count($this->journalRows());
            $markers = $this->markerCount();

            try {
                $this->reinstater()->reinstate(self::OPERATION, $owner, self::authority());

                self::fail('Expected the reinstatement to be refused.');
            } catch (ReinstatementRefusedException $exception) {
                self::assertSame('not_erased', $exception->reason, $owner->id);
            }

            self::assertCount($journal, $this->journalRows(), $owner->id);
            self::assertSame($markers, $this->markerCount(), $owner->id);
        }
    }

    /**
     * Rows of `[how the latest marker is forged, the finding]`: a marker that
     * names no row of the verified chain by its id and sequence, or a row that
     * is not a signed erasure of the owner at the marker's floor.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideForgedMarkers(): iterable
    {
        yield from [
            'a row that is not there'       => ['missing', Finding::JOURNAL_GAP],
            'a row at another sequence'     => ['sequence', Finding::JOURNAL_GAP],
            'a row whose payload changed'   => ['payload', Finding::JOURNAL_SIGNATURE],
            'a row of another kind'         => ['kind', Finding::JOURNAL_TRANSITION],
            'another owner\'s erasure'      => ['owner', Finding::JOURNAL_TRANSITION],
            'another floor than the row\'s' => ['floor', Finding::JOURNAL_TRANSITION],
        ];
    }

    /**
     * An erased marker the verified chain does not back is refused as a broken
     * journal, naming the finding, and nothing is written.
     *
     * @param  string  $forgery
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideForgedMarkers')]
    public function testAMarkerNotInTheChainRefuses(string $forgery, Finding $finding): void
    {
        $this->makeSubjectKey(self::owner());

        $erasure = $this->eraseByHand(self::owner());

        $this->forge($forgery, $erasure);

        $journal = $this->journalRows();
        $markers = $this->markerCount();

        try {
            $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

            self::fail('Expected the reinstatement to be refused.');
        } catch (JournalBrokenException $exception) {
            self::assertSame($finding, $exception->finding);
        }

        self::assertSame($journal, $this->journalRows());
        self::assertSame($markers, $this->markerCount());
    }

    /**
     * A journal that fails verification refuses the reinstatement before the
     * marker is read, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABrokenJournalRefuses(): void
    {
        $this->makeSubjectKey(self::owner());

        $erasure = $this->eraseByHand(self::owner());

        $this->tamperJournal($erasure->sequence, ['reason' => 'other.reason']);

        try {
            $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

            self::fail('Expected the reinstatement to be refused.');
        } catch (JournalBrokenException $exception) {
            self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        }

        self::assertCount(1, $this->journalRows());
        self::assertSame(1, $this->markerCount());
    }

    /**
     * Reinstatement creates no key; the owner's next key, in any unit, is made
     * one above the erasure's floor, the largest generation the owner had, even
     * in a unit whose own largest generation is lower.
     *
     * @return void
     */
    public function testTheNextKeyIsAboveTheFloor(): void
    {
        [$first] = $this->makeSubjectKey(self::owner());

        $this->makeSubjectKey(self::owner(), null, 'billing');
        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $first->id)->update(['state' => KeyState::SUPERSEDED->value]);
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());

        $keys   = count($this->storedSubjectKeys());
        $result = $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

        self::assertSame(2, $result->generationFloor);
        self::assertCount($keys, $this->storedSubjectKeys());

        [$billing] = $this->makeSubjectKey(self::owner(), null, 'billing');
        [$default] = $this->makeSubjectKey(self::owner());

        self::assertSame(3, $billing->generation);
        self::assertSame(3, $default->generation);
    }

    /**
     * An erased generation never reopens: after the reinstatement the erased
     * key is still erased with no wrapped key, and the unit's next key is a new
     * row at a new generation.
     *
     * @return void
     */
    public function testAnErasedGenerationNeverReopens(): void
    {
        [$erased] = $this->makeSubjectKey(self::owner());

        $erasure = $this->eraseByHand(self::owner());

        $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

        [$next] = $this->makeSubjectKey(self::owner());
        $stored = $this->storedSubjectKeys();

        self::assertSame(KeyState::ERASED, $stored[$erased->id]->state);
        self::assertNull($stored[$erased->id]->wrappedKey);
        self::assertSame($erasure->id, $stored[$erased->id]->erasureId);
        self::assertNotSame($erased->id, $next->id);
        self::assertSame(2, $next->generation);
        self::assertSame(KeyState::LIVE, $next->state);
        self::assertSame($next->id, app(KeyStore::class)->liveOf($this->keyConnection(), new KeyUnit(self::owner(), null, self::KEY_CATEGORY))?->id);
    }

    /**
     * An owner erased, reinstated and erased again is reinstated again, at the
     * floor of the later erasure.
     *
     * @return void
     */
    public function testAnOwnerIsReinstatedAfterEachErasure(): void
    {
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());
        $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());

        $result = $this->reinstater()->reinstate('01932b4e-9000-7000-8000-0000000000a2', self::owner(), self::authority());

        self::assertSame(2, $result->generationFloor);
        self::assertSame(MarkerTransition::REINSTATED, app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner())?->transition);
        self::assertCount(4, $this->journalRows());
    }

    /**
     * The installation is confirmed before the lock is taken: a maintenance
     * connection that reaches another database is refused, and neither the
     * lock, the journal nor the markers are touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInstallationMismatchRefusesBeforeTheLock(): void
    {
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());
        $this->otherDatabase();

        $lock = (array) DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->first();

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        try {
            $this->reinstater()->reinstate(self::OPERATION, self::owner(), self::authority());

            self::fail('Expected the reinstatement to be refused.');
        } catch (InstallationMismatchException) {
            // The refusal under test
        }

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', null);

        self::assertSame($lock, (array) DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->first());
        self::assertCount(1, $this->journalRows());
        self::assertSame(1, $this->markerCount());
    }

    /**
     * Forge the owner's latest marker, or the erasure row it names, as the case
     * says.
     *
     * @param  string  $forgery
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $erasure
     * @return void
     */
    private function forge(string $forgery, JournalRow $erasure): void
    {
        $marker = $this->keyConnection()->table(KeyTables::ownerErasuresTable())->where('id', $erasure->id);

        match ($forgery) {
            'missing'  => $marker->update(['id' => Str::uuid7()->toString()]),
            'sequence' => $marker->update(['journal_sequence' => $erasure->sequence + 5]),
            'payload'  => $this->tamperJournal($erasure->sequence, ['payload' => CanonicalEncoder::encode(['generation_floor' => 1])]),
            'kind'     => $this->pointAt($marker, $this->journalRow(JournalKind::REWRAP, ['run_id' => self::OPERATION, 'rotate' => false, 'keys' => [], 'skipped' => []])),
            'owner'    => $this->pointAt($marker, $this->otherOwnersErasure()),
            'floor'    => $marker->update(['generation_floor' => 5]),
            default    => self::fail(sprintf('No forgery is called `%s`.', $forgery)),
        };
    }

    /**
     * Point the marker at the journal row, by its id and sequence.
     *
     * @param  \Illuminate\Database\Query\Builder  $marker
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @return int
     */
    private function pointAt(Builder $marker, JournalRow $row): int
    {
        return $marker->update(['id' => $row->id, 'journal_sequence' => $row->sequence]);
    }

    /**
     * Another owner's erasure row at the same floor, its own marker removed so
     * the owner's marker can take its id.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function otherOwnersErasure(): JournalRow
    {
        $other = Reference::of('App\Models\User', '43');

        $this->makeSubjectKey($other);

        $row = $this->eraseByHand($other);

        $this->keyConnection()->table(KeyTables::ownerErasuresTable())->where('id', $row->id)->delete();

        return $row;
    }

    /**
     * Configure `OTHER`, a connection to another database whose integrity state
     * table holds no installation id.
     *
     * @return void
     */
    private function otherDatabase(): void
    {
        $config = app(ConfigRepository::class);

        DB::purge(self::OTHER);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        $schema = DB::connection(self::OTHER)->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        $this->beforeApplicationDestroyed(static fn () => DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable()));
    }

    /**
     * The number of owner markers stored.
     *
     * @return int
     */
    private function markerCount(): int
    {
        return $this->keyConnection()->table(KeyTables::ownerErasuresTable())->count();
    }

    /**
     * The reinstater the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Reinstater
     */
    private function reinstater(): Reinstater
    {
        $this->keyWrapper();

        return app(Reinstater::class);
    }

    /**
     * The owner every test reinstates.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', '42');
    }

    /**
     * The authority every reinstatement is made with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }
}
