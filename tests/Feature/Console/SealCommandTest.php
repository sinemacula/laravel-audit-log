<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\SealContentionException;
use SineMacula\Laravel\AuditLog\Integrity\SealFailedException;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Symfony\Component\Console\Output\Output;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:seal`: it seals the recent window or sweeps the
 * table and says what it sealed, anchors afterwards even when sealing failed,
 * warns on an unavailable anchor and still succeeds, alarms with a whole,
 * payload-free event and a reported exception on a refused head, a skipped
 * entry, a conflict or a refused seal, names any other failure by its class
 * alone, and takes the cache lock only when the store can hold one, skipping a
 * run while another holds it and releasing it after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealCommand::class)]
final class SealCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration, SealsEntries, SearchesForSecrets;

    /** @var string When the command runs. */
    private const string NOW = '2026-11-01 13:00:00';

    /** @var string The digest a disagreeing anchor holds instead of the local one. */
    private const string OTHER_DIGEST = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var list<string> The integrity status values, in order. */
    private const array INTEGRITY = ['valid', 'pruned', 'incomplete', 'unverifiable', 'tampered'];

    /** @var list<string> The anchoring status values, in order. */
    private const array ANCHORING = ['anchored', 'unanchored', 'unavailable', 'contradicted'];

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The handler every report reaches. */
    private RecordingExceptionHandler $handler;

    /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> Every integrity event dispatched. */
    private \ArrayObject $alarms;

    /**
     * Register the command with the console kernel, which keeps the test
     * independent of the provider, stop the clock, bind no anchor, and record
     * every report and every integrity event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new SealCommand);

        $this->sealAt(self::NOW);
        $this->handler = new RecordingExceptionHandler;
        $this->alarms  = new \ArrayObject;

        app()->instance(Clock::class, FrozenClock::at(self::NOW));
        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(ExceptionHandler::class, $this->handler);

        $alarms = $this->alarms;

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event);
        });
    }

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::name());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A run seals what is unsealed, prints the tally and succeeds; with no
     * anchor configured it says nothing of anchoring.
     *
     * @return void
     */
    public function testSealsAndPrintsTheTally(): void
    {
        $this->storeEntries(3);

        self::assertSame(0, $this->seal());
        self::assertSame("Sealed 3 entries in 1 seals (sequences 1 to 1).\n", $this->printed());
        self::assertCount(1, $this->seals());
        self::assertSame([], $this->handler->reports());
        self::assertCount(0, $this->alarms);
    }

    /**
     * A run with nothing unsealed says so and succeeds.
     *
     * @return void
     */
    public function testNothingToSealSaysSo(): void
    {
        self::assertSame(0, $this->seal());
        self::assertSame("Nothing to seal.\n", $this->printed());
    }

    /**
     * A sweep seals a window of the table from its cursor and says whether it
     * reached the end; the next sweep goes on from there.
     *
     * @return void
     */
    public function testSweepSealsFromTheCursorAndSaysWhetherItIsComplete(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', 100);
        app(ConfigRepository::class)->set('audit-log.integrity.seal.max_batches', 1);

        $this->storeEntries(150);

        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertSame("Sealed 100 entries in 1 seals (sequences 1 to 1).\nThe sweep continues from its cursor next run.\n", $this->printed());

        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertSame("Sealed 50 entries in 1 seals (sequences 2 to 2).\nThe sweep is complete.\n", $this->printed());

        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertSame("Nothing to seal.\nThe sweep is complete.\n", $this->printed());
    }

    /**
     * A sweep finds a row older than the recent window's lookback, which the
     * recent pass leaves.
     *
     * @return void
     */
    public function testTheSweepFindsWhatTheRecentPassLeaves(): void
    {
        $this->storeEntryAt('2026-11-01 12:50:00');
        $this->seal();
        $this->storeEntryAt('2026-11-01 10:00:00');

        self::assertSame(0, $this->seal());
        self::assertSame("Nothing to seal.\n", $this->printed());

        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertSame("Sealed 1 entries in 1 seals (sequences 2 to 2).\nThe sweep is complete.\n", $this->printed());
    }

    /**
     * A configured anchor is given the seals once they are sealed, and the
     * count anchored is printed.
     *
     * @return void
     */
    public function testAnchorsAfterSealing(): void
    {
        $anchor = $this->bindAnchor(new RecordingAnchor);

        $this->storeEntries(2);

        self::assertSame(0, $this->seal());
        self::assertSame("Sealed 2 entries in 1 seals (sequences 1 to 1).\nAnchored 1 seals.\n", $this->printed());
        self::assertSame([1 => $this->seals()[0]['seal_digest']], $anchor->held());

        self::assertSame(0, $this->seal());
        self::assertSame("Nothing to seal.\nAnchored 0 seals.\n", $this->printed());
    }

    /**
     * An unavailable anchor warns, naming its class and the seal from which
     * seals wait, and the run still succeeds with nothing reported or
     * dispatched.
     *
     * @return void
     */
    public function testAnUnavailableAnchorWarnsAndStillSucceeds(): void
    {
        $this->bindAnchor((new RecordingAnchor)->failing());
        $this->storeEntries(1);

        self::assertSame(0, $this->seal());
        self::assertSame(
            "Sealed 1 entries in 1 seals (sequences 1 to 1).\nAnchored 0 seals.\nThe anchor is unavailable (RuntimeException); seals from 1 wait to be anchored.\n",
            $this->printed(),
        );
        self::assertSame([], $this->handler->reports());
        self::assertCount(0, $this->alarms);
    }

    /**
     * An anchor unavailable before any seal is read, for a name the column
     * cannot hold, warns without naming a seal.
     *
     * @return void
     */
    public function testAnAnchorUnavailableBeforeAnySealWarnsWithoutASeal(): void
    {
        $anchor = \Mockery::mock(CheckpointAnchor::class);

        $anchor->shouldReceive('name')->andReturn('');

        $this->bindAnchor($anchor);

        self::assertSame(0, $this->seal());
        self::assertSame("Nothing to seal.\nAnchored 0 seals.\nThe anchor is unavailable (UnexpectedValueException); no seal is anchored until it is.\n", $this->printed());
    }

    /**
     * An anchor that holds another digest for a seal is an alarm: an error is
     * printed, a whole event is dispatched counting it tampered and
     * contradicted, the exception is reported, and the run fails.
     *
     * @return void
     */
    public function testAConflictAlarmsAndFails(): void
    {
        $this->bindAnchor((new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));
        $this->storeEntries(1);

        self::assertSame(1, $this->seal());
        self::assertSame(
            "Sealed 1 entries in 1 seals (sequences 1 to 1).\nAnchored 0 seals.\nThe anchor holds another digest for seal 1; the local log or the anchor has been altered.\n",
            $this->printed(),
        );

        $id = (string) $this->seals()[0]['id'];

        self::assertSingleAlarm(
            ['valid' => 0, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1],
            ['anchored' => 0, 'unanchored' => 0, 'unavailable' => 0, 'contradicted' => 1],
            'anchor_conflict',
            $id,
        );
        self::assertReported('The audit log\'s integrity check failed (seal): 1 tampered, 0 incomplete, 0 unverifiable; 0 unanchored,'
            . ' 0 unavailable, 1 contradicted; first finding anchor_conflict at ' . $id . '; head none.');
    }

    /**
     * A seal that does not verify is refused, never anchored, and alarms under
     * the status of its finding.
     *
     * @return void
     */
    public function testARefusedSealAlarmsAndFails(): void
    {
        $this->storeEntries(1);
        $this->seal();
        $this->editFirstSeal(['signature' => str_repeat('a', 64)]);

        $anchor = $this->bindAnchor(new RecordingAnchor);

        self::assertSame(1, $this->seal());
        self::assertSame("Nothing to seal.\nAnchored 0 seals.\nSeal 1 does not verify (seal_signature), so it is not anchored; run audit-log:verify.\n", $this->printed());
        self::assertSame(['latest'], $anchor->calls());

        $id = (string) $this->seals()[0]['id'];

        self::assertSingleAlarm(self::integrity(['tampered' => 1]), self::anchoring([]), 'seal_signature', $id);
        self::assertReported('The audit log\'s integrity check failed (seal): 1 tampered, 0 incomplete, 0 unverifiable; 0 unanchored,'
            . ' 0 unavailable, 0 contradicted; first finding seal_signature at ' . $id . '; head none.');
    }

    /**
     * A seal refused for a key the ring no longer holds alarms as unverifiable,
     * not tampered.
     *
     * @return void
     */
    public function testASealUnderAKeyNoLongerHeldAlarmsAsUnverifiable(): void
    {
        $this->storeEntries(1);
        $this->seal();
        $this->useRing(['k-other' => 'audit-log seal command test other key 0123'], 'k-other');
        $this->bindAnchor(new RecordingAnchor);

        self::assertSame(1, $this->seal());
        self::assertSingleAlarm(self::integrity(['unverifiable' => 1]), self::anchoring([]), 'seal_key', (string) $this->seals()[0]['id']);
    }

    /**
     * A last seal whose stored digest disagrees with its fields is never
     * extended: sealing stops, the alarm counts it tampered under the head's
     * id, and the run fails.
     *
     * @return void
     */
    public function testAChainRefusalAlarmsAndFails(): void
    {
        $this->storeEntries(1);
        $this->seal();
        $this->editFirstSeal(['seal_digest' => str_repeat('f', 64)]);
        $this->storeEntryAt('2026-11-01 12:30:00');

        self::assertSame(1, $this->seal());
        self::assertSame('Sealing stopped with ' . SealChainException::class . ".\n", $this->printed());
        self::assertCount(1, $this->seals());

        $id = (string) $this->seals()[0]['id'];

        self::assertSingleAlarm(self::integrity(['tampered' => 1]), self::anchoring([]), 'seal_digest', $id);
        self::assertReported('The audit log\'s integrity check failed (seal): 1 tampered, 0 incomplete, 0 unverifiable; 0 unanchored,'
            . ' 0 unavailable, 0 contradicted; first finding seal_digest at ' . $id . '; head none.');
    }

    /**
     * A last seal of another log id is never extended: sealing stops and the
     * alarm counts it unverifiable.
     *
     * @return void
     */
    public function testAHeadOfAnotherLogAlarmsAndFails(): void
    {
        $this->storeEntries(1);
        $this->seal();

        app(ConfigRepository::class)->set('audit-log.integrity.log_id', 'another-log');

        $this->storeEntryAt('2026-11-01 12:30:00');

        self::assertSame(1, $this->seal());
        self::assertSame('Sealing stopped with ' . SealChainException::class . ".\n", $this->printed());
        self::assertSingleAlarm(self::integrity(['unverifiable' => 1]), self::anchoring([]), 'log_mismatch', (string) $this->seals()[0]['id']);
    }

    /**
     * Entries that cannot be sealed are skipped and alarmed as unverifiable,
     * counted in the output, while the event, whose maps count segments, counts
     * the one failing condition once however many entries were skipped; no id
     * of them is in the output, the event or the report.
     *
     * @return void
     */
    public function testASkippedEntryAlarms(): void
    {
        $ids = $this->storeEntries(3);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->whereIn('id', [$ids[0], $ids[1]])->update(['hmac' => str_repeat('z', 64)]);

        self::assertSame(1, $this->seal());
        self::assertSame(
            "Sealed 1 entries in 1 seals (sequences 1 to 1).\nSkipped 2 entries that cannot be sealed (a malformed id, HMAC or time); they stay unsealed.\n",
            $this->printed(),
        );

        self::assertSingleAlarm(self::integrity(['unverifiable' => 1]), self::anchoring([]), 'entry_malformed', null);
        self::assertReported('The audit log\'s integrity check failed (seal): 0 tampered, 0 incomplete, 1 unverifiable; 0 unanchored,'
            . ' 0 unavailable, 0 contradicted; first finding entry_malformed at none; head none.');
        self::assertFalse(self::holdsText($this->printed(), $ids[0]), 'The skipped id was printed.');
        self::assertFalse(self::holdsText($this->alarms->getArrayCopy(), $ids[0]), 'The skipped id was dispatched.');
        self::assertFalse(self::holdsText($this->handler->reports(), $ids[0]), 'The skipped id was reported.');
    }

    /**
     * An anchor setting that is malformed stops anchoring alone: the run still
     * seals, prints that anchoring stopped, reports it as a seal failure by its
     * class alone and exits 1, and dispatches nothing, since the log itself is
     * not found altered.
     *
     * @return void
     */
    public function testAMalformedAnchorSettingStillSeals(): void
    {
        app()->offsetUnset(CheckpointAnchor::class);
        app()->bind(CheckpointAnchor::class, static fn (): CheckpointAnchor => app(AnchorFactory::class)->make());
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.driver', 'foo');

        $this->storeEntries(3);

        self::assertSame(1, $this->seal());
        self::assertSame("Sealed 3 entries in 1 seals (sequences 1 to 1).\nAnchoring stopped with InvalidArgumentException.\n", $this->printed());
        self::assertCount(1, $this->seals());
        self::assertSame([], $this->alarms->getArrayCopy());
        self::assertReported('Sealing stopped with InvalidArgumentException.', SealFailedException::class);
    }

    /**
     * The sweep holds its own lock, apart from the recent pass's, so a long
     * sweep never keeps the recent pass from sealing and anchoring, and either
     * pass that finds its own lock held does nothing.
     *
     * @return void
     */
    public function testTheSweepHoldsItsOwnLock(): void
    {
        $this->storeEntries(1);

        $sweep = Cache::lock(SealCommand::SWEEP_LOCK, SealCommand::LOCK_SECONDS);

        self::assertTrue($sweep->get());
        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertSame("Another sealer holds the lock.\n", $this->printed());
        self::assertSame(0, $this->seal());
        self::assertCount(1, $this->seals());

        $sweep->release();

        $recent = Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS);

        self::assertTrue($recent->get());

        $this->storeEntryAt('2026-11-01 12:30:00');

        self::assertSame(0, $this->seal(['--sweep' => true]));
        self::assertCount(2, $this->seals());
        self::assertSame(0, $this->seal());
        self::assertSame("Another sealer holds the lock.\n", $this->printed());

        $recent->release();
    }

    /**
     * Every event the command dispatches lists every integrity and every
     * anchoring status, in order, zero-filled, and covers no head, no remote
     * head and not the whole log.
     *
     * @return void
     */
    public function testEveryEventMapIsWhole(): void
    {
        $ids = $this->storeEntries(2);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $ids[0])->update(['hmac' => str_repeat('z', 64)]);

        $this->bindAnchor((new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));

        self::assertSame(1, $this->seal());
        self::assertCount(2, $this->alarms);
        self::assertCount(2, $this->handler->reports());

        foreach ($this->alarms as $alarm) {
            self::assertSame(self::INTEGRITY, array_keys($alarm->integrity), 'An integrity map is not whole.');
            self::assertSame(self::ANCHORING, array_keys($alarm->anchoring), 'An anchoring map is not whole.');
            self::assertSame('seal', $alarm->command);
            self::assertNull($alarm->head);
            self::assertNull($alarm->remoteHead);
            self::assertFalse($alarm->complete);
        }

        self::assertSame(['entry_malformed', 'anchor_conflict'], array_map(static fn (IntegrityCheckFailed $alarm): ?string => $alarm->finding, $this->alarms->getArrayCopy()));
        self::assertSame(self::INTEGRITY, array_map(static fn (IntegrityStatus $status): string => $status->value, IntegrityStatus::cases()));
        self::assertSame(self::ANCHORING, array_map(static fn (AnchorStatus $status): string => $status->value, AnchorStatus::cases()));
    }

    /**
     * A failure that stops sealing is printed and reported by its class alone:
     * neither its message, its statement nor its bindings appear anywhere.
     *
     * @return void
     */
    public function testAFailureIsReportedByItsClassAlone(): void
    {
        $this->storeEntries(1);
        $this->raiseOnEntrySelects(new QueryException(self::CONNECTION, 'select ' . self::SECRET, [self::SECRET], new \PDOException('Down: ' . self::SECRET)));

        self::assertSame(1, $this->seal());
        self::assertSame('Sealing stopped with ' . QueryException::class . ".\n", $this->printed());
        self::assertReported('Sealing stopped with ' . QueryException::class . '.', SealFailedException::class);
        self::assertHoldsNoSecret($this->printed(), 'the output');
        self::assertHoldsNoSecret($this->handler->reports(), 'the reports');
        self::assertCount(0, $this->alarms);
    }

    /**
     * A failure of the anchorer itself is printed and reported by its class
     * alone, and fails the run.
     *
     * @return void
     */
    public function testAnAnchoringFailureIsReportedByItsClassAlone(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.batch', 'many');

        $this->bindAnchor(new RecordingAnchor);
        $this->storeEntries(1);

        self::assertSame(1, $this->seal());
        self::assertSame("Sealed 1 entries in 1 seals (sequences 1 to 1).\nAnchoring stopped with InvalidArgumentException.\n", $this->printed());
        self::assertReported('Sealing stopped with InvalidArgumentException.', SealFailedException::class);
    }

    /**
     * Anchoring runs even when sealing stops, so seals already committed are
     * still anchored.
     *
     * @return void
     */
    public function testAnchoringRunsEvenWhenSealingFails(): void
    {
        $this->storeEntries(1);
        $this->seal();

        $anchor = $this->bindAnchor(new RecordingAnchor);

        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->raiseOnEntrySelects(new \DomainException('The entries cannot be read.'));

        self::assertSame(1, $this->seal());
        self::assertSame("Sealing stopped with DomainException.\nAnchored 1 seals.\n", $this->printed());
        self::assertSame([1 => $this->seals()[0]['seal_digest']], $anchor->held());
    }

    /**
     * A run that finds the lock held does nothing and succeeds.
     *
     * @return void
     */
    public function testAHeldLockSkipsTheRun(): void
    {
        $this->storeEntries(1);

        $held = Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS);

        self::assertTrue($held->get());
        self::assertSame(0, $this->seal());
        self::assertSame("Another sealer holds the lock.\n", $this->printed());
        self::assertSame([], $this->seals());
    }

    /**
     * A store that cannot lock costs only the lock: the run seals without one.
     *
     * @return void
     */
    public function testACacheWithoutLocksRunsWithoutOne(): void
    {
        $this->bindCacheStore(\Mockery::mock(Store::class));
        $this->storeEntries(1);

        self::assertSame(0, $this->seal());
        self::assertSame("Sealed 1 entries in 1 seals (sequences 1 to 1).\n", $this->printed());
    }

    /**
     * Rows of `[how the cache fails]`: a default store that is not configured,
     * and a store whose lock throws.
     *
     * @return iterable<string, array{0: \Closure(self): void}>
     */
    public static function provideFailingCaches(): iterable
    {
        yield from [
            'an unconfigured store' => [static function (): void {
                app(ConfigRepository::class)->set('cache.default', 'audit-log-missing-store');
            }],
            'a lock that throws' => [static function (self $test): void {
                $store = \Mockery::mock(Store::class, LockProvider::class);

                $store->shouldReceive('lock')->andThrow(new \RuntimeException('The cache is down.'));

                $test->bindCacheStore($store);
            }],
        ];
    }

    /**
     * A cache that fails does not stop sealing: the run goes on without a lock,
     * reporting nothing.
     *
     * @param  \Closure(self): void  $failing
     * @return void
     */
    #[DataProvider('provideFailingCaches')]
    public function testACacheThatFailsDoesNotStopSealing(\Closure $failing): void
    {
        $failing($this);

        $this->storeEntries(1);

        self::assertSame(0, $this->seal());
        self::assertSame("Sealed 1 entries in 1 seals (sequences 1 to 1).\n", $this->printed());
        self::assertSame([], $this->handler->reports());
    }

    /**
     * The lock is held while the run seals and released after it, whether it
     * succeeded or failed.
     *
     * @return void
     */
    public function testTheLockIsReleased(): void
    {
        $this->storeEntries(1);

        $heldDuringTheRun = null;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use (&$heldDuringTheRun): void {
            if ($heldDuringTheRun !== null || !str_contains($query, EntrySettings::table())) {
                return;
            }

            $heldDuringTheRun = !Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS)->get();
        });

        self::assertSame(0, $this->seal());
        self::assertTrue($heldDuringTheRun);
        self::assertTrue(Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS)->get());

        Cache::lock(SealCommand::LOCK)->forceRelease();

        $this->raiseOnEntrySelects(new \DomainException('The entries cannot be read.'));

        self::assertSame(1, $this->seal());
        self::assertTrue(Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS)->get());
    }

    /**
     * A run that an error stops before it ends, here an output that can no
     * longer be written to, still releases the lock rather than leaving the
     * next runs to skip until it lapses.
     *
     * @return void
     */
    public function testTheLockIsReleasedWhenTheRunIsInterrupted(): void
    {
        $this->storeEntries(1);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $output = new class extends Output {
            /**
             * Refuse every write, as a closed pipe does.
             *
             * @param  string  $message
             * @param  bool  $newline
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            protected function doWrite(string $message, bool $newline): void
            {
                throw new \RuntimeException('The output is closed.');
            }
        };

        try {
            $kernel->call('audit-log:seal', [], $output);

            self::fail('The run was not interrupted.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The output is closed.', $exception->getMessage());
        }

        self::assertCount(1, $this->seals());
        self::assertTrue(Cache::lock(SealCommand::LOCK, SealCommand::LOCK_SECONDS)->get());
    }

    /**
     * Every attempt lost to a concurrent writer stops sealing with contention,
     * which is reported by its class and fails the run.
     *
     * @return void
     */
    public function testContentionIsReportedAndFails(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.max_attempts', 1);

        $this->storeEntries(1);

        $driver = new \PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');

        $driver->errorInfo = ['23000', 1062, ''];

        $this->raiseOnEntrySelects(new UniqueConstraintViolationException(self::CONNECTION, 'insert into checkpoints', [], $driver));

        self::assertSame(1, $this->seal());
        self::assertSame('Sealing stopped with ' . SealContentionException::class . ".\n", $this->printed());
        self::assertReported('Sealing stopped with ' . SealContentionException::class . '.', SealFailedException::class);
    }

    /**
     * A run inside a transaction on the storage connection seals nothing, says
     * why by class alone, and fails.
     *
     * @return void
     */
    public function testRefusesInsideATransaction(): void
    {
        $this->storeEntries(1);

        DB::connection(StorageConnection::name())->beginTransaction();

        self::assertSame(1, $this->seal());
        self::assertSame("Sealing stopped with LogicException.\n", $this->printed());
        self::assertReported('Sealing stopped with LogicException.', SealFailedException::class);
        self::assertSame([], $this->seals());
    }

    /**
     * A listener that fails hides nothing: its own exception is reported, as it
     * threw, the alarm's exception is still reported after it, and the run
     * still fails.
     *
     * @return void
     */
    public function testAListenerThatThrowsDoesNotHideTheFailure(): void
    {
        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (): void {
            throw new \RuntimeException('The listener failed.');
        });

        $this->bindAnchor((new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));
        $this->storeEntries(1);

        self::assertSame(1, $this->seal());
        self::assertCount(2, $this->handler->reports());
        self::assertSame('The listener failed.', $this->handler->reports()[0]->getMessage());
        self::assertInstanceOf(IntegrityCheckFailedException::class, $this->handler->reports()[1]);
    }

    /**
     * A reporter that fails too stops nothing: the error is printed, anchoring
     * still runs, and the run still fails.
     *
     * @return void
     */
    public function testABrokenReporterStillPrintsAndFails(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler(throwsOnReport: true));

        $this->storeEntries(1);
        $this->raiseOnEntrySelects(new \DomainException('The entries cannot be read.'));
        $this->bindAnchor(new RecordingAnchor);

        self::assertSame(1, $this->seal());
        self::assertSame("Sealing stopped with DomainException.\nAnchored 0 seals.\n", $this->printed());
    }

    /**
     * Nothing printed, dispatched or reported holds a value of an entry or of a
     * failure, across a skipped entry, a conflict and a stopped run.
     *
     * @return void
     */
    public function testPrintsNoValueOfAnEntry(): void
    {
        $id = $this->storeSecretEntry('2026-11-01 12:00:00');

        $this->storeSecretEntry('2026-11-01 12:00:01');

        self::assertTrue(self::holdsText(DB::connection(StorageConnection::name())->table(EntrySettings::table())->get()->all(), self::SECRET), 'The secret was not planted.');

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->update(['hmac' => str_repeat('z', 64)]);

        $this->bindAnchor((new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));

        self::assertSame(1, $this->seal());

        $printed = $this->printed();

        $this->storeSecretEntry('2026-11-01 12:30:00');
        $this->raiseOnEntrySelects(new \DomainException('Down: ' . self::SECRET));

        self::assertSame(1, $this->seal());
        self::assertHoldsNoSecret($printed . $this->printed(), 'the output');
        self::assertHoldsNoSecret($this->alarms->getArrayCopy(), 'the events');
        self::assertHoldsNoSecret($this->handler->reports(), 'the reports');
    }

    /**
     * The command is named `audit-log:seal` and takes `--sweep` alone.
     *
     * @return void
     */
    public function testTheSignatureIsPinned(): void
    {
        $command = new SealCommand;

        self::assertSame('audit-log:seal', $command->getName());
        self::assertSame(['sweep'], array_keys($command->getDefinition()->getOptions()));
        self::assertSame([], $command->getDefinition()->getArguments());
        self::assertSame('audit-log:seal', SealCommand::LOCK);
        self::assertSame(900, SealCommand::LOCK_SECONDS);
    }

    /**
     * Bind a cache whose default store is the one given.
     *
     * @param  \Illuminate\Contracts\Cache\Store  $store
     * @return void
     */
    private function bindCacheStore(Store $store): void
    {
        $factory = \Mockery::mock(CacheFactory::class);

        $factory->shouldReceive('store')->andReturn(new CacheRepository($store));

        app()->instance(CacheFactory::class, $factory);
    }

    /**
     * Run the command with the options given and return its exit code.
     *
     * @param  array<string, bool>  $options
     * @return int
     */
    private function seal(array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:seal', $options);
    }

    /**
     * What the last run printed.
     *
     * @return string
     */
    private function printed(): string
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->output();
    }

    /**
     * Bind the anchor every run anchors with.
     *
     * @template T of \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor
     *
     * @param  T  $anchor
     * @return T
     */
    private function bindAnchor(CheckpointAnchor $anchor): CheckpointAnchor
    {
        app()->instance(CheckpointAnchor::class, $anchor);

        return $anchor;
    }

    /**
     * Change columns of the first seal, as someone who can write to the
     * database could.
     *
     * @param  array<string, string>  $columns
     * @return void
     */
    private function editFirstSeal(array $columns): void
    {
        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('id', $this->seals()[0]['id'])->update($columns);
    }

    /**
     * Raise the failure from every selection of entries from now on.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function raiseOnEntrySelects(#[\SensitiveParameter] \Throwable $failure): void
    {
        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($failure): void {
            if (str_starts_with(strtolower($query), 'select') && str_contains($query, EntrySettings::table())) {
                throw $failure;
            }
        });
    }

    /**
     * Store a record whose properties hold the planted secret, recorded at the
     * time given, and return its id.
     *
     * @param  string  $recordedAt
     * @return string
     */
    private function storeSecretEntry(string $recordedAt): string
    {
        $instant   = (new CarbonImmutable($recordedAt, 'UTC'))->format('Y-m-d\TH:i:s.u\Z');
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured(['note' => self::SECRET], occurredAt: $instant));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }

    /**
     * Assert that exactly one event was dispatched, with the maps, the finding
     * and the id given.
     *
     * @param  array<string, int>  $integrity
     * @param  array<string, int>  $anchoring
     * @param  string  $finding
     * @param  ?string  $firstBadId
     * @return void
     */
    private function assertSingleAlarm(array $integrity, array $anchoring, string $finding, ?string $firstBadId): void
    {
        self::assertCount(1, $this->alarms);

        $alarm = $this->alarms->getArrayCopy()[0] ?? null;

        self::assertInstanceOf(IntegrityCheckFailed::class, $alarm);
        self::assertSame('seal', $alarm->command);
        self::assertSame($integrity, $alarm->integrity);
        self::assertSame($anchoring, $alarm->anchoring);
        self::assertSame($finding, $alarm->finding);
        self::assertSame($firstBadId, $alarm->firstBadId);
        self::assertNull($alarm->head);
        self::assertNull($alarm->remoteHead);
        self::assertFalse($alarm->complete);
    }

    /**
     * Assert that exactly one exception of the class was reported, with the
     * message given and no previous.
     *
     * @param  string  $message
     * @param  class-string<\Throwable>  $class
     * @return void
     */
    private function assertReported(string $message, string $class = IntegrityCheckFailedException::class): void
    {
        $reports = $this->handler->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf($class, $reports[0]);
        self::assertSame($message, $reports[0]->getMessage());
        self::assertNull($reports[0]->getPrevious());
    }

    /**
     * The whole integrity map, the counts given and zero for the rest.
     *
     * @param  array<string, int>  $counts
     * @return array<string, int>
     */
    private static function integrity(array $counts): array
    {
        return array_merge(array_fill_keys(self::INTEGRITY, 0), $counts);
    }

    /**
     * The whole anchoring map, the counts given and zero for the rest.
     *
     * @param  array<string, int>  $counts
     * @return array<string, int>
     */
    private static function anchoring(array $counts): array
    {
        return array_merge(array_fill_keys(self::ANCHORING, 0), $counts);
    }
}
