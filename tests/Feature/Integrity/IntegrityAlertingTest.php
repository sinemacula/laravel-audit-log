<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for how an integrity failure reaches the application: sealing
 * and verification alike dispatch one payload-free `IntegrityCheckFailed`,
 * whose maps list every status in order, and report an
 * `IntegrityCheckFailedException` that carries no other exception, on a failure
 * and on a run that stopped; a listener sees the counts and the heads; and a
 * listener or a reporter that fails hides neither the exit code nor the report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifyCommand::class)]
#[CoversClass(SealCommand::class)]
#[CoversClass(IntegrityCheckFailed::class)]
#[CoversClass(IntegrityCheckFailedException::class)]
final class IntegrityAlertingTest extends TestCase
{
    use SealsEntries;

    /** @var string When the log is sealed. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When the log is verified: past the anchoring grace of every seal. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string The digest a disagreeing anchor holds instead of the local one. */
    private const string OTHER_DIGEST = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var list<string> The event's public properties, in order. */
    private const array PROPERTIES = ['command', 'integrity', 'anchoring', 'finding', 'firstBadId', 'head', 'remoteHead', 'complete'];

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The handler every report reaches. */
    private RecordingExceptionHandler $handler;

    /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> Every integrity event dispatched. */
    private \ArrayObject $alarms;

    /** @var \ArrayObject<int, \Throwable> The failure every selection of a seal's members raises, while one is held. */
    private \ArrayObject $failure;

    /**
     * Register both commands with the console kernel, bind no anchor and
     * nothing pruned, and record every report and every integrity event.
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
        $kernel->registerCommand(new VerifyCommand);

        $this->handler = new RecordingExceptionHandler;
        $this->alarms  = new \ArrayObject;

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(ExceptionHandler::class, $this->handler);

        /** @var \ArrayObject<int, \Throwable> $failure */
        $failure       = new \ArrayObject;
        $alarms        = $this->alarms;
        $this->failure = $failure;

        // While a test holds a failure, every selection of a seal's members
        // with their entries raises it
        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($failure): void {
            $raised = $failure->getArrayCopy()[0] ?? null;

            if ($raised instanceof \Throwable && self::readsMembersOfASeal($query)) {
                throw $raised;
            }
        });

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event);
        });
    }

    /**
     * The event's public properties are exactly the eight, each typed as a
     * scalar, `null` or an array, and each array a map of counts by status,
     * from a failing verification, a stopped one and a seal conflict.
     *
     * @return void
     */
    public function testTheEventIsPayloadFree(): void
    {
        $properties = (new \ReflectionClass(IntegrityCheckFailed::class))->getProperties(\ReflectionProperty::IS_PUBLIC);
        $types      = array_map(static fn (\ReflectionProperty $property): string => (string) $property->getType(), $properties);

        self::assertSame(self::PROPERTIES, array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $properties));
        self::assertSame(['string', 'array', 'array', '?string', '?string', '?int', '?int', 'bool'], $types);

        foreach ([$this->failingVerification(), $this->stoppedVerification(), $this->sealConflict()] as $event) {
            self::assertTrue(self::isCounts($event->integrity), 'The integrity map holds more than counts.');
            self::assertTrue(self::isCounts($event->anchoring), 'The anchoring map holds more than counts.');
        }
    }

    /**
     * Both maps list every status, in enum order, from a failing verification,
     * a stopped one and a seal conflict alike.
     *
     * @return void
     */
    public function testEveryMapHoldsEveryStatus(): void
    {
        $integrity = array_map(static fn (IntegrityStatus $status): string => $status->value, IntegrityStatus::cases());
        $anchoring = array_map(static fn (AnchorStatus $status): string => $status->value, AnchorStatus::cases());

        foreach (['verification' => $this->failingVerification(), 'stopped' => $this->stoppedVerification(), 'seal' => $this->sealConflict()] as $run => $event) {
            self::assertSame($integrity, array_keys($event->integrity), sprintf('The %s event\'s integrity map is not whole.', $run));
            self::assertSame($anchoring, array_keys($event->anchoring), sprintf('The %s event\'s anchoring map is not whole.', $run));
        }
    }

    /**
     * Every exception reported beside the event carries no other exception,
     * from a failing verification, a stopped one and a seal conflict.
     *
     * @return void
     */
    public function testTheReportedExceptionHasNoPrevious(): void
    {
        $this->failingVerification();
        $this->stoppedVerification();
        $this->sealConflict();

        $reports = $this->handler->reports();

        self::assertCount(3, $reports);

        foreach ($reports as $report) {
            self::assertInstanceOf(IntegrityCheckFailedException::class, $report);
            self::assertNull($report->getPrevious());
        }
    }

    /**
     * A listener sees the counts of a failing verification, its first finding
     * and the id it was found at, the local head and the anchor's, and that the
     * run covered the whole log. The anchor holds the head's digest and no
     * receipt is kept, so every seal is unanchored on every engine.
     *
     * @return void
     */
    public function testAListenerSeesTheCountsAndHead(): void
    {
        $this->sealSeals(2);

        $head     = $this->seals()[1];
        $tampered = $this->membersOf((string) $head['id'])[0];

        $this->bindAnchor((new RecordingAnchor)->holdInstead(2, (string) $head['seal_digest']));
        $this->editEntry($tampered);

        self::assertSame(1, $this->verify());

        $event = $this->onlyAlarm();

        self::assertSame('verify', $event->command);
        self::assertSame(['valid' => 1, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1], $event->integrity);
        self::assertSame(['anchored' => 2, 'unanchored' => 0, 'unavailable' => 0, 'contradicted' => 0], $event->anchoring);
        self::assertSame(['entry_hmac', $tampered, 2, 2, true], [$event->finding, $event->firstBadId, $event->head, $event->remoteHead, $event->complete]);
    }

    /**
     * A seal conflict raises the same event, from the seal command: tampered
     * and contradicted once, the conflict's finding at the seal, and no head.
     *
     * @return void
     */
    public function testASealConflictRaisesTheSameEvent(): void
    {
        $event = $this->sealConflict();

        self::assertSame('seal', $event->command);
        self::assertSame(['valid' => 0, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1], $event->integrity);
        self::assertSame(['anchored' => 0, 'unanchored' => 0, 'unavailable' => 0, 'contradicted' => 1], $event->anchoring);
        $seal = $this->seals()[0];

        self::assertSame(['anchor_conflict', $seal['id'], null, null, false], [$event->finding, $event->firstBadId, $event->head, $event->remoteHead, $event->complete]);
    }

    /**
     * A listener that throws hides nothing: its own exception is reported, as
     * it threw, and a failing verification still exits 1 and is still reported
     * after it, and so is a stopped one.
     *
     * @return void
     */
    public function testAListenerThatThrowsDoesNotHideTheFailure(): void
    {
        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (): void {
            throw new \RuntimeException('The listener failed.');
        });

        $this->failingVerification();
        $this->stoppedVerification();

        $reports = $this->handler->reports();

        self::assertCount(4, $reports);
        self::assertSame('The listener failed.', $reports[0]->getMessage());
        self::assertStringStartsWith('The audit log\'s integrity check failed (verify)', $reports[1]->getMessage());
        self::assertSame('The listener failed.', $reports[2]->getMessage());
        self::assertSame('The audit log\'s verify run stopped with DomainException; its integrity was not established.', $reports[3]->getMessage());
    }

    /**
     * A reporter that throws hides nothing either: the verdict is printed, the
     * event dispatched and the run still exits 1.
     *
     * @return void
     */
    public function testAReporterThatThrowsDoesNotHideTheFailure(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler(throwsOnReport: true));

        $this->sealSeals(1);
        $this->editEntry($this->membersOf((string) $this->seals()[0]['id'])[0]);

        self::assertSame(1, $this->verify());
        self::assertStringEndsWith("Verification failed.\n", $this->kernel()->output());

        $this->failure->append(new \DomainException('The members cannot be read.'));

        self::assertSame(1, $this->verify());
        self::assertSame("Verification stopped with DomainException.\n", $this->kernel()->output());
        self::assertCount(2, $this->alarms);
    }

    /**
     * Seal the log, tamper with an entry and verify it, asserting the run
     * failed, and return the one event it dispatched.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function failingVerification(): IntegrityCheckFailed
    {
        $this->clearLog();
        $this->sealSeals(1);
        $this->editEntry($this->membersOf((string) $this->seals()[0]['id'])[0]);

        self::assertSame(1, $this->verify());

        return $this->onlyAlarm();
    }

    /**
     * Seal the log and verify it while its members cannot be read, asserting
     * the run failed, and return the one event it dispatched.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function stoppedVerification(): IntegrityCheckFailed
    {
        $this->clearLog();
        $this->sealSeals(1);

        $this->failure->append(new \DomainException('The members cannot be read.'));

        self::assertSame(1, $this->verify());

        return $this->onlyAlarm();
    }

    /**
     * Seal an entry while the anchor holds another digest for its seal,
     * asserting the run failed, and return the one event it dispatched.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function sealConflict(): IntegrityCheckFailed
    {
        $this->clearLog();
        $this->bindAnchor((new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));
        $this->storeEntries(1);

        app()->instance(Clock::class, FrozenClock::at(self::SEALED_AT));

        self::assertSame(1, $this->kernel()->call('audit-log:seal'));

        $this->bindAnchor(new NullAnchor);

        return $this->onlyAlarm();
    }

    /**
     * Store and seal the number of seals, two entries each, recorded a minute
     * apart, through the seal command, which anchors each seal when an anchor
     * is bound.
     *
     * @param  int  $count
     * @return void
     */
    private function sealSeals(int $count): void
    {
        app()->instance(Clock::class, FrozenClock::at(self::SEALED_AT));

        for ($seal = 0; $seal < $count; $seal++) {
            $this->storeEntries(2, sprintf('2026-11-01 12:%02d:00.000000', $seal));

            self::assertSame(0, $this->kernel()->call('audit-log:seal'), 'The log could not be sealed.');
        }
    }

    /**
     * Verify the whole log once the grace of every seal has passed, and return
     * the exit code.
     *
     * @return int
     */
    private function verify(): int
    {
        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        return $this->kernel()->call('audit-log:verify');
    }

    /**
     * Delete every entry, seal, member and progress row, and stop raising on
     * the members of a seal, so each run of a test starts from an empty log.
     *
     * @return void
     */
    private function clearLog(): void
    {
        $this->failure->exchangeArray([]);

        $connection = DB::connection(StorageConnection::name());

        foreach ([IntegrityTables::membersTable(), IntegrityTables::checkpointsTable(), IntegrityTables::stateTable(), EntrySettings::table()] as $table) {
            $connection->table($table)->delete();
        }
    }

    /**
     * Change the stored event of the entry, so it no longer matches its HMAC.
     *
     * @param  string  $id
     * @return void
     */
    private function editEntry(string $id): void
    {
        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->update(['event' => 'invoice.voided']);
    }

    /**
     * Bind the anchor every run anchors and verifies with.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @return void
     */
    private function bindAnchor(CheckpointAnchor $anchor): void
    {
        app()->instance(CheckpointAnchor::class, $anchor);
    }

    /**
     * The console kernel.
     *
     * @return \Illuminate\Contracts\Console\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel;
    }

    /**
     * The one event dispatched since the last was taken, which is taken.
     *
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private function onlyAlarm(): IntegrityCheckFailed
    {
        self::assertCount(1, $this->alarms);

        $alarm = $this->alarms->getArrayCopy()[0] ?? null;

        self::assertInstanceOf(IntegrityCheckFailed::class, $alarm);

        $this->alarms->exchangeArray([]);

        return $alarm;
    }

    /**
     * Whether the statement reads the members of one seal with their entries,
     * as verifying a segment does.
     *
     * @param  string  $query
     * @return bool
     */
    private static function readsMembersOfASeal(string $query): bool
    {
        return str_contains($query, IntegrityTables::membersTable()) && str_contains($query, 'checkpoint_id') && str_contains($query, EntrySettings::table());
    }

    /**
     * Whether the map holds only counts, by name.
     *
     * @param  array<array-key, int>  $map
     * @return bool
     */
    private static function isCounts(array $map): bool
    {
        return array_filter(array_keys($map), is_string(...)) === array_keys($map) && array_filter($map, is_int(...)) === $map;
    }
}
