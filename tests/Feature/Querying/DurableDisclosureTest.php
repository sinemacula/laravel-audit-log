<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Querying\AccessRecorder;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;

/**
 * Feature tests for the rule that nothing a read finds leaves the package until
 * its record is durable, through the read API alone: no row, count or
 * verification result returned when the record fails; a read refused before
 * anything is queried while a transaction is open on the storage connection, or
 * in outbox mode on the outbox's own connection or the storage connection; a
 * read refused on a store that is not durable; and a failed record spilled,
 * with its disclosure, and reported once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadGate::class)]
#[CoversClass(TrailReader::class)]
#[CoversClass(AccessRecorder::class)]
final class DurableDisclosureTest extends TestCase
{
    use CapturesLogLines, InteractsWithOutbox, ReadsTheTrail;

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /** @var list<string> The files an export wrote, removed when the test ends. */
    private array $files = [];

    /**
     * Bind the read path, report to a recording handler, and capture every line
     * logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->captureLogLines();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Roll back any transaction a test left open, put the outbox back, and
     * remove the files an export wrote.
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

        $this->removeMovedOutbox();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * No row is returned when the read's record cannot be written: the rows
     * were found, but the read is refused as unrecorded, carrying nothing.
     *
     * @return void
     */
    public function testNoRowIsReturnedWhenTheReadRecordFails(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->captureQueries();

        $refusal = $this->refusalOf(fn () => $this->trail()->cursorPaginate());

        self::assertInstanceOf(AuditReadRefusedException::class, $refusal);
        self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $refusal->getMessage());
        self::assertNull($refusal->getPrevious());
        self::assertCount(1, $this->entryReads());
    }

    /**
     * No count is returned when the count's record cannot be written.
     *
     * @return void
     */
    public function testNoCountIsReturnedWhenItsRecordFails(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->trail()->count();
    }

    /**
     * Rows of `[terminal call]`: a page and a count.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)}>
     */
    public static function provideTerminals(): iterable
    {
        yield from [
            'a page'  => [static fn (AuditTrail $trail): TrailPage => $trail->cursorPaginate()],
            'a count' => [static fn (AuditTrail $trail): int => $trail->count()],
        ];
    }

    /**
     * A read inside a transaction on the storage connection is refused, naming
     * the connection, before the policy is asked or any statement runs, and
     * leaves no record.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $terminal
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testAReadInsideATransactionIsRefusedBeforeAnyQuery(\Closure $terminal): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(2);

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefusedBeforeAnyQuery(AuditReadRefusedException::inTransaction(self::CONNECTION), $policy, $terminal);
    }

    /**
     * In outbox mode a read inside a transaction on the outbox's own connection
     * is refused, naming that connection, before the policy is asked or any
     * statement runs, and leaves no outbox row.
     *
     * @return void
     */
    public function testInOutboxModeAReadInsideAnOutboxTransactionIsRefused(): void
    {
        $this->outboxOnItsOwnConnection();

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(2);

        $this->outboxConnection()->beginTransaction();

        $refusal = AuditReadRefusedException::inTransaction(self::MOVED_OUTBOX_CONNECTION);

        $this->assertRefusedBeforeAnyQuery($refusal, $policy, static fn (AuditTrail $trail): TrailPage => $trail->cursorPaginate());

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * In outbox mode a read inside a transaction on the storage connection,
     * which the read reads, is refused too, though the outbox is on another
     * connection.
     *
     * @return void
     */
    public function testInOutboxModeAReadInsideATransactionOnTheStorageConnectionIsRefused(): void
    {
        $this->outboxOnItsOwnConnection();

        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(2);

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefusedBeforeAnyQuery(AuditReadRefusedException::inTransaction(self::CONNECTION), $policy, static fn (AuditTrail $trail): int => $trail->count());

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A read with the log store bound, which is not durable, is refused naming
     * the store, before the policy is asked or any statement runs, and no line
     * is logged.
     *
     * @return void
     */
    public function testAReadOnALogStoreIsRefused(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntries(2);

        app()->instance(AuditStore::class, new LogAuditStore(app(LogManager::class), new NdjsonFormatter));

        $refusal = AuditReadRefusedException::notDurable(LogAuditStore::class);

        $this->assertRefusedBeforeAnyQuery($refusal, $policy, static fn (AuditTrail $trail): TrailPage => $trail->cursorPaginate());

        self::assertSame([], $this->logStoreLines());
    }

    /**
     * A read whose record fails is spilled once, the whole bundle with the
     * disclosure of what it found, and the failure is reported once as the
     * store's sanitised failure.
     *
     * @return void
     */
    public function testTheFailureIsSpilledAndReportedOnce(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $refusal = $this->refusalOf(fn () => $this->trail()->cursorPaginate());
        $lines   = $this->spillLines();
        $reports = $this->reporter?->reports() ?? [];

        self::assertNotNull($refusal);
        self::assertCount(1, $lines);
        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);

        $spilled = app(EnvelopeCodec::class)->decode((string) SpillReader::extract($lines[0]));

        self::assertSame(['audit_log.trail_read', 'success'], [$spilled->record->event, $spilled->record->outcome]);
        self::assertSame([ArtifactKind::DISCLOSURE->value, 2], [$spilled->record->attachment?->kind, $spilled->record->attachment?->memberCount]);
        self::assertSame([], $this->readRecords());
    }

    /**
     * No verification result is returned when the verification's record cannot
     * be written: the export verifies while its record can be, and is refused
     * as unrecorded once it cannot.
     *
     * @return void
     */
    public function testNoVerificationResultIsReturnedWhenItsRecordFails(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $path = $this->exportPath();

        $this->trail()->export($path);

        self::assertTrue($this->trail()->verifyExport($path)->isVerified());

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->trail()->verifyExport($path);
    }

    /**
     * The trail, in the `finance` category the seeded entries are in, read for
     * the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
    }

    /**
     * Put the trail in outbox mode with the outbox on a connection of its own.
     *
     * @return void
     */
    private function outboxOnItsOwnConnection(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $this->moveOutboxToItsOwnConnection();
    }

    /**
     * A path of the test's own for an export, removed with its bundle when the
     * test ends.
     *
     * @return string
     */
    private function exportPath(): string
    {
        $path = sys_get_temp_dir() . '/' . uniqid('audit-durable-export-', true) . '.ndjson';

        array_push($this->files, $path, $path . '.manifest.json');

        return $path;
    }

    /**
     * The refusal the read is refused with, or `null` when it is not.
     *
     * @param  \Closure(): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $read
     * @return ?\SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refusalOf(\Closure $read): ?AuditReadRefusedException
    {
        try {
            $read();
        } catch (AuditReadRefusedException $refusal) {
            return $refusal;
        }

        return null;
    }

    /**
     * Assert the terminal call on the trail is refused as expected, before the
     * policy is asked or any statement runs on any connection, and that nothing
     * is reported and no read is recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException  $expected
     * @param  \Tests\Fixtures\Querying\ClosurePolicy  $policy
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $terminal
     * @return void
     */
    private function assertRefusedBeforeAnyQuery(AuditReadRefusedException $expected, ClosurePolicy $policy, \Closure $terminal): void
    {
        $this->captureQueries();

        $refusal = $this->refusalOf(fn (): int|TrailPage => $terminal($this->trail()));

        self::assertInstanceOf(AuditReadRefusedException::class, $refusal);
        self::assertSame($expected->getMessage(), $refusal->getMessage());
        self::assertNull($refusal->getPrevious());
        self::assertSame([], $this->capturedQueries());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->reporter?->reports());

        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        self::assertSame([], $this->readRecords());
    }
}
