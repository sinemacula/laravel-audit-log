<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\FailsEntryReads;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\RevealingFieldReader;
use Tests\TestCase;

/**
 * Feature tests for the reader of the trail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
final class TrailReaderTest extends TestCase
{
    use FailsEntryReads, InteractsWithAuditStore, ReadsTheTrail, SeedsArtifacts;

    /** @var string A second connection, on an in-memory SQLite database, configured as the storage connection. */
    private const string READING = 'audit_reading';

    /** @var list<string> The shipped migrations of the tables a read and its record need. */
    private const array MIGRATIONS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php',
    ];

    /** @var string The id of the key an owner's fragments are sealed under. */
    private const string OWNER_KEY = '0192f5a0-7c1e-7000-8000-0000000000f1';

    /** @var string The id of the key another owner's fragments are sealed under. */
    private const string OTHER_OWNER_KEY = '0192f5a0-7c1e-7000-8000-0000000000f2';

    /** @var string A value only a binding of the failed statement holds. */
    private const string SECRET = 'app:kept-out-of-every-refusal';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Bind the read path and report to a recording handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Put the entries table back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeProbeTable();

        parent::tearDown();
    }

    /**
     * The read and its record use the storage connection, not the default.
     *
     * @return void
     */
    public function testItReadsOnTheStorageConnection(): void
    {
        $this->storeOn(self::READING);
        $this->allowEverything();

        $id = $this->seedEntry();

        $this->captureQueries();

        $page    = $this->financeTrail()->cursorPaginate();
        $selects = array_values(array_filter($this->capturedQueries(), static fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select')));

        self::assertSame([$id], self::idsOf($page));
        self::assertCount(1, $selects);
        self::assertSame(self::READING, $selects[0]->connectionName);
        self::assertCount(1, $this->readRecords('audit_log.trail_read'));
        self::assertSame(0, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * A page of fifty is one statement, with a cursor to the next.
     *
     * @return void
     */
    public function testAPageOfFiftyIsOneStatement(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(60);

        $this->captureQueries();

        $page = $this->financeTrail()->cursorPaginate(50);

        self::assertCount(1, $this->entryReads());
        self::assertSame(array_slice(array_reverse($ids), 0, 50), self::idsOf($page));
        self::assertTrue($page->hasMore());
    }

    /**
     * The policy gets the viewer as given and each terminal call's purpose.
     *
     * @return void
     */
    public function testThePolicyIsGivenTheOriginalViewerAndThePurpose(): void
    {
        $viewer = new GenericUser(['id' => 'user-7']);
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $trail  = app(AuditTrail::class)->visibleTo($viewer);

        $trail->cursorPaginate();
        $trail->count();

        self::assertSame([[$viewer, ReadPurpose::READ], [$viewer, ReadPurpose::COUNT]], $policy->asked());
    }

    /**
     * The policy runs inside the read window, so a read it makes is refused.
     *
     * @return void
     */
    public function testThePolicyRunsInsideTheReadWindow(): void
    {
        $inside = [];

        $this->usePolicy(static function () use (&$inside): AccessScope {
            $inside[] = app(ReadGuard::class)->isActive();

            return AccessScope::all();
        });

        $this->financeTrail()->cursorPaginate();
        $this->financeTrail()->count();

        self::assertSame([true, true], $inside);
        self::assertFalse(app(ReadGuard::class)->isActive());
    }

    /**
     * A read inside a read is refused by the gate before the policy is asked.
     *
     * @return void
     */
    public function testTheGateRefusesBeforeThePolicy(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        $refusal = app(ReadGuard::class)->during(function (): ?AuditReadRefusedException {
            try {
                $this->financeTrail()->count();
            } catch (AuditReadRefusedException $refusal) {
                return $refusal;
            }

            return null;
        });

        self::assertSame(AuditReadRefusedException::reentrant()->getMessage(), $refusal?->getMessage());
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->capturedQueries());
    }

    /**
     * Rows of `[terminal call, its empty result]`: a page and a count.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage), 1: int}>
     */
    public static function provideTerminals(): iterable
    {
        yield from [
            'a page'  => [static fn (AuditTrail $trail): int => count($trail->cursorPaginate()->entries), 0],
            'a count' => [static fn (AuditTrail $trail): int => $trail->count(), 0],
        ];
    }

    /**
     * A denied scope reads nothing, with no statement on the entries table.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): int  $terminal
     * @param  int  $empty
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testADeniedScopeMakesNoQuery(\Closure $terminal, int $empty): void
    {
        $this->seedEntries(2);
        $this->captureQueries();

        self::assertSame($empty, $terminal($this->financeTrail()));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A tenant filter outside the scope reads nothing, with no statement.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): int  $terminal
     * @param  int  $empty
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testADisjointTenantFilterMakesNoQuery(\Closure $terminal, int $empty): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));
        $this->seedEntries(2);
        $this->captureQueries();

        self::assertSame($empty, $terminal($this->financeTrail()->forTenant(Reference::of('organisation', 'org_02'))));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A category filter outside the scope reads nothing, with no statement.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Querying\AuditTrail): int  $terminal
     * @param  int  $empty
     * @return void
     */
    #[DataProvider('provideTerminals')]
    public function testADisjointCategoryFilterMakesNoQuery(\Closure $terminal, int $empty): void
    {
        $this->usePolicy(static fn (): AccessScope => AccessScope::all()->onlyCategories('finance'));
        $this->seedEntries(2);
        $this->captureQueries();

        self::assertSame($empty, $terminal($this->financeTrail()->inCategory('hr')));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A denied read is recorded as `denied` with `no_scope`, returning nothing.
     *
     * @return void
     */
    public function testADeniedReadIsRecordedAsADenial(): void
    {
        $this->seedEntries(2);

        $page = $this->financeTrail()->cursorPaginate(10);

        self::assertSame([[], null, 10], [$page->entries, $page->nextCursor, $page->perPage]);
        self::assertSame(0, $this->financeTrail()->count());

        $records = $this->readRecords();

        self::assertSame(['audit_log.trail_read', 'audit_log.trail_counted'], array_column($records, 'event'));

        foreach ($records as $record) {
            self::assertSame(['denied', 'no_scope'], [$record['outcome'], $record['reason']]);
            self::assertSame(0, self::propertiesOf($record)['returned']);
            self::assertSame(self::termsOf(null, AccessScope::none())->scopeFingerprint, self::propertiesOf($record)['scope_fingerprint']);
        }
    }

    /**
     * A disjoint read is recorded as a success that returned nothing.
     *
     * @return void
     */
    public function testADisjointReadIsRecordedAsASuccessOfNone(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));
        $this->seedEntries(2);

        $page = $this->financeTrail()->forTenant(Reference::of('organisation', 'org_02'))->cursorPaginate();

        self::assertSame([], $page->entries);

        $record = $this->readRecords('audit_log.trail_read')[0];

        self::assertSame(['success', null, 0], [$record['outcome'], $record['reason'], self::propertiesOf($record)['returned']]);
        self::assertSame([], $this->disclosureOf(self::idOf($record))['members']);
    }

    /**
     * A throwing policy is recorded as `policy_failed` and rethrown unchanged.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAThrowingPolicyIsRecordedAsAFailureAndRethrown(): void
    {
        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): never => throw $thrown);

        foreach ([fn () => $this->financeTrail()->cursorPaginate(), fn () => $this->financeTrail()->count()] as $terminal) {
            try {
                $terminal();

                self::fail('Expected the policy\'s exception.');
            } catch (\RuntimeException $caught) {
                self::assertSame($thrown, $caught);
            }
        }

        $records = $this->readRecords();

        self::assertSame(['audit_log.trail_read', 'audit_log.trail_counted'], array_column($records, 'event'));

        foreach ($records as $record) {
            self::assertSame(['failure', 'policy_failed'], [$record['outcome'], $record['reason']]);
            self::assertNull(self::propertiesOf($record)['scope_fingerprint']);
            self::assertNull($record['tenant_type']);
        }
    }

    /**
     * A failure whose record fails is still thrown, and the failure reported.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAFailureWhoseRecordFailsIsStillThrown(): void
    {
        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): never => throw $thrown);
        $this->pointAtProbeTable();

        try {
            $this->financeTrail()->count();

            self::fail('Expected the policy\'s exception.');
        } catch (\RuntimeException $caught) {
            self::assertSame($thrown, $caught);
        }

        $reports = array_map(static fn (\Throwable $report): string => $report->getMessage(), $this->reporter?->reports() ?? []);

        self::assertContains(AuditReadRefusedException::unrecorded()->getMessage(), $reports);
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A success whose record cannot be written is refused as unrecorded.
     *
     * @return void
     */
    public function testASuccessWhoseRecordFailsReturnsNothing(): void
    {
        $this->allowEverything();
        $this->pointAtProbeTable();

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->financeTrail()->cursorPaginate();
    }

    /**
     * A failing query is recorded and refused, naming only the failing class.
     *
     * @return void
     */
    public function testAQueryFailureIsRecordedAsAFailureAndRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->failEntryReads();

        foreach ([fn () => $this->financeTrail()->cursorPaginate(), fn () => $this->financeTrail()->count()] as $terminal) {
            try {
                $terminal();

                self::fail('Expected the read to be refused.');
            } catch (AuditReadRefusedException $refusal) {
                self::assertSame(AuditReadRefusedException::failed(QueryException::class)->getMessage(), $refusal->getMessage());
            }
        }

        $this->failEntryReads = false;

        $records = $this->readRecords();

        self::assertSame(['audit_log.trail_read', 'audit_log.trail_counted'], array_column($records, 'event'));

        foreach ($records as $record) {
            self::assertSame(['failure', 'query_failed', 0], [$record['outcome'], $record['reason'], self::propertiesOf($record)['returned']]);
            self::assertSame(self::termsOf(null, AccessScope::all())->scopeFingerprint, self::propertiesOf($record)['scope_fingerprint']);
        }
    }

    /**
     * A row that cannot be shown is recorded as `format_failed` and refused.
     *
     * @return void
     */
    public function testAFormattingFailureIsRecordedAsAFailureAndRefused(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(2);

        $this->corrupt($ids[1]);

        try {
            $this->financeTrail()->cursorPaginate();

            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::failed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }

        $record = $this->readRecords('audit_log.trail_read')[0];

        self::assertSame(['failure', 'format_failed', 0], [$record['outcome'], $record['reason'], self::propertiesOf($record)['returned']]);
        self::assertSame([], $this->disclosureOf(self::idOf($record))['members']);
    }

    /**
     * A refused cursor is recorded as `cursor_rejected` and thrown uniformly.
     *
     * @return void
     */
    public function testARefusedCursorIsRecordedAndThrown(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->captureQueries();

        $this->expectExceptionObject(InvalidCursorException::refused());

        try {
            $this->financeTrail()->cursorPaginate(10, 'v1.bm90.YQ.YQ');
        } finally {
            self::assertSame([], $this->entryReads());

            $record     = $this->readRecords('audit_log.trail_read')[0];
            $properties = self::propertiesOf($record);

            self::assertSame(['denied', 'cursor_rejected', 'cursor', 0], [$record['outcome'], $record['reason'], $properties['page'], $properties['returned']]);
            self::assertNull($this->disclosureOf(self::idOf($record))['page']);
        }
    }

    /**
     * A cursor issued for another page size is refused.
     *
     * @return void
     */
    public function testACursorOfAnotherReadIsRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->financeTrail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);

        $this->expectExceptionObject(InvalidCursorException::refused());

        $this->financeTrail()->cursorPaginate(3, $cursor);
    }

    /**
     * A revealing page asks the reader once and records its disclosure counts.
     *
     * @return void
     */
    public function testARevealingPageRecordsItsDisclosureCounts(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => '4242', 'properties.pin' => FieldState::ERASED]);

        app()->instance(FieldReader::class, $reader);

        $this->revealEverything();

        $card     = ['properties' => ['card' => ['v' => 1, 'k' => 'key_42', 'c' => 'Y2FyZA']]];
        $pin      = ['properties' => ['pin' => ['v' => 1, 'k' => 'key_42', 'c' => 'cGlu']]];
        $tampered = $this->seedEntry($card, '2026-11-01T11:00:00.000000Z');

        $this->seedEntry($pin, '2026-11-01T11:00:01.000000Z');
        $this->seedEntry($card, '2026-11-01T11:00:02.000000Z');

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $tampered)->update(['reason' => 'edited']);

        $page       = $this->financeTrail()->cursorPaginate(10);
        $properties = self::propertiesOf($this->readRecords('audit_log.trail_read')[0]);

        $shown = [$page->entries[0]->properties['card'], $page->entries[1]->properties['pin'], $page->entries[2]->properties['card']];

        self::assertSame(['4242', '[ERASED]', '[UNREADABLE]'], $shown);
        self::assertSame(1, $reader->calls());
        self::assertSame(['properties.card', 'properties.pin'], $reader->paths());
        self::assertTrue($properties['reveal']);
        self::assertSameProperties(['encrypted' => 0, 'erased' => 1, 'revealed' => 1, 'unreadable' => 1], $properties['fields']);

        self::assertSame(3, $this->financeTrail()->count());
        self::assertSame(1, $reader->calls());
        self::assertArrayNotHasKey('reveal', self::propertiesOf($this->readRecords('audit_log.trail_counted')[0]));

        $this->allowEverything();

        $sealed = $this->financeTrail()->cursorPaginate(10);
        $record = self::propertiesOf($this->readRecords('audit_log.trail_read')[1]);

        self::assertSame('[ENCRYPTED]', $sealed->entries[0]->properties['card']);
        self::assertSame(1, $reader->calls());
        self::assertFalse($record['reveal']);
        self::assertSameProperties(['encrypted' => 3, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0], $record['fields']);
    }

    /**
     * A cursor is refused once the policy grants or withdraws the reveal.
     *
     * @return void
     */
    public function testACursorIssuedWithoutTheGrantIsRefusedWithIt(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $plain = $this->financeTrail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($plain);

        $this->revealEverything();

        $revealing = $this->financeTrail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($revealing);
        self::assertNotSame($plain, $revealing);

        foreach ([[$plain, true], [$revealing, false]] as $index => [$cursor, $grant]) {
            $this->usePolicy(static fn (): AccessScope => $grant ? AccessScope::all()->revealingEncryptedFields() : AccessScope::all());

            try {
                $this->financeTrail()->cursorPaginate(2, $cursor);
                self::fail('Expected the cursor to be refused.');
            } catch (InvalidCursorException $refusal) {
                self::assertEquals(InvalidCursorException::refused(), $refusal);
            }

            $record     = $this->readRecords('audit_log.trail_read')[2 + $index];
            $properties = self::propertiesOf($record);

            self::assertSame(['denied', 'cursor_rejected', $grant], [$record['outcome'], $record['reason'], $properties['reveal']], (string) $index);
            self::assertSameProperties(['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0], $properties['fields']);
        }
    }

    /**
     * A page's cursor opens the next page, recorded from its position.
     *
     * @return void
     */
    public function testTheNextCursorOpensTheNextPage(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));

        $ids   = $this->seedEntries(5);
        $first = $this->financeTrail()->cursorPaginate(2);

        self::assertIsString($first->nextCursor);

        $second = $this->financeTrail()->cursorPaginate(2, $first->nextCursor);

        self::assertSame([$ids[4], $ids[3]], self::idsOf($first));
        self::assertSame([$ids[2], $ids[1]], self::idsOf($second));
        self::assertIsString($second->nextCursor);

        $third = $this->financeTrail()->cursorPaginate(2, $second->nextCursor);

        self::assertSame([$ids[0]], self::idsOf($third));
        self::assertNull($third->nextCursor);

        $pages = array_map(static fn (array $record): mixed => self::propertiesOf($record)['page'], $this->readRecords('audit_log.trail_read'));

        self::assertSameProperties([
            'first',
            ['occurred_at' => StoredTime::format($first->entries[1]->occurredAt), 'id' => $ids[3]],
            ['occurred_at' => StoredTime::format($second->entries[1]->occurredAt), 'id' => $ids[1]],
        ], $pages);
    }

    /**
     * A wide scope keeps a page's position in the encrypted disclosure alone.
     *
     * @return void
     */
    public function testAPositionUnderAWideScopeIsKeptInTheDisclosureAlone(): void
    {
        $this->allowEverything();

        $ids   = $this->seedEntries(3);
        $first = $this->financeTrail()->cursorPaginate(2);

        self::assertIsString($first->nextCursor);

        $this->financeTrail()->cursorPaginate(2, $first->nextCursor);

        $record = $this->readRecords('audit_log.trail_read')[1];

        self::assertSame([null, null], [$record['tenant_type'], $record['tenant_id']]);
        self::assertSame('next', self::propertiesOf($record)['page']);

        foreach ($ids as $id) {
            self::assertStringNotContainsString($id, (string) json_encode(self::propertiesOf($record)));
        }

        self::assertSame([StoredTime::format($first->entries[1]->occurredAt), $ids[1]], $this->disclosureOf(self::idOf($record))['page']);
    }

    /**
     * A viewer denied between pages gets a plain denial, hiding the revocation.
     *
     * @return void
     */
    public function testAViewerDeniedAfterACursorWasIssuedSeesAnEmptyPage(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->financeTrail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);

        app()->instance(AuditAccessPolicy::class, new DenyAllPolicy);

        $this->captureQueries();

        $page = $this->financeTrail()->cursorPaginate(2, $cursor);

        self::assertSame([[], null, 2], [$page->entries, $page->nextCursor, $page->perPage]);
        self::assertSame([], $this->entryReads());

        $records = $this->readRecords('audit_log.trail_read');

        self::assertCount(2, $records);
        $properties = self::propertiesOf($records[1]);

        self::assertSame(['denied', 'no_scope', 'cursor', 0], [$records[1]['outcome'], $records[1]['reason'], $properties['page'], $properties['returned']]);
    }

    /**
     * A page with no size holds 50, or `read.max_per_page` when fewer.
     *
     * @return void
     */
    public function testAPageWithNoSizeHoldsFiftyOrTheMostAllowed(): void
    {
        $this->allowEverything();
        $this->seedEntries(25);

        app(ConfigRepository::class)->set('audit-log.read.max_per_page', 20);

        $page = $this->financeTrail()->cursorPaginate();

        self::assertSame([20, 20], [$page->perPage, count($page->entries)]);
        self::assertIsString($page->nextCursor);

        $next = $this->financeTrail()->cursorPaginate(null, $page->nextCursor);

        self::assertSame([20, 5, null], [$next->perPage, count($next->entries), $next->nextCursor]);

        app(ConfigRepository::class)->set('audit-log.read.max_per_page', 100);

        self::assertSame(TrailReader::DEFAULT_PER_PAGE, $this->financeTrail()->cursorPaginate()->perPage);
        self::assertSame(50, TrailReader::DEFAULT_PER_PAGE);
    }

    /**
     * A page that holds the last entry has no cursor, even when it is full.
     *
     * @return void
     */
    public function testTheLastPageHasNoCursor(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $page = $this->financeTrail()->cursorPaginate(3);

        self::assertCount(3, $page->entries);
        self::assertNull($page->nextCursor);
        self::assertFalse($page->hasMore());
    }

    /**
     * The look-ahead row is dropped undecoded, never shown or disclosed.
     *
     * @return void
     */
    public function testTheLookAheadRowIsNeitherReturnedNorDisclosed(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(3);

        $this->corrupt($ids[0]);

        $page   = $this->financeTrail()->cursorPaginate(2);
        $record = $this->readRecords('audit_log.trail_read')[0];
        $shown  = array_map(static fn (TrailEntry $entry): array => [$entry->id, $entry->hmac], $page->entries);

        self::assertSame([$ids[2], $ids[1]], self::idsOf($page));
        self::assertTrue($page->hasMore());
        self::assertSame(2, self::propertiesOf($record)['returned']);
        self::assertSame($shown, $this->disclosureOf(self::idOf($record))['members']);
        self::assertNotContains($ids[0], array_column($this->disclosureOf(self::idOf($record))['members'], 0));
    }

    /**
     * A count is one `count(*)` statement, recorded with what it counted.
     *
     * @return void
     */
    public function testACountIsOneCountStatementAndItsRecord(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);
        $this->captureQueries();

        self::assertSame(3, $this->financeTrail()->count());

        $reads = $this->entryReads();

        self::assertCount(1, $reads);
        self::assertStringContainsString('count(*)', $reads[0]);

        $record     = $this->readRecords('audit_log.trail_counted')[0];
        $disclosure = $this->disclosureOf(self::idOf($record));

        self::assertSame(['success', 3], [$record['outcome'], self::propertiesOf($record)['returned']]);
        self::assertSame([], $disclosure['members']);
        self::assertSame(TrailFilters::none()->withCategories(['finance'])->normalised(), $disclosure['filters']);
    }

    /**
     * A page of bulk entries reads no artifact, showing only descriptors.
     *
     * @return void
     */
    public function testAPageOfBulkEntriesReadsNoArtifact(): void
    {
        $this->allowEverything();

        $id = $this->seedBundle(3);

        $this->captureQueries();

        $page      = $this->financeTrail()->cursorPaginate();
        $artifacts = array_filter(
            $this->capturedQueries(),
            static fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select') && str_contains($query->sql, EntrySettings::artifactsTable()),
        );

        self::assertSame([$id], self::idsOf($page));
        self::assertSame([], $artifacts);
        self::assertSame(['kind' => ArtifactKind::BULK->value, 'count' => 3], array_intersect_key($page->entries[0]->manifest ?? [], ['kind' => true, 'count' => true]));
    }

    /**
     * A refusal names the failing class and nothing the read held.
     *
     * @return void
     */
    public function testTheRefusalNamesNoValue(): void
    {
        $this->allowEverything();
        $this->failEntryReads();

        try {
            $this->financeTrail()->correlatedWith(self::SECRET)->cursorPaginate();

            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertStringNotContainsString(self::SECRET, $refusal->getMessage());
            self::assertStringNotContainsString('select', $refusal->getMessage());
            self::assertStringNotContainsString(EntrySettings::table(), $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }
    }

    /**
     * An owner's page is one statement, its record keeping the owner filter.
     *
     * @return void
     */
    public function testAnOwnersPageIsOneStatementWithTheOwnerInItsFilters(): void
    {
        $this->allowEverything();

        $owner = Reference::of('App\Models\User', '42');
        $ids   = $this->seedEntries(3);

        self::holdData($owner, self::OWNER_KEY, [$ids[0], $ids[2]]);

        $this->captureQueries();

        $page  = $this->financeTrail()->holdingDataOf($owner)->cursorPaginate();
        $reads = $this->entryReads();

        self::assertCount(1, $reads);
        self::assertStringContainsString('exists', $reads[0]);
        self::assertStringContainsString(KeyTables::keyUsesTable(), $reads[0]);
        self::assertSame([$ids[2], $ids[0]], self::idsOf($page));
        self::assertSame(2, $this->financeTrail()->holdingDataOf($owner)->count());

        $filters = TrailFilters::none()->withCategories(['finance'])->withHoldingDataOf($owner)->normalised();

        self::assertSame(['App\Models\User', '42'], $filters['holding_data_of']);
        self::assertSame($filters, $this->disclosureOf(self::idOf($this->readRecords('audit_log.trail_read')[0]))['filters']);
        self::assertSame($filters, $this->disclosureOf(self::idOf($this->readRecords('audit_log.trail_counted')[0]))['filters']);
    }

    /**
     * A cursor for one owner's entries is refused for another's, and recorded.
     *
     * @return void
     */
    public function testACursorOfAnotherOwnerIsRefused(): void
    {
        $this->allowEverything();

        $owner = Reference::of('App\Models\User', '42');
        $other = Reference::of('App\Models\User', '43');
        $ids   = $this->seedEntries(3);

        self::holdData($owner, self::OWNER_KEY, $ids);
        self::holdData($other, self::OTHER_OWNER_KEY, $ids);

        $cursor = $this->financeTrail()->holdingDataOf($owner)->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);
        self::assertCount(1, $this->financeTrail()->holdingDataOf($owner)->cursorPaginate(2, $cursor)->entries);

        try {
            $this->financeTrail()->holdingDataOf($other)->cursorPaginate(2, $cursor);

            self::fail('Expected the cursor to be refused.');
        } catch (InvalidCursorException $refusal) {
            self::assertEquals(InvalidCursorException::refused(), $refusal);
        }

        self::assertSame('denied', $this->readRecords('audit_log.trail_read')[2]['outcome']);
    }

    /**
     * Store the owner's key and a key use of it for each entry.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $keyId
     * @param  list<string>  $entryIds
     * @return void
     */
    private static function holdData(Reference $owner, string $keyId, array $entryIds): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->table(KeyTables::subjectKeysTable())->insert([
            'id'          => $keyId,
            'owner_type'  => $owner->type,
            'owner_id'    => $owner->id,
            'tenant_type' => null,
            'tenant_id'   => null,
            'category'    => 'finance',
            'unit'        => hash('sha256', $keyId),
            'generation'  => 1,
            'state'       => 'live',
            'wrapped_key' => 'wrapped',
            'wrap_key_id' => 'd-1',
            'created_at'  => '2026-11-01 12:00:00.000000',
            'erasure_id'  => null,
            'key_id'      => 'k1',
            'hmac'        => str_repeat('0', 64),
        ]);

        $connection->table(KeyTables::keyUsesTable())->insert(array_map(static fn (string $entryId): array => ['key_id' => $keyId, 'entry_id' => $entryId], $entryIds));
    }

    /**
     * Store properties the row codec refuses: valid JSON, but with a key
     * starting with NUL, which PHP cannot name a property.
     *
     * @param  string  $id
     * @return void
     */
    private function corrupt(string $id): void
    {
        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->update(['properties' => '{"\u0000amount":1}']);
    }

    /**
     * Make an in-memory SQLite connection the migrated storage connection.
     *
     * @param  string  $connection
     * @return void
     */
    private function storeOn(string $connection): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . $connection, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', $connection);

        foreach (self::MIGRATIONS as $path) {
            $migration = require $path;

            assert($migration instanceof Migration && method_exists($migration, 'up'));

            $migration->up();
        }
    }
}
