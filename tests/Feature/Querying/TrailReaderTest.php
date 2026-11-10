<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
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
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\RevealingFieldReader;
use Tests\TestCase;

/**
 * Feature tests for the reader of the trail: one statement on the storage
 * connection for a page and one `count(*)` for a count, the policy handed the
 * viewer as given and the purpose, a denied or disjoint read answered without a
 * statement and recorded as a denial or a success of none, a policy, a
 * statement or a row that fails recorded as a failure before anything is
 * thrown, a refused cursor recorded and thrown, the cursor walking the trail,
 * the look-ahead row neither shown nor disclosed, no artifact read for a page
 * of bulk entries, a page's encrypted fields revealed only under the grant and
 * counted in its record, a cursor bound to the grant, and a refusal that names
 * nothing it read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
final class TrailReaderTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail, SeedsArtifacts;

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

    /** @var bool Whether a read of the entries table on the storage connection fails. */
    private bool $failEntryReads = false;

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
     * The statement reads the storage connection, a connection other than the
     * default when one is configured, and the read is recorded there.
     *
     * @return void
     */
    public function testItReadsOnTheStorageConnection(): void
    {
        $this->storeOn(self::READING);
        $this->allowEverything();

        $id = $this->seedEntry();

        $this->captureQueries();

        $page    = $this->trail()->cursorPaginate();
        $selects = array_values(array_filter($this->capturedQueries(), static fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select')));

        self::assertSame([$id], self::idsOf($page));
        self::assertCount(1, $selects);
        self::assertSame(self::READING, $selects[0]->connectionName);
        self::assertCount(1, $this->readRecords('audit_log.trail_read'));
        self::assertSame(0, DB::connection(self::CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * A page of fifty is one statement on the entries table, the newest fifty
     * of what the filters select, with a cursor to the next.
     *
     * @return void
     */
    public function testAPageOfFiftyIsOneStatement(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(60);

        $this->captureQueries();

        $page = $this->trail()->cursorPaginate(50);

        self::assertCount(1, $this->entryReads());
        self::assertSame(array_slice(array_reverse($ids), 0, 50), self::idsOf($page));
        self::assertTrue($page->hasMore());
    }

    /**
     * The policy is handed the viewer exactly as the application gave it, and
     * the purpose of each terminal call.
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
     * The policy runs inside the read guard's window, so a read it makes is
     * refused.
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

        $this->trail()->cursorPaginate();
        $this->trail()->count();

        self::assertSame([true, true], $inside);
        self::assertFalse(app(ReadGuard::class)->isActive());
    }

    /**
     * A read entered inside a read is refused by the gate before the policy is
     * asked or anything is queried.
     *
     * @return void
     */
    public function testTheGateRefusesBeforeThePolicy(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        $refusal = app(ReadGuard::class)->during(function (): ?AuditReadRefusedException {
            try {
                $this->trail()->count();
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
     * A denied scope reads nothing: no statement reads the entries table, and
     * the result is empty.
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

        self::assertSame($empty, $terminal($this->trail()));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A tenant filter outside a scope of listed tenants reads nothing: no
     * statement, and the empty result a denial gives.
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

        self::assertSame($empty, $terminal($this->trail()->forTenant(Reference::of('organisation', 'org_02'))));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A category filter outside the scope's categories reads nothing: no
     * statement, and the empty result a denial gives.
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

        self::assertSame($empty, $terminal($this->trail()->inCategory('hr')));
        self::assertSame([], $this->entryReads());
    }

    /**
     * A denied read is recorded as `denied` with `no_scope`, under the scope
     * the policy answered, having returned nothing; a page's is an empty page
     * with no cursor.
     *
     * @return void
     */
    public function testADeniedReadIsRecordedAsADenial(): void
    {
        $this->seedEntries(2);

        $page = $this->trail()->cursorPaginate(10);

        self::assertSame([[], null, 10], [$page->entries, $page->nextCursor, $page->perPage]);
        self::assertSame(0, $this->trail()->count());

        $records = $this->readRecords();

        self::assertSame(['audit_log.trail_read', 'audit_log.trail_counted'], array_column($records, 'event'));

        foreach ($records as $record) {
            self::assertSame(['denied', 'no_scope'], [$record['outcome'], $record['reason']]);
            self::assertSame(0, self::propertiesOf($record)['returned']);
            self::assertSame(self::termsOf(null, AccessScope::none())->scopeFingerprint, self::propertiesOf($record)['scope_fingerprint']);
        }
    }

    /**
     * A read whose filters the scope cannot meet is recorded as a success that
     * returned nothing, and discloses no entry.
     *
     * @return void
     */
    public function testADisjointReadIsRecordedAsASuccessOfNone(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));
        $this->seedEntries(2);

        $page = $this->trail()->forTenant(Reference::of('organisation', 'org_02'))->cursorPaginate();

        self::assertSame([], $page->entries);

        $record = $this->readRecords('audit_log.trail_read')[0];

        self::assertSame(['success', null, 0], [$record['outcome'], $record['reason'], self::propertiesOf($record)['returned']]);
        self::assertSame([], $this->disclosureOf(self::idOf($record))['members']);
    }

    /**
     * A policy that throws is recorded as a failure with `policy_failed` and no
     * scope, and what it threw propagates unchanged, from a page and a count
     * alike.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAThrowingPolicyIsRecordedAsAFailureAndRethrown(): void
    {
        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): never => throw $thrown);

        foreach ([fn () => $this->trail()->cursorPaginate(), fn () => $this->trail()->count()] as $terminal) {
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
     * A failure whose own record cannot be written is still thrown as it would
     * have been, and the failure to record it is reported.
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
            $this->trail()->count();

            self::fail('Expected the policy\'s exception.');
        } catch (\RuntimeException $caught) {
            self::assertSame($thrown, $caught);
        }

        $reports = array_map(static fn (\Throwable $report): string => $report->getMessage(), $this->reporter?->reports() ?? []);

        self::assertContains(AuditReadRefusedException::unrecorded()->getMessage(), $reports);
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A success whose record cannot be written returns nothing: the read is
     * refused as unrecorded.
     *
     * @return void
     */
    public function testASuccessWhoseRecordFailsReturnsNothing(): void
    {
        $this->allowEverything();
        $this->pointAtProbeTable();

        $this->expectExceptionObject(AuditReadRefusedException::unrecorded());

        $this->trail()->cursorPaginate();
    }

    /**
     * A statement that fails is recorded as a failure with `query_failed`, and
     * the read is refused naming the class that failed, from a page and a count
     * alike.
     *
     * @return void
     */
    public function testAQueryFailureIsRecordedAsAFailureAndRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);
        $this->failEntryReads();

        foreach ([fn () => $this->trail()->cursorPaginate(), fn () => $this->trail()->count()] as $terminal) {
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
     * A row that cannot be decoded or shown is recorded as a failure with
     * `format_failed`, which discloses no entry, and the read is refused naming
     * the class that failed.
     *
     * @return void
     */
    public function testAFormattingFailureIsRecordedAsAFailureAndRefused(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(2);

        $this->corrupt($ids[1]);

        try {
            $this->trail()->cursorPaginate();

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
     * A cursor that is refused is recorded as a denial with `cursor_rejected`
     * whose page is `cursor`, since a cursor was presented and gave no
     * position, never `first`, and thrown as the uniform refusal, before
     * anything is read.
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
            $this->trail()->cursorPaginate(10, 'v1.bm90.YQ.YQ');
        } finally {
            self::assertSame([], $this->entryReads());

            $record     = $this->readRecords('audit_log.trail_read')[0];
            $properties = self::propertiesOf($record);

            self::assertSame(['denied', 'cursor_rejected', 'cursor', 0], [$record['outcome'], $record['reason'], $properties['page'], $properties['returned']]);
            self::assertNull($this->disclosureOf(self::idOf($record))['page']);
        }
    }

    /**
     * A cursor issued for another page size is refused, since it was bound to
     * the read it was issued for.
     *
     * @return void
     */
    public function testACursorOfAnotherReadIsRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->trail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);

        $this->expectExceptionObject(InvalidCursorException::refused());

        $this->trail()->cursorPaginate(3, $cursor);
    }

    /**
     * A page read under a scope that reveals the encrypted fields asks the
     * bound field reader once for every field of the rows that verify, and its
     * record keeps the grant and how many fragments it showed in each state; a
     * row whose signature no longer verifies shows its field as unreadable
     * without the reader seeing it. The same page without the grant shows every
     * field as encrypted and asks no reader.
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

        $page       = $this->trail()->cursorPaginate(10);
        $properties = self::propertiesOf($this->readRecords('audit_log.trail_read')[0]);

        $shown = [$page->entries[0]->properties['card'], $page->entries[1]->properties['pin'], $page->entries[2]->properties['card']];

        self::assertSame(['4242', '[ERASED]', '[UNREADABLE]'], $shown);
        self::assertSame(1, $reader->calls());
        self::assertSame(['properties.card', 'properties.pin'], $reader->paths());
        self::assertTrue($properties['reveal']);
        self::assertSameProperties(['encrypted' => 0, 'erased' => 1, 'revealed' => 1, 'unreadable' => 1], $properties['fields']);

        self::assertSame(3, $this->trail()->count());
        self::assertSame(1, $reader->calls());
        self::assertArrayNotHasKey('reveal', self::propertiesOf($this->readRecords('audit_log.trail_counted')[0]));

        $this->allowEverything();

        $sealed = $this->trail()->cursorPaginate(10);
        $record = self::propertiesOf($this->readRecords('audit_log.trail_read')[1]);

        self::assertSame('[ENCRYPTED]', $sealed->entries[0]->properties['card']);
        self::assertSame(1, $reader->calls());
        self::assertFalse($record['reveal']);
        self::assertSameProperties(['encrypted' => 3, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0], $record['fields']);
    }

    /**
     * A cursor is bound to the scope it was issued under, the grant included:
     * one issued without the grant is refused once the policy grants it, and
     * one issued with it is refused once the policy withdraws it, each recorded
     * as a denial that keeps the grant of the scope it was presented under and
     * counts no fragment.
     *
     * @return void
     */
    public function testACursorIssuedWithoutTheGrantIsRefusedWithIt(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $plain = $this->trail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($plain);

        $this->revealEverything();

        $revealing = $this->trail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($revealing);
        self::assertNotSame($plain, $revealing);

        foreach ([[$plain, true], [$revealing, false]] as $index => [$cursor, $grant]) {
            $this->usePolicy(static fn (): AccessScope => $grant ? AccessScope::all()->revealingEncryptedFields() : AccessScope::all());

            try {
                $this->trail()->cursorPaginate(2, $cursor);
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
     * The cursor of a page opens the next one, which starts after the last
     * entry shown, and that read is recorded from the position it started at:
     * under a scope of exactly one tenant, in the record's own properties.
     *
     * @return void
     */
    public function testTheNextCursorOpensTheNextPage(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));

        $ids   = $this->seedEntries(5);
        $first = $this->trail()->cursorPaginate(2);

        self::assertIsString($first->nextCursor);

        $second = $this->trail()->cursorPaginate(2, $first->nextCursor);

        self::assertSame([$ids[4], $ids[3]], self::idsOf($first));
        self::assertSame([$ids[2], $ids[1]], self::idsOf($second));
        self::assertIsString($second->nextCursor);

        $third = $this->trail()->cursorPaginate(2, $second->nextCursor);

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
     * Under a scope that is not of exactly one tenant, whose read record is
     * tenantless and so visible beyond any one tenant, a page after the first
     * names `next` and no entry of the trail in its properties; the position it
     * read after is kept in its encrypted disclosure alone.
     *
     * @return void
     */
    public function testAPositionUnderAWideScopeIsKeptInTheDisclosureAlone(): void
    {
        $this->allowEverything();

        $ids   = $this->seedEntries(3);
        $first = $this->trail()->cursorPaginate(2);

        self::assertIsString($first->nextCursor);

        $this->trail()->cursorPaginate(2, $first->nextCursor);

        $record = $this->readRecords('audit_log.trail_read')[1];

        self::assertSame([null, null], [$record['tenant_type'], $record['tenant_id']]);
        self::assertSame('next', self::propertiesOf($record)['page']);

        foreach ($ids as $id) {
            self::assertStringNotContainsString($id, (string) json_encode(self::propertiesOf($record)));
        }

        self::assertSame([StoredTime::format($first->entries[1]->occurredAt), $ids[1]], $this->disclosureOf(self::idOf($record))['page']);
    }

    /**
     * A viewer who loses access between pages, and asks for the next page with
     * the cursor it already holds, is answered as any denied viewer is: an
     * empty page, recorded as `denied` with `no_scope`, never the refusal of a
     * cursor bound to the scope it no longer has, so the answer does not say
     * the access was revoked. The cursor is never opened, so the page is
     * `cursor` and no entry is read.
     *
     * @return void
     */
    public function testAViewerDeniedAfterACursorWasIssuedSeesAnEmptyPage(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $cursor = $this->trail()->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);

        app()->instance(AuditAccessPolicy::class, new DenyAllPolicy);

        $this->captureQueries();

        $page = $this->trail()->cursorPaginate(2, $cursor);

        self::assertSame([[], null, 2], [$page->entries, $page->nextCursor, $page->perPage]);
        self::assertSame([], $this->entryReads());

        $records = $this->readRecords('audit_log.trail_read');

        self::assertCount(2, $records);
        $properties = self::propertiesOf($records[1]);

        self::assertSame(['denied', 'no_scope', 'cursor', 0], [$records[1]['outcome'], $records[1]['reason'], $properties['page'], $properties['returned']]);
    }

    /**
     * A page that names no size holds 50 entries, or `read.max_per_page` when
     * that is fewer, so the call with no arguments works under every setting
     * the package accepts, and its cursor opens the next page asked for the
     * same way.
     *
     * @return void
     */
    public function testAPageWithNoSizeHoldsFiftyOrTheMostAllowed(): void
    {
        $this->allowEverything();
        $this->seedEntries(25);

        app(ConfigRepository::class)->set('audit-log.read.max_per_page', 20);

        $page = $this->trail()->cursorPaginate();

        self::assertSame([20, 20], [$page->perPage, count($page->entries)]);
        self::assertIsString($page->nextCursor);

        $next = $this->trail()->cursorPaginate(null, $page->nextCursor);

        self::assertSame([20, 5, null], [$next->perPage, count($next->entries), $next->nextCursor]);

        app(ConfigRepository::class)->set('audit-log.read.max_per_page', 100);

        self::assertSame(TrailReader::DEFAULT_PER_PAGE, $this->trail()->cursorPaginate()->perPage);
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

        $page = $this->trail()->cursorPaginate(3);

        self::assertCount(3, $page->entries);
        self::assertNull($page->nextCursor);
        self::assertFalse($page->hasMore());
    }

    /**
     * The row read beyond the page is dropped before it is decoded: it is not
     * shown, not disclosed and not counted as returned, and a row there that
     * could not even be decoded costs the page nothing.
     *
     * @return void
     */
    public function testTheLookAheadRowIsNeitherReturnedNorDisclosed(): void
    {
        $this->allowEverything();

        $ids = $this->seedEntries(3);

        $this->corrupt($ids[0]);

        $page   = $this->trail()->cursorPaginate(2);
        $record = $this->readRecords('audit_log.trail_read')[0];
        $shown  = array_map(static fn (TrailEntry $entry): array => [$entry->id, $entry->hmac], $page->entries);

        self::assertSame([$ids[2], $ids[1]], self::idsOf($page));
        self::assertTrue($page->hasMore());
        self::assertSame(2, self::propertiesOf($record)['returned']);
        self::assertSame($shown, $this->disclosureOf(self::idOf($record))['members']);
        self::assertNotContains($ids[0], array_column($this->disclosureOf(self::idOf($record))['members'], 0));
    }

    /**
     * A count is one `count(*)` statement on the entries table, and is recorded
     * with what it counted and a disclosure of no entry.
     *
     * @return void
     */
    public function testACountIsOneCountStatementAndItsRecord(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);
        $this->captureQueries();

        self::assertSame(3, $this->trail()->count());

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
     * A page of bulk entries reads no artifact: the members are never loaded,
     * and each entry shows only its manifest's descriptor.
     *
     * @return void
     */
    public function testAPageOfBulkEntriesReadsNoArtifact(): void
    {
        $this->allowEverything();

        $id = $this->seedBundle(3);

        $this->captureQueries();

        $page      = $this->trail()->cursorPaginate();
        $artifacts = array_filter(
            $this->capturedQueries(),
            static fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select') && str_contains($query->sql, EntrySettings::artifactsTable()),
        );

        self::assertSame([$id], self::idsOf($page));
        self::assertSame([], $artifacts);
        self::assertSame(['kind' => ArtifactKind::BULK->value, 'count' => 3], array_intersect_key($page->entries[0]->manifest ?? [], ['kind' => true, 'count' => true]));
    }

    /**
     * A refusal names the class that failed and nothing the read held: no
     * statement, no binding, and no previous exception.
     *
     * @return void
     */
    public function testTheRefusalNamesNoValue(): void
    {
        $this->allowEverything();
        $this->failEntryReads();

        try {
            $this->trail()->correlatedWith(self::SECRET)->cursorPaginate();

            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertStringNotContainsString(self::SECRET, $refusal->getMessage());
            self::assertStringNotContainsString('select', $refusal->getMessage());
            self::assertStringNotContainsString(EntrySettings::table(), $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }
    }

    /**
     * A page of the entries holding an owner's data is still one statement, the
     * owner's key uses read inside it, and the read's record, like a count's,
     * keeps the owner in its normalised filters.
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

        $page  = $this->trail()->holdingDataOf($owner)->cursorPaginate();
        $reads = $this->entryReads();

        self::assertCount(1, $reads);
        self::assertStringContainsString('exists', $reads[0]);
        self::assertStringContainsString(KeyTables::keyUsesTable(), $reads[0]);
        self::assertSame([$ids[2], $ids[0]], self::idsOf($page));
        self::assertSame(2, $this->trail()->holdingDataOf($owner)->count());

        $filters = TrailFilters::none()->withCategories(['finance'])->withHoldingDataOf($owner)->normalised();

        self::assertSame(['App\Models\User', '42'], $filters['holding_data_of']);
        self::assertSame($filters, $this->disclosureOf(self::idOf($this->readRecords('audit_log.trail_read')[0]))['filters']);
        self::assertSame($filters, $this->disclosureOf(self::idOf($this->readRecords('audit_log.trail_counted')[0]))['filters']);
    }

    /**
     * A cursor issued for one owner's entries is refused for another owner's,
     * since the owner is part of the filters the cursor is bound to, and the
     * refusal is recorded.
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

        $cursor = $this->trail()->holdingDataOf($owner)->cursorPaginate(2)->nextCursor;

        self::assertIsString($cursor);
        self::assertCount(1, $this->trail()->holdingDataOf($owner)->cursorPaginate(2, $cursor)->entries);

        try {
            $this->trail()->holdingDataOf($other)->cursorPaginate(2, $cursor);

            self::fail('Expected the cursor to be refused.');
        } catch (InvalidCursorException $refusal) {
            self::assertEquals(InvalidCursorException::refused(), $refusal);
        }

        self::assertSame('denied', $this->readRecords('audit_log.trail_read')[2]['outcome']);
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
     * The ids of the entries the page shows, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return list<string>
     */
    private static function idsOf(TrailPage $page): array
    {
        return array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);
    }

    /**
     * Store a key of the owner, by its id, and a key use of it for each entry,
     * as an entry holding a fragment sealed under it has; only the columns the
     * filter reads mean anything.
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
     * Make every read of the entries table on the storage connection fail with
     * the engine's exception, which holds the statement and its bindings, until
     * the flag is cleared.
     *
     * @return void
     */
    private function failEntryReads(): void
    {
        $this->failEntryReads = true;

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query, array $bindings, Connection $connection): void {
            if (!$this->failEntryReads || !str_starts_with($query, 'select') || !str_contains($query, EntrySettings::table())) {
                return;
            }

            throw new QueryException((string) $connection->getName(), $query, $bindings, new \PDOException('SQLSTATE[HY000]: General error: the read failed'));
        });
    }

    /**
     * Store the entry's properties as JSON the row codec refuses to decode: a
     * valid document every engine's JSON column holds, but with a key that
     * starts with a NUL character, which PHP cannot make the name of an
     * object's property.
     *
     * @param  string  $id
     * @return void
     */
    private function corrupt(string $id): void
    {
        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->update(['properties' => '{"\u0000amount":1}']);
    }

    /**
     * Configure the connection, an in-memory SQLite database, as the storage
     * connection, with the entries and artifacts tables migrated on it.
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
