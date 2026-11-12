<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use Tests\Concerns\ReadsTheTrail;

/**
 * Statement budget for reading the trail: a page or count is one select and its
 * record one bundle's two inserts, a denied read selects nothing, and page size
 * changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
final class TrailQueryBudgetTest extends PerformanceContractTestCase
{
    use ReadsTheTrail;

    /**
     * Bind the read path.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
    }

    /**
     * A page of fifty is one entries select and no artifacts select, and its
     * record one bundle's two inserts in one transaction.
     *
     * @return void
     */
    public function testAPageOfFiftyIsOneSelect(): void
    {
        $this->allowEverything();
        $this->seedEntries(60);

        $page = $this->assertTransactionBudget(1, 1, fn () => $this->assertStatementBudget(1, 2, 0, 0, fn () => $this->trail()->cursorPaginate(50)));

        self::assertCount(50, $page->entries);
        $this->assertOneEntriesSelectAndABundle();
    }

    /**
     * A count is one entries select, with the same record.
     *
     * @return void
     */
    public function testACountIsOneSelect(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        $count = $this->assertTransactionBudget(1, 1, fn () => $this->assertStatementBudget(1, 2, 0, 0, fn () => $this->trail()->count()));

        self::assertSame(3, $count);
        $this->assertOneEntriesSelectAndABundle();
        self::assertStringContainsString('count(*)', $this->capturedStatements()[0]);
    }

    /**
     * A denied read, a page or a count, selects nothing at all and writes only
     * its record.
     *
     * @return void
     */
    public function testADeniedReadIsNoSelect(): void
    {
        $this->seedEntries(3);

        $page  = $this->assertStatementBudget(0, 2, 0, 0, fn () => $this->trail()->cursorPaginate());
        $count = $this->assertStatementBudget(0, 2, 0, 0, fn () => $this->trail()->count());

        self::assertSame([[], 0], [$page->entries, $count]);
    }

    /**
     * Pages of one, fifty and five hundred cost the same statements, differing
     * only in the limit.
     *
     * @return void
     */
    public function testTheStatementsDoNotGrowWithThePage(): void
    {
        app(ConfigRepository::class)->set('audit-log.read.max_per_page', 500);

        $this->allowEverything();
        $this->seedEntries(510);

        $shapes = [];

        foreach ([1, 50, 500] as $perPage) {
            $page = $this->assertStatementBudget(1, 2, 0, 0, fn () => $this->trail()->cursorPaginate($perPage));

            self::assertCount($perPage, $page->entries);

            $shapes[$perPage] = array_map(static fn (string $statement): string => (string) preg_replace('/\blimit \d+/', 'limit ?', $statement), $this->capturedStatements());
        }

        self::assertSame($shapes[1], $shapes[50]);
        self::assertSame($shapes[1], $shapes[500]);
    }

    /**
     * The `finance` trail, read for the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
    }

    /**
     * Assert the last statements were one entries select, no artifacts select,
     * then one bundle's inserts, the artifact's first.
     *
     * @return void
     */
    private function assertOneEntriesSelectAndABundle(): void
    {
        [$select, $artifact, $entry] = $this->capturedStatements();

        self::assertStringStartsWith('select', $select);
        self::assertStringContainsString(EntrySettings::table(), $select);
        self::assertStringNotContainsString(EntrySettings::artifactsTable(), $select);
        self::assertStringStartsWith('insert into ', $artifact);
        self::assertStringContainsString(EntrySettings::artifactsTable(), $artifact);
        self::assertStringStartsWith('insert into ', $entry);
        self::assertStringContainsString(EntrySettings::table(), $entry);
        self::assertStringNotContainsString(EntrySettings::artifactsTable(), $entry);
    }
}
