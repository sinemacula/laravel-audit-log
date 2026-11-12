<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for paging the trail while another process writes to it: no
 * entry repeats or is skipped, within the documented limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
#[CoversClass(ScopeCompiler::class)]
final class ConcurrentPaginationTest extends TestCase
{
    use ReadsTheTrail, RunsKilledChildren;

    /** @var string The file a child names each entry it stored in. */
    private const string IDS = 'ids';

    /** @var int The entries present when the walk begins. */
    private const int PRESENT = 500;

    /** @var int The batches the child inserts, one between each two pages. */
    private const int BATCHES = 10;

    /** @var int The entries in each batch. */
    private const int PER_BATCH = 20;

    /** @var int The microseconds between two entries a batch inserts. */
    private const int SPREAD = 3;

    /** @var int The microseconds before the first present entry the child's first entry occurs. */
    private const int LEAD = 50;

    /**
     * Bind the read path and let the viewer see every entry.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();
    }

    /**
     * Remove what the children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Another process inserting between pages causes no repeat or skip.
     *
     * @return void
     */
    public function testPaginatingWhileAnotherProcessInsertsNeitherRepeatsNorSkipsAnyRowPresentAtTheStart(): void
    {
        $present = $this->seedEntries(self::PRESENT);

        $child = $this->startChild(function (): void {
            for ($batch = 0; $batch < self::BATCHES; $batch++) {
                $this->awaitGate("page-{$batch}");

                for ($index = 0; $index < self::PER_BATCH; $index++) {
                    $offset = (($batch * self::PER_BATCH) + $index) * self::SPREAD - self::LEAD;

                    $this->appendToChildFile(self::IDS, $this->seedEntry([], self::microsecondsAfterTheFirst($offset)));
                }

                $this->openGate("inserted-{$batch}");
            }
        });

        $pages = $this->walk(50, function (int $page): void {
            if ($page >= self::BATCHES) {
                return;
            }

            $this->openGate("page-{$page}");
            $this->awaitGate("inserted-{$page}");
        });

        $this->assertKilled($this->waitForChild($child));

        $shown    = self::shownIn($pages);
        $inserted = $this->childFileLines(self::IDS);

        self::assertCount(self::BATCHES * self::PER_BATCH, $inserted);
        self::assertSame($shown, array_values(array_unique($shown)), 'An entry was shown twice.');
        self::assertSame([], array_values(array_diff($present, $shown)), 'An entry present at the start was skipped.');
        self::assertSame([], array_values(array_diff($shown, $present, $inserted)), 'An entry that was never stored was shown.');
        self::assertStrictlyDescending($pages);
    }

    /**
     * A row inserted behind a walk is not revisited by it, as documented.
     *
     * @return void
     */
    public function testALateRowInAWalkedIntervalIsNotRevisited(): void
    {
        $present = $this->seedEntries(100);

        $child = $this->startChild(function (): void {
            $this->awaitGate('walked');

            $this->appendToChildFile(self::IDS, $this->seedEntry([], self::microsecondsAfterTheFirst(75)));
            $this->appendToChildFile(self::IDS, $this->seedEntry([], self::microsecondsAfterTheFirst(25)));

            $this->openGate('inserted');
        });

        $pages = $this->walk(50, function (int $page): void {
            if ($page !== 0) {
                return;
            }

            $this->openGate('walked');
            $this->awaitGate('inserted');
        });

        $this->assertKilled($this->waitForChild($child));

        [$behind, $ahead] = $this->childFileLines(self::IDS);

        $shown = self::shownIn($pages);
        $fresh = self::shownIn($this->walk(50));

        self::assertNotContains($behind, $shown, 'The walk revisited the part it had passed.');
        self::assertContains($ahead, $shown, 'The walk did not reach the part ahead of it.');
        self::assertSame([], array_values(array_diff($present, $shown)));
        self::assertContains($behind, $fresh);
        self::assertContains($ahead, $fresh);
        self::assertCount(102, $fresh);
    }

    /**
     * Entries of one microsecond page by id alone, once each, on every engine.
     *
     * @return void
     */
    public function testIdenticalMicrosecondsPageOnEveryEngine(): void
    {
        $ids = [];

        for ($index = 0; $index < 120; $index++) {
            $ids[] = $this->seedEntry([], self::microsecondsAfterTheFirst(0));
        }

        usort($ids, static fn (string $a, string $b): int => strcmp($b, $a));

        $pages = $this->walk(7);

        self::assertCount(18, $pages);
        self::assertSame($ids, self::shownIn($pages));
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode.
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
     * Every page of the trail in order, running the step between pages.
     *
     * @param  int  $perPage
     * @param  ?\Closure(int): void  $between
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    private function walk(int $perPage, ?\Closure $between = null): array
    {
        $trail = app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
        $pages = [$trail->cursorPaginate($perPage)];

        while (($cursor = end($pages)->nextCursor) !== null) {
            self::assertLessThan(1000, count($pages), 'The walk never ended.');

            if ($between !== null) {
                $between(count($pages) - 1);
            }

            $pages[] = $trail->cursorPaginate($perPage, $cursor);
        }

        return $pages;
    }

    /**
     * The ids the pages show, in order.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>  $pages
     * @return list<string>
     */
    private static function shownIn(array $pages): array
    {
        return array_merge(...array_map(static fn (TrailPage $page): array => array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries), $pages));
    }

    /**
     * Assert the pages' entries are in strictly descending trail order.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>  $pages
     * @return void
     */
    private static function assertStrictlyDescending(array $pages): void
    {
        $previous = null;

        foreach ($pages as $page) {
            foreach ($page->entries as $entry) {
                $position = [StoredTime::format($entry->occurredAt), $entry->id];

                if ($previous !== null) {
                    self::assertLessThan(0, $position <=> $previous, sprintf('%s at %s is not after %s at %s.', $position[1], $position[0], $previous[1], $previous[0]));
                }

                $previous = $position;
            }
        }
    }

    /**
     * The instant that many microseconds after the first seeded entry, before
     * it when negative.
     *
     * @param  int  $microseconds
     * @return string
     */
    private static function microsecondsAfterTheFirst(int $microseconds): string
    {
        return StoredTime::format((new CarbonImmutable(self::FIRST_SEEDED_AT, 'UTC'))->addMicroseconds($microseconds));
    }
}
