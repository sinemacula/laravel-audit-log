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
 * Integration tests for paging the trail while another process writes to it, on
 * whichever engine the suite runs against, as another server would: a walk of
 * every page never repeats an entry and never skips one present when it began,
 * whatever is inserted before, inside and after the part already walked; an
 * entry inserted late into the part already walked is not revisited, which is
 * the documented limit; and entries of one microsecond page in a total order on
 * every engine.
 *
 * SQLite runs on a file in WAL mode, as the operations guidance advises, so the
 * parent reads while the child writes.
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

    /** @var int The microseconds between two entries a batch inserts, spreading the batches across the trail and past both ends. */
    private const int SPREAD = 3;

    /** @var int The microseconds before the first present entry the child's first entry occurs. */
    private const int LEAD = 50;

    /**
     * Bind the read path and a policy that lets the viewer see every entry.
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
     * A walk of pages of fifty over five hundred entries, while another process
     * inserts two hundred more between the pages, spread before the first
     * entry, among the entries, sharing their microseconds, and after the last,
     * shows each of the five hundred exactly once, no entry twice, nothing that
     * was never stored, and in strictly descending order.
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
     * An entry inserted by another process into the part of the trail a walk
     * has already passed is not revisited by that walk, though one inserted
     * into the part ahead of it is reached, and a fresh walk shows both: the
     * limit the guarantee documents.
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
     * A hundred and twenty entries of one microsecond page by their ids alone,
     * in pages of seven, each once and in descending id order, compared in the
     * engine's migrated type.
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
     * Every page of the trail of the size given, from the first by each page's
     * cursor, in order, running the step given after each page but the last
     * with the page's index.
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
     * Assert every entry the pages show comes strictly after the one before it
     * in the trail's order: an earlier occurrence, or the same one and a
     * smaller id.
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
     * The instant the number of microseconds after the first entry seeded
     * together occurs, before it when negative.
     *
     * @param  int  $microseconds
     * @return string
     */
    private static function microsecondsAfterTheFirst(int $microseconds): string
    {
        return StoredTime::format((new CarbonImmutable(self::FIRST_SEEDED_AT, 'UTC'))->addMicroseconds($microseconds));
    }
}
