<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for a page of the trail: the entries and cursor it holds, whether
 * there is a next page, the empty page of a denied or disjoint read, and the
 * page sizes and entry counts it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailPage::class)]
final class TrailPageTest extends TestCase
{
    /**
     * A page has more exactly when it holds a cursor, whatever it shows.
     *
     * @return void
     */
    public function testHasMore(): void
    {
        $entry = self::entry();

        $more = new TrailPage([$entry], 'v1.a.b.c', 1);
        $last = new TrailPage([$entry], null, 1);

        self::assertTrue($more->hasMore());
        self::assertSame('v1.a.b.c', $more->nextCursor);
        self::assertSame([$entry], $more->entries);
        self::assertSame(1, $more->perPage);
        self::assertFalse($last->hasMore());
        self::assertNull($last->nextCursor);
    }

    /**
     * An empty page shows nothing, has no next page and keeps the page size of
     * the read.
     *
     * @return void
     */
    public function testEmpty(): void
    {
        $page = TrailPage::empty(25);

        self::assertSame([], $page->entries);
        self::assertNull($page->nextCursor);
        self::assertSame(25, $page->perPage);
        self::assertFalse($page->hasMore());
    }

    /**
     * Rows of `[entries, page size]`: pages that cannot be: a page size under
     * 1, and more entries than the page size.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideImpossiblePages(): iterable
    {
        yield from [
            'a page size of 0'        => [0, 0],
            'a negative page size'    => [0, -1],
            'one entry over the size' => [2, 1],
        ];
    }

    /**
     * A page size under 1, or more entries than the page size, is refused.
     *
     * @param  int  $entries
     * @param  int  $perPage
     * @return void
     */
    #[DataProvider('provideImpossiblePages')]
    public function testRefusesAnImpossiblePage(int $entries, int $perPage): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A page shows from none to its page size of entries, and its page size is at least 1.');

        new TrailPage(array_fill(0, $entries, self::entry()), null, $perPage);
    }

    /**
     * A full page, as many entries as its size, is a page.
     *
     * @return void
     */
    public function testAFullPageIsAPage(): void
    {
        self::assertCount(2, (new TrailPage([self::entry(), self::entry()], null, 2))->entries);
    }

    /**
     * An entry shown of a captured record.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private static function entry(): TrailEntry
    {
        $record = RecordFactory::finalisedBundle(1);
        $stored = StoredEntry::fromRow((new RowCodec)->encode($record), new RowCodec);

        $signer = new RecordSigner(new KeyRing(new IntegritySettings(new Repository(['app' => ['key' => str_repeat('k', 32)]]))));

        return (new EntryProjector(new SealedFieldReader, self::handler(), $signer))->project([$stored], false)->entries[0];
    }

    /**
     * An exception handler that keeps what it is asked to report.
     *
     * @return \Illuminate\Contracts\Debug\ExceptionHandler
     */
    private static function handler(): ExceptionHandler
    {
        return new RecordingExceptionHandler;
    }
}
