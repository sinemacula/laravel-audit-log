<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\FieldDisclosure;
use SineMacula\Laravel\AuditLog\Querying\ProjectedPage;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for a projected page: the entries it shows, in order, and what it
 * disclosed of their encrypted fragments, kept as given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProjectedPage::class)]
final class ProjectedPageTest extends TestCase
{
    /**
     * The entries and the disclosure are kept as given, the entries in their
     * order.
     *
     * @return void
     */
    public function testKeepsTheEntriesAndTheirDisclosure(): void
    {
        $stored  = StoredEntry::fromRow((new RowCodec)->encode(RecordFactory::finalisedBundle(1)), new RowCodec);
        $signer  = new RecordSigner(new KeyRing(new IntegritySettings(new Repository(['app' => ['key' => str_repeat('k', 32)]]))));
        $entries = (new EntryProjector(new SealedFieldReader, new RecordingExceptionHandler, $signer))->project([$stored, $stored], false)->entries;
        $fields  = new FieldDisclosure(true, 1, 0, 2, 0);

        $page = new ProjectedPage([$entries[1], $entries[0]], $fields);

        self::assertSame([$entries[1], $entries[0]], $page->entries);
        self::assertSame($fields, $page->fields);
        self::assertSame([], (new ProjectedPage([], FieldDisclosure::none(false)))->entries);
    }
}
