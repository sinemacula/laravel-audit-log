<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;

/**
 * Unit tests for an import's source.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportSource::class)]
final class ImportSourceTest extends TestCase
{
    /** @var string What the file holds, which no refusal names. */
    private const string CONTENT = '{"secret":"never in a message"}';

    /** @var string The file every source names, unless a test names another. */
    private string $path = '';

    /**
     * Write the file every source names.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->path = (string) tempnam(sys_get_temp_dir(), 'import-source-');

        file_put_contents($this->path, self::CONTENT . "\n");
    }

    /**
     * Remove the file.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            chmod($this->path, 0o600);
            unlink($this->path);
        }

        parent::tearDown();
    }

    /**
     * A file of the import format keeps its path, source and region.
     *
     * @return void
     */
    public function testFromFileReadsTheImportFormat(): void
    {
        $source = ImportSource::fromFile($this->path, 'crm-eu', 'eu-west-2');

        self::assertSame($this->path, $source->path);
        self::assertSame('crm-eu', $source->sourceId);
        self::assertSame('eu-west-2', $source->region);
        self::assertSame(ImportFormat::IMPORT_V1, $source->format);
    }

    /**
     * An export file is read in the export format, its region optional.
     *
     * @return void
     */
    public function testFromExportReadsTheExportFormat(): void
    {
        $source = ImportSource::fromExport($this->path, 'app-us-1');

        self::assertSame('app-us-1', $source->sourceId);
        self::assertNull($source->region);
        self::assertSame(ImportFormat::EXPORT_V1, $source->format);
    }

    /**
     * A path that names nothing is refused, naming the path.
     *
     * @return void
     */
    public function testRefusesAMissingFile(): void
    {
        $missing = $this->path . '.missing';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The import file `%s` does not exist.', $missing));

        ImportSource::fromFile($missing, 'crm-eu');
    }

    /**
     * An empty path is refused as one that names nothing.
     *
     * @return void
     */
    public function testRefusesAnEmptyPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The import file `` does not exist.');

        ImportSource::fromFile('', 'crm-eu');
    }

    /**
     * A directory is refused as not a regular file.
     *
     * @return void
     */
    public function testRefusesADirectory(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The import file `%s` is not a regular file.', sys_get_temp_dir()));

        ImportSource::fromExport(sys_get_temp_dir(), 'crm-eu');
    }

    /**
     * An unreadable file is refused without naming its content.
     *
     * @return void
     */
    public function testRefusesAnUnreadableFile(): void
    {
        chmod($this->path, 0o000);

        if (is_readable($this->path)) {
            self::markTestSkipped('This process reads every file whatever its mode.');
        }

        try {
            ImportSource::fromFile($this->path, 'crm-eu');
            self::fail('Expected an unreadable file to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf('The import file `%s` is not readable.', $this->path), $exception->getMessage());
            self::assertStringNotContainsString('never in a message', $exception->getMessage());
        }
    }

    /**
     * Rows of `[source id]`: empty, over 64 characters or not clean text.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedSourceIds(): iterable
    {
        yield from [
            'empty'             => [''],
            'one character too' => [str_repeat('a', 65)],
            'a control'         => ["crm\x07eu"],
            'invalid UTF-8'     => ["crm\xC3"],
        ];
    }

    /**
     * A refused source id names the field and its limit, never its value.
     *
     * @param  string  $sourceId
     * @return void
     */
    #[DataProvider('provideRefusedSourceIds')]
    public function testRefusesASourceIdOutsideItsGrammar(string $sourceId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An import\'s source id must be from 1 to 64 characters, with no control characters.');

        ImportSource::fromFile($this->path, $sourceId);
    }

    /**
     * A source id of exactly 64 characters, counted as characters, is kept.
     *
     * @return void
     */
    public function testASourceIdOfSixtyFourCharactersIsKept(): void
    {
        $sourceId = str_repeat('é', 64);

        self::assertSame($sourceId, ImportSource::fromFile($this->path, $sourceId)->sourceId);
    }

    /**
     * Rows of `[region]`: empty, longer than 32 characters or not clean text.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedRegions(): iterable
    {
        yield from [
            'empty'             => [''],
            'one character too' => [str_repeat('r', 33)],
            'a line feed'       => ["eu\nwest"],
        ];
    }

    /**
     * Each refused region fails closed, naming the field and its limit.
     *
     * @param  string  $region
     * @return void
     */
    #[DataProvider('provideRefusedRegions')]
    public function testRefusesARegionOutsideItsGrammar(string $region): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An import\'s region must be from 1 to 32 characters, with no control characters.');

        ImportSource::fromExport($this->path, 'crm-eu', $region);
    }

    /**
     * A region of exactly 32 characters is kept.
     *
     * @return void
     */
    public function testARegionOfThirtyTwoCharactersIsKept(): void
    {
        self::assertSame(str_repeat('r', 32), ImportSource::fromFile($this->path, 'crm-eu', str_repeat('r', 32))->region);
    }
}
