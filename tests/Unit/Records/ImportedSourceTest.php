<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;

/**
 * Unit tests for an imported record's source: the fields it keeps exactly, the
 * lengths and the clean text its source id, region and record id must have, the
 * lower-case UUID its batch id must be, the lower-case hex its digest must be,
 * and refusals that name the field and never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportedSource::class)]
final class ImportedSourceTest extends TestCase
{
    /** @var string A lower-case UUID. */
    private const string BATCH_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string A refused value no message may repeat. */
    private const string SECRET = 'hunter2-not-for-messages';

    /**
     * Every field is kept exactly as given, and the region may be absent.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $digest = hash('sha256', 'assertion');
        $source = new ImportedSource('Legacy App', 'eu-west-1', ' 007 ', self::BATCH_ID, $digest);
        $bare   = new ImportedSource('legacy', null, 'r1', self::BATCH_ID, $digest);

        self::assertSame(['Legacy App', 'eu-west-1', ' 007 ', self::BATCH_ID, $digest], [
            $source->sourceId, $source->sourceRegion, $source->sourceRecordId, $source->importBatchId, $source->sourceDigest,
        ]);
        self::assertNull($bare->sourceRegion);
        self::assertSame(191, ImportedSource::SOURCE_RECORD_ID_MAX_CHARACTERS);
    }

    /**
     * Each text field is kept at the longest its column holds, counted in
     * characters, not bytes.
     *
     * @return void
     */
    public function testKeepsEachTextFieldAtItsLongest(): void
    {
        $source = new ImportedSource(
            str_repeat('é', AuditRecord::SOURCE_ID_MAX_CHARACTERS),
            str_repeat('é', AuditRecord::SOURCE_REGION_MAX_CHARACTERS),
            str_repeat('é', ImportedSource::SOURCE_RECORD_ID_MAX_CHARACTERS),
            self::BATCH_ID,
            str_repeat('0', 64),
        );

        self::assertSame(64, mb_strlen($source->sourceId));
        self::assertSame(32, mb_strlen((string) $source->sourceRegion));
        self::assertSame(191, mb_strlen($source->sourceRecordId));
    }

    /**
     * Rows of `[source id, source region, field, message bound]`: a source id
     * or region that is empty, one character too long, or unclean.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: string, 3: int}>
     */
    public static function provideRefusedSources(): iterable
    {
        yield from [
            'an empty source id'        => ['', null, 'source_id', 64],
            'a source id too long'      => [str_repeat('a', 65), null, 'source_id', 64],
            'a source id with a NUL'    => [self::SECRET . "\0", null, 'source_id', 64],
            'a source id with a bidi'   => [self::SECRET . "\u{202E}", null, 'source_id', 64],
            'an empty region'           => ['legacy', '', 'source_region', 32],
            'a region too long'         => ['legacy', str_repeat('a', 33), 'source_region', 32],
            'a region with a line feed' => ['legacy', self::SECRET . "\n", 'source_region', 32],
        ];
    }

    /**
     * A source id or region outside its length, or not clean text, is refused,
     * naming the field and its bound, never the value.
     *
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  string  $field
     * @param  int  $bound
     * @return void
     */
    #[DataProvider('provideRefusedSources')]
    public function testRefusesASourceIdOutsideItsLength(string $sourceId, ?string $sourceRegion, string $field, int $bound): void
    {
        self::assertRefused(
            static fn (): ImportedSource => new ImportedSource($sourceId, $sourceRegion, 'r1', self::BATCH_ID, str_repeat('a', 64)),
            sprintf('An imported record\'s `%s` must be from 1 to %d characters, with no control characters.', $field, $bound),
        );
    }

    /**
     * Rows of `[source record id]`: empty, one character too long, and unclean
     * in each way.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedRecordIds(): iterable
    {
        yield from [
            'empty'             => [''],
            'too long'          => [str_repeat('é', 192)],
            'a NUL'             => [self::SECRET . "\0"],
            'a carriage return' => [self::SECRET . "\r"],
            'a bidi override'   => [self::SECRET . "\u{202E}"],
            'invalid UTF-8'     => [self::SECRET . "\xC3"],
        ];
    }

    /**
     * A record id that is empty, longer than its column or not clean text is
     * refused, naming the field, never the value.
     *
     * @param  string  $sourceRecordId
     * @return void
     */
    #[DataProvider('provideRefusedRecordIds')]
    public function testRefusesARecordIdThatIsEmptyLongOrUnclean(string $sourceRecordId): void
    {
        self::assertRefused(
            static fn (): ImportedSource => new ImportedSource('legacy', null, $sourceRecordId, self::BATCH_ID, str_repeat('a', 64)),
            'An imported record\'s `source_record_id` must be from 1 to 191 characters, with no control characters.',
        );
    }

    /**
     * Rows of `[batch id]`: values that are not a lower-case UUID.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedBatchIds(): iterable
    {
        yield from [
            'empty'              => [''],
            'upper case'         => [strtoupper(self::BATCH_ID)],
            'without hyphens'    => [str_replace('-', '', self::BATCH_ID)],
            'braced'             => ['{' . self::BATCH_ID . '}'],
            'a trailing newline' => [self::BATCH_ID . "\n"],
            'a ULID'             => ['01JBQ4N6Z8X2Y3W4V5T6S7R8Q9'],
        ];
    }

    /**
     * A batch id that is not a lower-case UUID, the one form every engine
     * stores and returns, is refused, naming the field, never the value.
     *
     * @param  string  $importBatchId
     * @return void
     */
    #[DataProvider('provideRefusedBatchIds')]
    public function testRefusesABatchIdThatIsNotALowerCaseUuid(string $importBatchId): void
    {
        self::assertRefused(
            static fn (): ImportedSource => new ImportedSource('legacy', null, 'r1', $importBatchId, str_repeat('a', 64)),
            'An imported record\'s `import_batch_id` must be a lower-case UUID.',
        );
    }

    /**
     * Rows of `[digest]`: values that are not 64 lower-case hexadecimal
     * characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedDigests(): iterable
    {
        yield from [
            'empty'              => [''],
            'upper case'         => [str_repeat('A', 64)],
            'one short'          => [str_repeat('a', 63)],
            'one long'           => [str_repeat('a', 65)],
            'not hexadecimal'    => [str_repeat('g', 64)],
            'a trailing newline' => [str_repeat('a', 64) . "\n"],
        ];
    }

    /**
     * A digest that is not 64 lower-case hexadecimal characters is refused,
     * naming the field, never the value.
     *
     * @param  string  $sourceDigest
     * @return void
     */
    #[DataProvider('provideRefusedDigests')]
    public function testRefusesADigestThatIsNotLowerCaseHex(string $sourceDigest): void
    {
        self::assertRefused(
            static fn (): ImportedSource => new ImportedSource('legacy', null, 'r1', self::BATCH_ID, $sourceDigest),
            'An imported record\'s `source_digest` must be 64 lower-case hexadecimal characters.',
        );
    }

    /**
     * Assert the construction is refused with exactly the message given, which
     * never repeats the refused value.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\ImportedSource  $construct
     * @param  string  $message
     * @return void
     */
    private static function assertRefused(\Closure $construct, string $message): void
    {
        try {
            $construct();
            self::fail('Expected the source to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        }
    }
}
