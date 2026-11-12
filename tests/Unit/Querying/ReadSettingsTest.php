<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\ReadSettings;

/**
 * Unit tests for the read and export settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadSettings::class)]
final class ReadSettingsTest extends TestCase
{
    /** @var string The refusal of a page size outside its range. */
    private const string MALFORMED_MAX_PER_PAGE = '`audit-log.read.max_per_page` must be an integer from 1 to 500.';

    /** @var string The refusal of a chunk outside its range. */
    private const string MALFORMED_CHUNK = '`audit-log.export.chunk` must be an integer from 100 to 10000.';

    /** @var string What a test's bad value carries, and no message may hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /**
     * With nothing set, pages hold at most 100 entries and exports read 1000.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        $empty = new Repository(['audit-log' => ['read' => [], 'export' => []]]);

        foreach ([new ReadSettings(new Repository), self::settings([]), new ReadSettings($empty)] as $settings) {
            self::assertSame(100, $settings->maxPerPage());
            self::assertSame(1000, $settings->exportChunk());
        }
    }

    /**
     * Each setting accepts either end of its range and any value inside it.
     *
     * @return void
     */
    public function testTheBoundsAreAccepted(): void
    {
        $least = self::settings(['read' => ['max_per_page' => 1], 'export' => ['chunk' => 100]]);

        self::assertSame(1, $least->maxPerPage());
        self::assertSame(100, $least->exportChunk());

        $most = self::settings(['read' => ['max_per_page' => 500], 'export' => ['chunk' => 10000]]);

        self::assertSame(500, $most->maxPerPage());
        self::assertSame(10000, $most->exportChunk());

        $inside = self::settings(['read' => ['max_per_page' => 25], 'export' => ['chunk' => 2500]]);

        self::assertSame(25, $inside->maxPerPage());
        self::assertSame(2500, $inside->exportChunk());
    }

    /**
     * An environment digit string is read as its integer.
     *
     * @return void
     */
    public function testADigitStringFromTheEnvironmentIsRead(): void
    {
        $inside = self::settings(['read' => ['max_per_page' => '250'], 'export' => ['chunk' => '5000']]);

        self::assertSame(250, $inside->maxPerPage());
        self::assertSame(5000, $inside->exportChunk());

        $least = self::settings(['read' => ['max_per_page' => '1'], 'export' => ['chunk' => '100']]);

        self::assertSame(1, $least->maxPerPage());
        self::assertSame(100, $least->exportChunk());

        $most = self::settings(['read' => ['max_per_page' => '500'], 'export' => ['chunk' => '10000']]);

        self::assertSame(500, $most->maxPerPage());
        self::assertSame(10000, $most->exportChunk());
    }

    /**
     * Rows of `[the page size]`: out of range or no integer `env()` gives.
     *
     * @return iterable<string, array{0: array<int, int>|bool|float|int|string|null}>
     */
    public static function providePageSizesOutsideTheRange(): iterable
    {
        yield from [
            'zero'                => [0],
            'one over the most'   => [501],
            'a word'              => ['abc'],
            'negative'            => [-1],
            'a float'             => [1.5],
            'a whole float'       => [100.0],
            'digits over'         => ['501'],
            'digits of zero'      => ['0'],
            'a signed string'     => ['+100'],
            'a padded string'     => [' 100'],
            'a zero-led string'   => ['0100'],
            'a fractional string' => ['100.0'],
            'an exponent'         => ['1e2'],
            'an explicit null'    => [null],
            'a boolean'           => [true],
            'a list'              => [[100]],
            'the sentinel'        => [self::SENTINEL],
        ];
    }

    /**
     * A page size outside 1 to 500 fails closed, never naming the value.
     *
     * @param  array<int, int>|bool|float|int|string|null  $value
     * @return void
     */
    #[DataProvider('providePageSizesOutsideTheRange')]
    public function testRefusesAPageSizeOutsideItsRange(array|bool|float|int|string|null $value): void
    {
        $settings = self::settings(['read' => ['max_per_page' => $value]]);

        self::assertRefused(self::MALFORMED_MAX_PER_PAGE, $settings->maxPerPage(...));
        self::assertSame(1000, $settings->exportChunk());
    }

    /**
     * Rows of `[the chunk]`: out of range or no integer `env()` gives.
     *
     * @return iterable<string, array{0: array<int, int>|bool|float|int|string|null}>
     */
    public static function provideChunksOutsideTheRange(): iterable
    {
        yield from [
            'one under the least' => [99],
            'one over the most'   => [10001],
            'an exponent'         => ['1e3'],
            'digits under'        => ['99'],
            'digits over'         => ['10001'],
            'negative'            => [-1000],
            'a float'             => [1000.0],
            'a fractional string' => ['1000.5'],
            'a padded string'     => ['1000 '],
            'an explicit null'    => [null],
            'a boolean'           => [false],
            'a list'              => [[1000]],
            'the sentinel'        => [self::SENTINEL],
        ];
    }

    /**
     * A chunk outside 100 to 10000 fails closed, never naming the value.
     *
     * @param  array<int, int>|bool|float|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideChunksOutsideTheRange')]
    public function testRefusesAChunkOutsideItsRange(array|bool|float|int|string|null $value): void
    {
        $settings = self::settings(['export' => ['chunk' => $value]]);

        self::assertRefused(self::MALFORMED_CHUNK, $settings->exportChunk(...));
        self::assertSame(100, $settings->maxPerPage());
    }

    /**
     * Validation reads every setting, the page size first.
     *
     * @return void
     */
    public function testValidateReadsEverySetting(): void
    {
        (new ReadSettings(new Repository))->validate();

        self::settings(['read' => ['max_per_page' => '500'], 'export' => ['chunk' => 100]])->validate();

        $bad = [
            [['read' => ['max_per_page' => 0]], self::MALFORMED_MAX_PER_PAGE],
            [['export' => ['chunk' => 99]], self::MALFORMED_CHUNK],
            [['read' => ['max_per_page' => 501], 'export' => ['chunk' => 10001]], self::MALFORMED_MAX_PER_PAGE],
        ];

        foreach ($bad as [$settings, $message]) {
            self::assertRefused($message, self::settings($settings)->validate(...));
        }
    }

    /**
     * Each setting is read on every call.
     *
     * @return void
     */
    public function testTheSettingsAreReadOnEveryCall(): void
    {
        $config   = new Repository;
        $settings = new ReadSettings($config);

        self::assertSame(100, $settings->maxPerPage());
        self::assertSame(1000, $settings->exportChunk());

        $config->set('audit-log.read.max_per_page', 10);
        $config->set('audit-log.export.chunk', '200');

        self::assertSame(10, $settings->maxPerPage());
        self::assertSame(200, $settings->exportChunk());

        $config->set('audit-log.read.max_per_page', 'ten');

        self::assertRefused(self::MALFORMED_MAX_PER_PAGE, $settings->maxPerPage(...));
    }

    /**
     * Assert the read fails with exactly the message, which omits the sentinel.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $read
     * @return void
     */
    private static function assertRefused(string $message, \Closure $read): void
    {
        try {
            $read();
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertStringNotContainsString(self::SENTINEL, $exception->getMessage());

            return;
        }

        self::fail('Expected the setting to be refused.');
    }

    /**
     * Read settings over a configuration of the read and export sections.
     *
     * @param  array<string, array<string, array<int, int>|bool|float|int|string|null>>  $sections
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadSettings
     */
    private static function settings(array $sections): ReadSettings
    {
        return new ReadSettings(new Repository(['audit-log' => $sections]));
    }
}
