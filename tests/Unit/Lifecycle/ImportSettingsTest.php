<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings;

/**
 * Unit tests for the import settings: the default of each, the values each
 * accepts, the exact message each malformed value fails closed with, the fixed
 * age of a stale batch, and the reader of every setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportSettings::class)]
final class ImportSettingsTest extends TestCase
{
    /** @var array<string, array{0: string, 1: int, 2: int, 3: int}> Each numeric reader, by its key under `audit-log.import.`: its method, default, least and greatest value. */
    private const array NUMBERS = [
        'chunk'            => ['chunk', 500, 100, 5000],
        'max_skew_seconds' => ['maxSkewSeconds', 300, 0, 86400],
        'max_line_bytes'   => ['maxLineBytes', 1048576, 1024, 16777216],
    ];

    /**
     * Raise every PHP warning as an exception, so each setting is also read
     * quietly: inside a Laravel application a warning becomes an exception,
     * which would turn reading the settings into an error.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
    }

    /**
     * Restore the error handler after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        restore_error_handler();

        parent::tearDown();
    }

    /**
     * With nothing set, or none of the package's configuration at all, each
     * number takes its default: chunks of 500 lines, five minutes of skew and
     * lines of up to a mebibyte.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        foreach ([new ImportSettings(new Repository), self::settings([])] as $settings) {
            self::assertSame(500, $settings->chunk());
            self::assertSame(300, $settings->maxSkewSeconds());
            self::assertSame(1048576, $settings->maxLineBytes());
        }
    }

    /**
     * Each number accepts its least and greatest value, as an integer or as the
     * digit string an environment line gives, and is read again on every call.
     *
     * @return void
     */
    public function testTheBoundsAreAccepted(): void
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            foreach ([$least, $most, (string) $least, (string) $most] as $value) {
                self::assertSame((int) $value, self::number(self::settings([$key => $value]), $method), $key);
            }
        }

        $config   = new Repository(['audit-log' => ['import' => ['chunk' => 100]]]);
        $settings = new ImportSettings($config);

        self::assertSame(100, $settings->chunk());

        $config->set('audit-log.import.chunk', '250');

        self::assertSame(250, $settings->chunk());
    }

    /**
     * Rows of `[key, method, value, message]`: one below the least and one
     * above the greatest value of each number, and forms that name no integer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: string, 2: mixed, 3: string}>
     */
    public static function provideNumbersOutOfRange(): iterable
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            $message = sprintf('`audit-log.import.%s` must be an integer from %d to %d.', $key, $least, $most);

            yield $key . ', one below the least' => [$key, $method, $least - 1, $message];
            yield $key . ', one above the greatest' => [$key, $method, $most + 1, $message];
            yield $key . ', an exponent' => [$key, $method, '1e3', $message];
            yield $key . ', a fraction' => [$key, $method, 1.5, $message];
            yield $key . ', a padded digit string' => [$key, $method, ' ' . $most, $message];
            yield $key . ', null' => [$key, $method, null, $message];
            yield $key . ', true' => [$key, $method, true, $message];
        }
    }

    /**
     * Each malformed number is refused by its reader and by validation, with a
     * message naming its key and range.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  string  $method
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideNumbersOutOfRange')]
    public function testRefusesANumberOutsideItsRange(string $key, string $method, mixed $value, string $message): void
    {
        foreach ([$method, 'validate'] as $reader) {
            try {
                self::read(self::settings([$key => $value]), $reader);

                self::fail("Expected {$key} to be refused by {$reader}().");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage(), $reader);
            }
        }
    }

    /**
     * A running batch that has not moved for an hour is stale.
     *
     * @return void
     */
    public function testAStaleBatchIsAnHourOld(): void
    {
        self::assertSame(3600, ImportSettings::STALE_SECONDS);
    }

    /**
     * Validation reads every setting, so a malformed one fails it whichever it
     * is, and passes when all are well formed.
     *
     * @return void
     */
    public function testValidateReadsEverySetting(): void
    {
        foreach (self::NUMBERS as $key => [, , $least, $most]) {
            try {
                self::settings([$key => $most + 1])->validate();

                self::fail("Expected {$key} to fail validation.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('`audit-log.import.%s` must be an integer from %d to %d.', $key, $least, $most), $exception->getMessage());
            }
        }

        self::settings(['chunk' => 100, 'max_skew_seconds' => 0, 'max_line_bytes' => 1024])->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * The value of the numeric reader the method names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  string  $method
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function number(ImportSettings $settings, string $method): int
    {
        return match ($method) {
            'chunk'          => $settings->chunk(),
            'maxSkewSeconds' => $settings->maxSkewSeconds(),
            'maxLineBytes'   => $settings->maxLineBytes(),
            default          => self::fail(sprintf('No numeric reader is named %s.', $method)),
        };
    }

    /**
     * Call the reader the method names, or validation, for what it refuses.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  string  $method
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function read(ImportSettings $settings, string $method): void
    {
        if ($method === 'validate') {
            $settings->validate();

            return;
        }

        self::number($settings, $method);
    }

    /**
     * Import settings over configuration holding the import section given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $import
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings
     */
    private static function settings(array $import): ImportSettings
    {
        return new ImportSettings(new Repository(['audit-log' => ['import' => $import]]));
    }
}
