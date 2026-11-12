<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;

/**
 * Unit tests for the retention settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetentionSettings::class)]
final class RetentionSettingsTest extends TestCase
{
    /** @var array<string, array{0: string, 1: int, 2: int, 3: int}> Each numeric reader by key: its method, default, least and greatest value. */
    private const array NUMBERS = [
        'after_days'  => ['afterDays', 0, 0, 36500],
        'batch'       => ['batch', 1000, 100, 10000],
        'max_seconds' => ['maxSeconds', 3000, 60, 86400],
    ];

    /** @var string The refusal of a malformed map, by its key. */
    private const string MAP = '`audit-log.retention.%s` must be a map of categories to days, each from 0 to 36500, 0 meaning forever.';

    /** @var string The refusal of a key of a map that is no category, by the map's key. */
    private const string CATEGORY = '`audit-log.retention.%s` must be keyed by categories of 1 to 64 lower-case letters, digits or underscores, starting with a letter.';

    /** @var string The refusal of a retention shorter than its preservation. */
    private const string CONFLICT = '`audit-log.retention.%s` is shorter than `audit-log.retention.preserve.%s`; a category must be kept at least as long as it is preserved.';

    /**
     * Raise warnings as exceptions, as Laravel does, so settings read quietly.
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
     * With nothing set, every setting takes its default.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        foreach ([new RetentionSettings(new Repository), self::settings([])] as $settings) {
            self::assertSame(0, $settings->afterDays());
            self::assertSame([], $settings->categories());
            self::assertSame([], $settings->preserve());
            self::assertSame(1000, $settings->batch());
            self::assertSame(3000, $settings->maxSeconds());
            self::assertSame('30 3 * * *', $settings->schedule());
            self::assertFalse($settings->retainsAnythingForLess());
        }

        self::assertSame([], self::settings(['categories' => null, 'preserve' => null])->categories());
        self::assertSame([], self::settings(['categories' => null, 'preserve' => null])->preserve());
    }

    /**
     * Each setting accepts its bounds and is read again on every call.
     *
     * @return void
     */
    public function testTheBoundsAreAccepted(): void
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            foreach ([$least, $most] as $value) {
                self::assertSame($value, self::number(self::settings([$key => $value]), $method), $key);
            }
        }

        $settings = self::settings(['categories' => ['security' => 36500, 'general' => 0], 'preserve' => ['security' => 36500, 'audit' => 0]]);

        self::assertSame(['general' => 0, 'security' => 36500], $settings->categories());
        self::assertSame(['audit' => 0, 'security' => 36500], $settings->preserve());

        $config   = new Repository(['audit-log' => ['retention' => ['batch' => 100]]]);
        $settings = new RetentionSettings($config);

        self::assertSame(100, $settings->batch());

        $config->set('audit-log.retention.batch', 250);

        self::assertSame(250, $settings->batch());
    }

    /**
     * Each number and day count accepts an environment digit string.
     *
     * @return void
     */
    public function testADigitStringFromTheEnvironmentIsRead(): void
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            foreach ([(string) $least, (string) $most] as $value) {
                self::assertSame((int) $value, self::number(self::settings([$key => $value]), $method), $key);
            }
        }

        self::assertSame(['general' => 365], self::settings(['categories' => ['general' => '365']])->categories());
        self::assertSame(['general' => 0], self::settings(['preserve' => ['general' => '0']])->preserve());
    }

    /**
     * Rows of `[value]`: day counts below 0, above 36500, or naming no integer.
     *
     * @return iterable<string, array{0: float|int|string}>
     */
    public static function provideDayCountsOutOfRange(): iterable
    {
        yield from [
            'one below the least'     => [-1],
            'one above the greatest'  => [36501],
            'an exponent'             => ['1e3'],
            'a fraction'              => [1.5],
            'a padded digit string'   => [' 30'],
            'a signed digit string'   => ['+30'],
            'a digit string above'    => ['36501'],
            'a fraction digit string' => ['1.0'],
        ];
    }

    /**
     * A malformed day count is refused, naming the key that holds it.
     *
     * @param  float|int|string  $value
     * @return void
     */
    #[DataProvider('provideDayCountsOutOfRange')]
    public function testRefusesADayCountOutsideItsRange(float|int|string $value): void
    {
        $refusals = [
            'afterDays'  => [['after_days' => $value], '`audit-log.retention.after_days` must be an integer from 0 to 36500.'],
            'categories' => [['categories' => ['general' => $value]], '`audit-log.retention.categories.general` must be an integer from 0 to 36500.'],
            'preserve'   => [['preserve' => ['general' => $value]], '`audit-log.retention.preserve.general` must be an integer from 0 to 36500.'],
        ];

        foreach ($refusals as $method => [$retention, $message]) {
            foreach ([$method, 'validate'] as $reader) {
                try {
                    self::read(self::settings($retention), $reader);

                    self::fail("Expected {$method} to be refused by {$reader}().");
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame($message, $exception->getMessage(), "{$method} by {$reader}()");
                }
            }
        }
    }

    /**
     * Rows of `[value]`: map settings that are no map of categories.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMapsThatAreNoMap(): iterable
    {
        yield from [
            'a list of days'      => [[30, 365]],
            'a list of one'       => [[30]],
            'a number'            => [30],
            'a string'            => ['general'],
            'false'               => [false],
            'an object'           => [new \stdClass],
            'a list of day pairs' => [[['general', 30]]],
        ];
    }

    /**
     * A map setting that is a list or no array is refused, naming its key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMapsThatAreNoMap')]
    public function testRefusesACategoryMapThatIsAList(mixed $value): void
    {
        foreach (['categories', 'preserve'] as $map) {
            try {
                self::read(self::settings([$map => $value]), $map);

                self::fail("Expected {$map} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf(self::MAP, $map), $exception->getMessage(), $map);
            }
        }
    }

    /**
     * Rows of `[key]`: map keys outside the category grammar.
     *
     * @return iterable<string, array{0: int|string}>
     */
    public static function provideKeysOutsideTheGrammar(): iterable
    {
        yield from [
            'upper case'          => ['General'],
            'a leading digit'     => ['1general'],
            'a leading score'     => ['_general'],
            'a dot'               => ['general.reads'],
            'a hyphen'            => ['general-reads'],
            'empty'               => [''],
            'sixty-five long'     => ['a' . str_repeat('b', 64)],
            'an integer key'      => [7],
            'a trailing new line' => ["general\n"],
        ];
    }

    /**
     * A map key outside the category grammar is refused without naming the key.
     *
     * @param  int|string  $key
     * @return void
     */
    #[DataProvider('provideKeysOutsideTheGrammar')]
    public function testRefusesACategoryKeyOutsideTheGrammar(int|string $key): void
    {
        foreach (['categories', 'preserve'] as $map) {
            try {
                self::read(self::settings([$map => ['general' => 30, $key => 30]]), $map);

                self::fail("Expected {$map} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf(self::CATEGORY, $map), $exception->getMessage(), $map);
            }
        }

        self::assertSame(['a' . str_repeat('b', 63) => 1], self::settings(['categories' => ['a' . str_repeat('b', 63) => 1]])->categories());
    }

    /**
     * The chunk size is refused below 100, above 10000 or as a non-integer.
     *
     * @return void
     */
    public function testRefusesABatchOutsideItsRange(): void
    {
        foreach ([99, 10001, '1e3', 1.5, null, true] as $value) {
            try {
                self::settings(['batch' => $value])->batch();

                self::fail('Expected the batch to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`audit-log.retention.batch` must be an integer from 100 to 10000.', $exception->getMessage(), var_export($value, true));
            }
        }
    }

    /**
     * The time budget is refused below a minute, above a day or non-integer.
     *
     * @return void
     */
    public function testRefusesAMaxSecondsOutsideItsRange(): void
    {
        foreach ([59, 86401, '3e3', 60.5, null, false] as $value) {
            try {
                self::settings(['max_seconds' => $value])->maxSeconds();

                self::fail('Expected the time budget to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`audit-log.retention.max_seconds` must be an integer from 60 to 86400.', $exception->getMessage(), var_export($value, true));
            }
        }
    }

    /**
     * The schedule is a cron expression, or none when `null` or empty.
     *
     * @return void
     */
    public function testTheScheduleIsACronExpressionOrNone(): void
    {
        self::assertSame('30 3 * * *', self::settings([])->schedule());
        self::assertSame('0 4 * * 1', self::settings(['schedule' => '0 4 * * 1'])->schedule());
        self::assertSame('@daily', self::settings(['schedule' => '@daily'])->schedule());
        self::assertNull(self::settings(['schedule' => null])->schedule());
        self::assertNull(self::settings(['schedule' => ''])->schedule());

        foreach (['every night', '61 3 * * *', 5, false, ['30 3 * * *']] as $value) {
            try {
                self::settings(['schedule' => $value])->schedule();

                self::fail('Expected the schedule to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`audit-log.retention.schedule` must be a cron expression, or null or empty to schedule nothing.', $exception->getMessage());
            }
        }
    }

    /**
     * Something is kept for less than forever only when a retention is finite.
     *
     * @return void
     */
    public function testRetainsAnythingForLess(): void
    {
        self::assertTrue(self::settings(['after_days' => 1])->retainsAnythingForLess());
        self::assertTrue(self::settings(['categories' => ['general' => 1]])->retainsAnythingForLess());
        self::assertTrue(self::settings(['categories' => ['audit' => 0, 'general' => 1]])->retainsAnythingForLess());
        self::assertFalse(self::settings(['categories' => ['general' => 0]])->retainsAnythingForLess());
        self::assertFalse(self::settings(['preserve' => ['general' => 30]])->retainsAnythingForLess());
        self::assertFalse(self::settings(['after_days' => 0, 'categories' => []])->retainsAnythingForLess());
    }

    /**
     * Rows of `[retention, the key named]`: kept less than preserved.
     *
     * @return iterable<string, array{0: array<string, array<string, int>|int>, 1: string}>
     */
    public static function provideRetentionsShorterThanTheirPreservation(): iterable
    {
        yield from [
            'its own retention, one day short' => [['categories' => ['security' => 364], 'preserve' => ['security' => 365]], 'categories.security'],
            'the default, one day short'       => [['after_days' => 29, 'preserve' => ['security' => 30]], 'after_days'],
            'its own, beside a longer default' => [['after_days' => 400, 'categories' => ['security' => 30], 'preserve' => ['security' => 60]], 'categories.security'],
            'the second of two categories'     => [['after_days' => 90, 'preserve' => ['audit' => 30, 'security' => 91]], 'after_days'],
        ];
    }

    /**
     * Validation refuses a retention shorter than its preservation.
     *
     * @param  array<string, array<string, int>|int>  $retention
     * @param  string  $kept
     * @return void
     */
    #[DataProvider('provideRetentionsShorterThanTheirPreservation')]
    public function testRefusesARetentionShorterThanItsPreservation(array $retention, string $kept): void
    {
        $category = array_key_last((array) $retention['preserve']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(self::CONFLICT, $kept, $category));

        self::settings($retention)->validate();
    }

    /**
     * A retention at least its preservation, or forever, passes.
     *
     * @return void
     */
    public function testARetentionAtLeastItsPreservationPasses(): void
    {
        $passing = [
            ['categories' => ['security' => 365], 'preserve' => ['security' => 365]],
            ['categories' => ['security' => 366], 'preserve' => ['security' => 365]],
            ['after_days' => 30, 'categories' => ['security' => 0], 'preserve' => ['security' => 0]],
            ['after_days' => 0, 'preserve' => ['security' => 36500]],
            ['after_days' => 30, 'categories' => ['security' => 400], 'preserve' => ['security' => 400]],
            ['after_days' => 30, 'preserve' => []],
        ];

        foreach ($passing as $retention) {
            self::settings($retention)->validate();
        }

        $this->addToAssertionCount(count($passing));
    }

    /**
     * A category preserved forever must be kept forever.
     *
     * @return void
     */
    public function testAForeverPreservationNeedsAForeverRetention(): void
    {
        foreach ([[['categories' => ['security' => 36500]], 'categories.security'], [['after_days' => 36500], 'after_days']] as [$retention, $kept]) {
            try {
                self::settings([...$retention, 'preserve' => ['security' => 0]])->validate();

                self::fail('Expected the retention to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf(self::CONFLICT, $kept, 'security'), $exception->getMessage());
            }
        }

        self::settings(['after_days' => 30, 'categories' => ['security' => 0], 'preserve' => ['security' => 0]])->validate();
        self::settings(['preserve' => ['security' => 0]])->validate();

        $this->addToAssertionCount(2);
    }

    /**
     * Validation reads every setting, failing on any malformed one.
     *
     * @return void
     */
    public function testValidateReadsEverySetting(): void
    {
        $malformed = [
            'after_days'  => [-1, '`audit-log.retention.after_days` must be an integer from 0 to 36500.'],
            'categories'  => [[30], sprintf(self::MAP, 'categories')],
            'preserve'    => [['Bad' => 1], sprintf(self::CATEGORY, 'preserve')],
            'batch'       => [99, '`audit-log.retention.batch` must be an integer from 100 to 10000.'],
            'max_seconds' => [59, '`audit-log.retention.max_seconds` must be an integer from 60 to 86400.'],
            'schedule'    => ['nightly', '`audit-log.retention.schedule` must be a cron expression, or null or empty to schedule nothing.'],
        ];

        foreach ($malformed as $key => [$value, $message]) {
            try {
                self::settings([$key => $value])->validate();

                self::fail("Expected {$key} to fail validation.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage(), $key);
            }
        }

        self::settings([
            'after_days'  => 30,
            'categories'  => ['security' => 0],
            'preserve'    => ['security' => 0],
            'batch'       => 100,
            'max_seconds' => 60,
            'schedule'    => null,
        ])->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * The value of the numeric reader the method names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings  $settings
     * @param  string  $method
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function number(RetentionSettings $settings, string $method): int
    {
        return match ($method) {
            'afterDays'  => $settings->afterDays(),
            'batch'      => $settings->batch(),
            'maxSeconds' => $settings->maxSeconds(),
            default      => self::fail(sprintf('No numeric reader is named %s.', $method)),
        };
    }

    /**
     * Call the reader the method names, for what it refuses.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings  $settings
     * @param  string  $method
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function read(RetentionSettings $settings, string $method): void
    {
        match ($method) {
            'afterDays'  => $settings->afterDays(),
            'categories' => $settings->categories(),
            'preserve'   => $settings->preserve(),
            'validate'   => $settings->validate(),
            default      => self::fail(sprintf('No reader is named %s.', $method)),
        };
    }

    /**
     * Retention settings over the retention section given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $retention
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings
     */
    private static function settings(array $retention): RetentionSettings
    {
        return new RetentionSettings(new Repository(['audit-log' => ['retention' => $retention]]));
    }
}
