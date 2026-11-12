<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use Tests\Concerns\RaisesWarningsAsExceptions;

/**
 * Unit tests for the sealing settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealSettings::class)]
final class SealSettingsTest extends TestCase
{
    use RaisesWarningsAsExceptions;

    /** @var string The refusal of a malformed log id. */
    private const string LOG_ID = '`audit-log.integrity.log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string The refusal of a source id that is no log id. */
    private const string SOURCE_ID = '`audit-log.integrity.log_id` is empty, so `audit-log.source.id` is the log id, and it must be 1 to 64 letters, digits, dots,'
        . ' underscores or hyphens, starting with a letter or a digit.';

    /** @var string The refusal of a malformed schedule, by its key. */
    private const string SCHEDULE = '`%s` must be a cron expression, or null or empty to schedule nothing.';

    /** @var array<string, array{0: string, 1: int, 2: int, 3: int}> Each numeric reader, by its key under `audit-log.integrity.`: its method, default, least and greatest value. */
    private const array NUMBERS = [
        'seal.batch'                      => ['batch', 5000, 100, 50000],
        'seal.max_batches'                => ['maxBatches', 100, 1, 100000],
        'seal.lookback_seconds'           => ['lookbackSeconds', 3600, 0, 2592000],
        'seal.settle_seconds'             => ['settleSeconds', 0, 0, 3600],
        'seal.max_attempts'               => ['maxAttempts', 5, 1, 100],
        'verify.max_unsealed_age_seconds' => ['maxUnsealedAgeSeconds', 90000, 600, 31536000],
    ];

    /** @var array<string, array{0: string, 1: string}> Each schedule reader, by its key under `audit-log.integrity.`: its method and default. */
    private const array SCHEDULES = [
        'seal.schedule'       => ['sealSchedule', '*/5 * * * *'],
        'seal.sweep_schedule' => ['sweepSchedule', '15 3 * * *'],
        'verify.schedule'     => ['verifySchedule', '45 3 * * *'],
    ];

    /**
     * With nothing set, or none of the package's configuration at all, each
     * number takes its default.
     *
     * @return void
     */
    public function testTheNumbersHaveTheirDefaults(): void
    {
        foreach ([new SealSettings(new Repository), self::settings([])] as $settings) {
            self::assertSame(5000, $settings->batch());
            self::assertSame(100, $settings->maxBatches());
            self::assertSame(3600, $settings->lookbackSeconds());
            self::assertSame(0, $settings->settleSeconds());
            self::assertSame(5, $settings->maxAttempts());
            self::assertSame(90000, $settings->maxUnsealedAgeSeconds());
        }
    }

    /**
     * Each number accepts its least and greatest value, as an integer or as the
     * digit string an environment line gives, and is read again on every call.
     *
     * @return void
     */
    public function testTheNumbersAcceptTheirBoundsAndDigitStrings(): void
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            foreach ([$least, $most, (string) $least, (string) $most] as $value) {
                self::assertSame((int) $value, self::number(self::settings(self::nested($key, $value)), $method), $key);
            }
        }

        $config   = new Repository(['audit-log' => ['integrity' => ['seal' => ['batch' => 100]]]]);
        $settings = new SealSettings($config);

        self::assertSame(100, $settings->batch());

        $config->set('audit-log.integrity.seal.batch', '250');

        self::assertSame(250, $settings->batch());
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
            $message = sprintf('`audit-log.integrity.%s` must be an integer from %d to %d.', $key, $least, $most);

            yield $key . ', one below the least' => [$key, $method, $least - 1, $message];
            yield $key . ', one above the greatest' => [$key, $method, $most + 1, $message];
        }

        $batch = '`audit-log.integrity.seal.batch` must be an integer from 100 to 50000.';

        yield from [
            'a padded digit string' => ['seal.batch', 'batch', '0500', $batch],
            'a signed digit string' => ['seal.batch', 'batch', '+500', $batch],
            'a float'               => ['seal.batch', 'batch', 500.0, $batch],
            'null, set explicitly'  => ['seal.batch', 'batch', null, $batch],
            'a word'                => ['seal.batch', 'batch', 'many', $batch],
        ];
    }

    /**
     * Each number outside its range, or in a form that names no integer, fails
     * closed with its message.
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
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::number(self::settings(self::nested($key, $value)), $method);
    }

    /**
     * A configured log id is kept as given, never slugged, from one character
     * to 64, and is read again on every call.
     *
     * @return void
     */
    public function testTheLogIdIsReadAsConfigured(): void
    {
        foreach (['app-eu-1', 'A', '7', 'a.b_c-D', str_repeat('z', 64)] as $logId) {
            self::assertSame($logId, self::settings(['log_id' => $logId], ['id' => 'other'])->logId());
        }

        $config   = new Repository(['audit-log' => ['integrity' => ['log_id' => 'first'], 'source' => ['id' => 'source']]]);
        $settings = new SealSettings($config);

        self::assertSame('first', $settings->logId());

        $config->set('audit-log.integrity.log_id', 'second');

        self::assertSame('second', $settings->logId());
    }

    /**
     * A missing, `null` or empty log id falls back to the source id.
     *
     * @return void
     */
    public function testAnEmptyLogIdIsTheSourceId(): void
    {
        foreach ([[], ['log_id' => null], ['log_id' => '']] as $integrity) {
            self::assertSame('app-eu-1', self::settings($integrity, ['id' => 'app-eu-1'])->logId());
        }

        $settings = new SealSettings(new Repository(['app' => ['name' => 'Invoice Service'], 'audit-log' => ['integrity' => ['log_id' => '']]]));

        self::assertSame('invoice-service', $settings->logId());
    }

    /**
     * Rows of `[log id]`: values outside the log id grammar, or of another
     * type.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedLogIds(): iterable
    {
        yield from [
            'a leading hyphen'   => ['-a'],
            'a slash'            => ['a/b'],
            'two dots'           => ['..'],
            '65 characters'      => [str_repeat('a', 65)],
            'an integer'         => [42],
            'a space'            => ['app eu'],
            'a trailing line'    => ["app\n"],
            'a list'             => [['app']],
            'true'               => [true],
            'a leading dot'      => ['.app'],
            'a non-ASCII letter' => ['appé'],
        ];
    }

    /**
     * Each malformed log id fails closed with its message, never falling back
     * to the source id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $logId
     * @return void
     */
    #[DataProvider('provideMalformedLogIds')]
    public function testRefusesAMalformedLogId(mixed $logId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::LOG_ID);

        self::settings(['log_id' => $logId], ['id' => 'app-eu-1'])->logId();
    }

    /**
     * Rows of `[source id]`: source ids the source settings accept that are no
     * log id.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSourceIdsThatAreNoLogId(): iterable
    {
        yield from [
            'a space'            => ['app eu'],
            'a slash'            => ['app/eu'],
            'a leading hyphen'   => ['-app'],
            'a leading dot'      => ['.app'],
            'a colon'            => ['app:eu'],
            'a non-ASCII letter' => ['appé'],
        ];
    }

    /**
     * With no log id, a source id that does not fit the log id grammar fails
     * closed with a message naming both keys.
     *
     * @param  string  $sourceId
     * @return void
     */
    #[DataProvider('provideSourceIdsThatAreNoLogId')]
    public function testRefusesASourceIdThatIsNoLogId(string $sourceId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::SOURCE_ID);

        self::settings([], ['id' => $sourceId])->logId();
    }

    /**
     * A source id the source settings refuse is refused with their message.
     *
     * @return void
     */
    public function testASourceIdTheSourceRefusesIsRefusedAsTheSourceSays(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.source.id` must be set, because `app.name` gives no slug.');

        (new SealSettings(new Repository(['app' => ['name' => '!!!']])))->logId();
    }

    /**
     * With nothing set, each schedule takes its default.
     *
     * @return void
     */
    public function testTheSchedulesHaveTheirDefaults(): void
    {
        foreach ([new SealSettings(new Repository), self::settings([])] as $settings) {
            self::assertSame('*/5 * * * *', $settings->sealSchedule());
            self::assertSame('15 3 * * *', $settings->sweepSchedule());
            self::assertSame('45 3 * * *', $settings->verifySchedule());
        }
    }

    /**
     * A `null` or empty schedule schedules nothing; any cron expression is kept
     * as given.
     *
     * @return void
     */
    public function testAnEmptyOrNullScheduleIsNone(): void
    {
        foreach (self::SCHEDULES as $key => [$method]) {
            self::assertNull(self::schedule(self::settings(self::nested($key, null)), $method), $key);
            self::assertNull(self::schedule(self::settings(self::nested($key, '')), $method), $key);
            self::assertSame('0 * * * *', self::schedule(self::settings(self::nested($key, '0 * * * *')), $method), $key);
            self::assertSame('@daily', self::schedule(self::settings(self::nested($key, '@daily')), $method), $key);
        }
    }

    /**
     * Rows of `[key, method, value]`: values that are no cron expression, for
     * each schedule.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: string, 2: mixed}>
     */
    public static function provideMalformedSchedules(): iterable
    {
        foreach (self::SCHEDULES as $key => [$method]) {
            $values = ['words' => 'every five minutes', 'three fields' => '* * *', 'minute 61' => '61 * * * *', 'a list' => [], 'an integer' => 5, 'false' => false];

            foreach ($values as $what => $value) {
                yield $key . ', ' . $what => [$key, $method, $value];
            }
        }
    }

    /**
     * Each value that is no cron expression fails closed, naming the key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  string  $method
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedSchedules')]
    public function testRefusesAMalformedSchedule(string $key, string $method, mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(self::SCHEDULE, 'audit-log.integrity.' . $key));

        self::schedule(self::settings(self::nested($key, $value)), $method);
    }

    /**
     * Rows of `[integrity settings, source settings, message]`: a settings set
     * malformed in one setting alone, for each setting the reader reads.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: string}>
     */
    public static function provideSettingsMalformedOnce(): iterable
    {
        yield 'log_id' => [['log_id' => 'a/b'], ['id' => 'app-eu-1'], self::LOG_ID];
        yield 'source.id' => [[], ['id' => 'app eu'], self::SOURCE_ID];

        foreach (self::NUMBERS as $key => [, , $least, $most]) {
            yield $key => [self::nested($key, $most + 1), ['id' => 'app-eu-1'], sprintf('`audit-log.integrity.%s` must be an integer from %d to %d.', $key, $least, $most)];
        }

        foreach (array_keys(self::SCHEDULES) as $key) {
            yield $key => [self::nested($key, '* * *'), ['id' => 'app-eu-1'], sprintf(self::SCHEDULE, 'audit-log.integrity.' . $key)];
        }
    }

    /**
     * The reader reads every setting: well-formed settings pass, and a setting
     * malformed alone fails it with that setting's message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $source
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideSettingsMalformedOnce')]
    public function testValidateReadsEverySetting(array $integrity, array $source, string $message): void
    {
        self::settings([], ['id' => 'app-eu-1'])->validate();
        (new SealSettings(new Repository(['app' => ['name' => 'Invoices']])))->validate();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($integrity, $source)->validate();
    }

    /**
     * The first malformed setting wins: the log id is read before the numbers,
     * and the numbers before the schedules.
     *
     * @return void
     */
    public function testTheFirstFailureWins(): void
    {
        $integrity = ['log_id' => 'a/b', 'seal' => ['batch' => 1, 'schedule' => 'x']];

        $messages = [];

        foreach ([$integrity, ['seal' => ['batch' => 1, 'schedule' => 'x']], ['seal' => ['schedule' => 'x']]] as $settings) {
            try {
                self::settings($settings, ['id' => 'app-eu-1'])->validate();
                self::fail('Expected the settings to be refused.');
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        $batch = '`audit-log.integrity.seal.batch` must be an integer from 100 to 50000.';

        self::assertSame([self::LOG_ID, $batch, sprintf(self::SCHEDULE, 'audit-log.integrity.seal.schedule')], $messages);
    }

    /**
     * Every refusal names the key and never quotes the value.
     *
     * @return void
     */
    public function testAMessageNamesTheKeyAndNeverTheValue(): void
    {
        $refusals = [
            'audit-log.integrity.log_id'              => static fn () => self::settings(['log_id' => 's3cr3t/x'])->logId(),
            'audit-log.source.id'                     => static fn () => self::settings([], ['id' => 's3cr3t x'])->logId(),
            'audit-log.integrity.seal.batch'          => static fn () => self::settings(['seal' => ['batch' => 's3cr3t']])->batch(),
            'audit-log.integrity.seal.max_attempts'   => static fn () => self::settings(['seal' => ['max_attempts' => 's3cr3t']])->maxAttempts(),
            'audit-log.integrity.seal.sweep_schedule' => static fn () => self::settings(['seal' => ['sweep_schedule' => 's3cr3t']])->sweepSchedule(),
            'audit-log.integrity.verify.schedule'     => static fn () => self::settings(['verify' => ['schedule' => '* s3cr3t *']])->verifySchedule(),
        ];

        foreach ($refusals as $key => $refusal) {
            try {
                $refusal();
                self::fail(sprintf('Expected `%s` to be refused.', $key));
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('`' . $key . '`', $exception->getMessage(), $key);
                self::assertStringNotContainsStringIgnoringCase('s3cr3t', $exception->getMessage(), $key);
                self::assertNull($exception->getPrevious(), $key);
            }
        }
    }

    /**
     * The numeric reader's answer.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  string  $method
     * @return int
     */
    private static function number(SealSettings $settings, string $method): int
    {
        return match ($method) {
            'batch'                 => $settings->batch(),
            'maxBatches'            => $settings->maxBatches(),
            'lookbackSeconds'       => $settings->lookbackSeconds(),
            'settleSeconds'         => $settings->settleSeconds(),
            'maxAttempts'           => $settings->maxAttempts(),
            'maxUnsealedAgeSeconds' => $settings->maxUnsealedAgeSeconds(),
            default                 => self::fail(sprintf('No numeric reader is named %s.', $method)),
        };
    }

    /**
     * The schedule reader's answer.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  string  $method
     * @return ?string
     */
    private static function schedule(SealSettings $settings, string $method): ?string
    {
        return match ($method) {
            'sealSchedule'   => $settings->sealSchedule(),
            'sweepSchedule'  => $settings->sweepSchedule(),
            'verifySchedule' => $settings->verifySchedule(),
            default          => self::fail(sprintf('No schedule reader is named %s.', $method)),
        };
    }

    /**
     * The integrity settings holding the value under the dotted key given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return array<string, mixed>
     */
    private static function nested(string $key, mixed $value): array
    {
        [$section, $leaf] = explode('.', $key, 2);

        return [$section => [$leaf => $value]];
    }

    /**
     * Settings over the integrity and source settings given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $source
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSettings
     */
    private static function settings(array $integrity, array $source = ['id' => 'app-eu-1']): SealSettings
    {
        return new SealSettings(new Repository(['audit-log' => ['integrity' => $integrity, 'source' => $source]]));
    }
}
