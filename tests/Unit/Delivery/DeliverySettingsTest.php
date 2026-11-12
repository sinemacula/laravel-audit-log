<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;

/**
 * Unit tests for the delivery settings and the messages they fail closed with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliverySettings::class)]
final class DeliverySettingsTest extends TestCase
{
    /** @var string The refusal of an unknown mode. */
    private const string MODE = '`audit-log.delivery.mode` must be `sync` or `outbox`.';

    /** @var string The refusal of a lease out of range. */
    private const string LEASE = '`audit-log.delivery.outbox.lease_seconds` must be an integer from 30 to 86400.';

    /** @var string The refusal of a number of attempts out of range. */
    private const string ATTEMPTS = '`audit-log.delivery.outbox.max_attempts` must be an integer from 1 to 1000.';

    /** @var string The refusal of a backoff out of range. */
    private const string BACKOFF = '`audit-log.delivery.outbox.backoff_seconds` must be an integer from 1 to 3600.';

    /** @var string The refusal of a malformed outbox connection. */
    private const string CONNECTION = '`audit-log.delivery.outbox.connection` must be a connection name, or null or empty for the storage connection.';

    /** @var string The refusal of a malformed outbox table. */
    private const string OUTBOX_TABLE = '`audit-log.delivery.outbox.table`' . self::TABLE;

    /** @var string The refusal of a malformed receipts table. */
    private const string DELIVERIES_TABLE = '`audit-log.delivery.deliveries_table`' . self::TABLE;

    /** @var string What a malformed table is refused with, after its key. */
    private const string TABLE = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';

    /**
     * Forget the repository the `Config` facade was pointed at.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Config::clearResolvedInstance();

        parent::tearDown();
    }

    /**
     * With nothing set, or none of the package's configuration at all, a record
     * is written by the code that records it.
     *
     * @return void
     */
    public function testTheModeDefaultsToSync(): void
    {
        self::assertSame(DeliveryMode::SYNC, (new DeliverySettings(new Repository))->mode());
        self::assertSame(DeliveryMode::SYNC, self::settings([])->mode());
    }

    /**
     * Every mode is read by its stored value, and each read goes back to the
     * configuration, so a change is seen by the next read.
     *
     * @return void
     */
    public function testTheModeIsReadAsConfigured(): void
    {
        foreach (DeliveryMode::cases() as $mode) {
            self::assertSame($mode, self::settings(['mode' => $mode->value])->mode());
        }

        $config   = new Repository(['audit-log' => ['delivery' => ['mode' => 'outbox']]]);
        $settings = new DeliverySettings($config);

        self::assertSame(DeliveryMode::OUTBOX, $settings->mode());

        $config->set('audit-log.delivery.mode', 'sync');

        self::assertSame(DeliveryMode::SYNC, $settings->mode());
    }

    /**
     * Rows of `[value]`: what names no mode, or is no string; a `null` set
     * explicitly is malformed, unlike a missing key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideModesThatAreNoCase(): iterable
    {
        yield from [
            'an unknown name'  => ['queue'],
            'true'             => [true],
            'null'             => [null],
            'an integer'       => [1],
            'empty'            => [''],
            'upper case'       => ['SYNC'],
            'padded'           => ['outbox '],
            'a list'           => [['sync']],
            'the enum, itself' => [DeliveryMode::SYNC],
        ];
    }

    /**
     * Each value that names no mode fails closed with its message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideModesThatAreNoCase')]
    public function testRefusesAModeThatIsNoCase(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODE);

        self::settings(['mode' => $value])->mode();
    }

    /**
     * With nothing set, a claim lasts five minutes, a row gets ten attempts,
     * and the first retry waits a minute.
     *
     * @return void
     */
    public function testTheNumbersHaveTheirDefaults(): void
    {
        foreach ([new DeliverySettings(new Repository), self::settings([]), self::settings(['outbox' => []])] as $settings) {
            self::assertSame(300, $settings->leaseSeconds());
            self::assertSame(10, $settings->maxAttempts());
            self::assertSame(60, $settings->backoffSeconds());
        }
    }

    /**
     * Each number takes its least and greatest value, as an integer and as a
     * digit string.
     *
     * @return void
     */
    public function testTheNumbersAcceptTheirBoundsAndDigitStrings(): void
    {
        $least = self::settings(['outbox' => ['lease_seconds' => 30, 'max_attempts' => 1, 'backoff_seconds' => 1]]);
        $most  = self::settings(['outbox' => ['lease_seconds' => '86400', 'max_attempts' => '1000', 'backoff_seconds' => '3600']]);

        self::assertSame([30, 1, 1], [$least->leaseSeconds(), $least->maxAttempts(), $least->backoffSeconds()]);
        self::assertSame([86400, 1000, 3600], [$most->leaseSeconds(), $most->maxAttempts(), $most->backoffSeconds()]);

        $config   = new Repository;
        $settings = new DeliverySettings($config);

        $config->set('audit-log.delivery.outbox', ['lease_seconds' => '45', 'max_attempts' => '3', 'backoff_seconds' => '5']);

        self::assertSame([45, 3, 5], [$settings->leaseSeconds(), $settings->maxAttempts(), $settings->backoffSeconds()]);
    }

    /**
     * Rows of `[setting, value, message]`: least minus one and most plus one
     * for each number, and values that are no integer at all.
     *
     * @return iterable<string, array{0: string, 1: bool|float|int|string|null, 2: string}>
     */
    public static function provideNumbersOutsideTheirRange(): iterable
    {
        yield from [
            'a lease under 30'          => ['lease_seconds', 29, self::LEASE],
            'a lease over a day'        => ['lease_seconds', 86401, self::LEASE],
            'no attempts'               => ['max_attempts', 0, self::ATTEMPTS],
            'over 1000 attempts'        => ['max_attempts', 1001, self::ATTEMPTS],
            'no backoff'                => ['backoff_seconds', 0, self::BACKOFF],
            'a backoff over an hour'    => ['backoff_seconds', 3601, self::BACKOFF],
            'a padded digit string'     => ['lease_seconds', ' 300', self::LEASE],
            'a signed digit string'     => ['max_attempts', '+10', self::ATTEMPTS],
            'a fraction'                => ['backoff_seconds', 60.0, self::BACKOFF],
            'null set explicitly'       => ['lease_seconds', null, self::LEASE],
            'a negative'                => ['max_attempts', -1, self::ATTEMPTS],
            'true'                      => ['backoff_seconds', true, self::BACKOFF],
            'a digit string over range' => ['lease_seconds', '86401', self::LEASE],
        ];
    }

    /**
     * Each number outside its range, or that is no integer, fails closed with
     * its message, naming the setting and the range.
     *
     * @param  string  $setting
     * @param  bool|float|int|string|null  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideNumbersOutsideTheirRange')]
    public function testRefusesANumberOutsideItsRange(string $setting, bool|float|int|string|null $value, string $message): void
    {
        $settings = self::settings(['outbox' => [$setting => $value]]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        match ($setting) {
            'lease_seconds' => $settings->leaseSeconds(),
            'max_attempts'  => $settings->maxAttempts(),
            default         => $settings->backoffSeconds(),
        };
    }

    /**
     * Rows of `[delivery configuration, message]`: one malformed setting at a
     * time.
     *
     * @return iterable<string, array{0: array<string, array<string, int|string>|string>, 1: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'mode'              => [['mode' => 'queue'], self::MODE],
            'lease_seconds'     => [['outbox' => ['lease_seconds' => 29]], self::LEASE],
            'max_attempts'      => [['outbox' => ['max_attempts' => 0]], self::ATTEMPTS],
            'backoff_seconds'   => [['outbox' => ['backoff_seconds' => 0]], self::BACKOFF],
            'outbox connection' => [['outbox' => ['connection' => 42]], self::CONNECTION],
            'outbox table'      => [['outbox' => ['table' => 'Audit']], self::OUTBOX_TABLE],
            'deliveries table'  => [['deliveries_table' => '9a'], self::DELIVERIES_TABLE],
        ];
    }

    /**
     * `validate()` reads every setting: each malformed one fails it, alone,
     * with its own message.
     *
     * @param  array<string, array<string, int|string>|string>  $delivery
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testValidateReadsEverySetting(array $delivery, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($delivery)->validate();
    }

    /**
     * `validate()` fails on the first malformed setting in order until none is
     * left.
     *
     * @return void
     */
    public function testTheFirstMalformedSettingWins(): void
    {
        $delivery = [];

        foreach (self::provideMalformedSettings() as [$malformed]) {
            $delivery = array_replace_recursive($delivery, $malformed);
        }

        foreach (self::provideMalformedSettings() as [$malformed, $message]) {
            try {
                self::settings($delivery)->validate();
                self::fail(sprintf('Expected the settings to be refused with: %s', $message));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }

            $delivery = self::without($delivery, $malformed);
        }

        self::settings($delivery)->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * The configuration with the leaves of the malformed one removed.
     *
     * @param  array<string, array<string, int|string>|string>  $delivery
     * @param  array<string, array<string, int|string>|string>  $malformed
     * @return array<string, array<string, int|string>|string>
     */
    private static function without(array $delivery, array $malformed): array
    {
        foreach ($malformed as $key => $value) {
            if (is_array($value) && is_array($delivery[$key])) {
                $delivery[$key] = array_diff_key($delivery[$key], $value);

                continue;
            }

            unset($delivery[$key]);
        }

        return $delivery;
    }

    /**
     * Settings over a plain repository holding the delivery settings, which the
     * `Config` facade then reads too.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $delivery
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliverySettings
     */
    private static function settings(array $delivery): DeliverySettings
    {
        $config = new Repository(['audit-log' => ['delivery' => $delivery], 'database' => ['default' => 'testing']]);

        Config::swap($config);

        return new DeliverySettings($config);
    }
}
