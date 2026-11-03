<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;
use SineMacula\Laravel\AuditLog\Stores\FailureSettings;

/**
 * Unit tests for the failure settings: the default of each, the values each
 * accepts, the exact message each malformed value fails closed with, the reader
 * of every setting, and the values no message or stack trace ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureSettings::class)]
final class FailureSettingsTest extends TestCase
{
    /** @var string The refusal of an unknown mode. */
    private const string MODE = '`audit-log.failure.mode` must be `report` or `throw`.';

    /** @var string The refusal of a malformed log channel. */
    private const string CHANNEL = '`audit-log.failure.log_channel` must be a channel name of 1 to 64 characters, or null or empty for the default channel.';

    /**
     * With nothing set, or none of the package's configuration at all, a
     * failure is reported.
     *
     * @return void
     */
    public function testTheModeDefaultsToReport(): void
    {
        self::assertSame(FailureMode::REPORT, (new FailureSettings(new Repository))->mode());
        self::assertSame(FailureMode::REPORT, self::settings([])->mode());
    }

    /**
     * Every mode is read by its stored value, and each read goes back to the
     * configuration, so a change is seen by the next read.
     *
     * @return void
     */
    public function testTheModeIsReadAsConfigured(): void
    {
        foreach (FailureMode::cases() as $mode) {
            self::assertSame($mode, self::settings(['mode' => $mode->value])->mode());
        }

        $config   = new Repository(['audit-log' => ['failure' => ['mode' => 'throw']]]);
        $settings = new FailureSettings($config);

        self::assertSame(FailureMode::THROW, $settings->mode());

        $config->set('audit-log.failure.mode', 'report');

        self::assertSame(FailureMode::REPORT, $settings->mode());
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
            'an unknown name'  => ['maybe'],
            'true'             => [true],
            'null'             => [null],
            'an integer'       => [1],
            'empty'            => [''],
            'upper case'       => ['REPORT'],
            'padded'           => [' throw'],
            'a list'           => [['report']],
            'the enum, itself' => [FailureMode::REPORT],
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
     * With no channel set, or one set to `null`, the spill goes to the default
     * channel.
     *
     * @return void
     */
    public function testTheChannelDefaultsToTheDefaultChannel(): void
    {
        self::assertNull((new FailureSettings(new Repository))->logChannel());
        self::assertNull(self::settings([])->logChannel());
        self::assertNull(self::settings(['log_channel' => null])->logChannel());
    }

    /**
     * An empty channel, as an unset environment variable gives it, is the
     * default channel.
     *
     * @return void
     */
    public function testAnEmptyChannelIsTheDefaultChannel(): void
    {
        self::assertNull(self::settings(['log_channel' => ''])->logChannel());
    }

    /**
     * Rows of `[channel]`: names the setting accepts, at each end of its
     * length, counted in characters rather than bytes (protects against a
     * mutation that counts bytes).
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAcceptedChannels(): iterable
    {
        yield from [
            'one character'                => ['a'],
            'a stack channel'              => ['audit'],
            '64 characters'                => [str_repeat('a', 64)],
            '64 characters of two bytes'   => [str_repeat('é', 64)],
            'a name with spaces and marks' => ['audit spill-1.log'],
        ];
    }

    /**
     * A configured channel is the one the spill goes to, as configured.
     *
     * @param  string  $channel
     * @return void
     */
    #[DataProvider('provideAcceptedChannels')]
    public function testTheChannelIsReadAsConfigured(string $channel): void
    {
        self::assertSame($channel, self::settings(['log_channel' => $channel])->logChannel());
    }

    /**
     * Rows of `[value]`: values that are not a channel name of 1 to 64
     * characters.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedChannels(): iterable
    {
        yield from [
            'an integer'      => [42],
            '65 characters'   => [str_repeat('a', 65)],
            'an empty list'   => [[]],
            'a list'          => [['audit']],
            'false'           => [false],
            '65 of two bytes' => [str_repeat('é', 65)],
        ];
    }

    /**
     * Each malformed channel fails closed with its message, rather than falling
     * back to the default channel.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedChannels')]
    public function testRefusesAMalformedChannel(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CHANNEL);

        self::settings(['log_channel' => $value])->logChannel();
    }

    /**
     * Rows of `[setting, value, message]`: one malformed setting at a time,
     * each of those `validate()` reads.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'mode'        => ['mode', 'maybe', self::MODE],
            'log_channel' => ['log_channel', 42, self::CHANNEL],
        ];
    }

    /**
     * `validate()` reads every setting: each malformed one fails it, alone,
     * with its own message.
     *
     * @param  string  $setting
     * @param  int|string  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testValidateReadsEverySetting(string $setting, int|string $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings([$setting => $value])->validate();
    }

    /**
     * With both settings malformed, `validate()` fails on the mode, and with
     * both well formed, or neither set, it passes.
     *
     * @return void
     */
    public function testTheFirstMalformedSettingWins(): void
    {
        self::settings([])->validate();
        self::settings(['mode' => 'throw', 'log_channel' => 'audit'])->validate();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODE);

        self::settings(['mode' => 'maybe', 'log_channel' => 42])->validate();
    }

    /**
     * Rows of `[setting]`: each setting, set to a sentinel it refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSettings(): iterable
    {
        yield from [
            'mode'        => ['mode'],
            'log_channel' => ['log_channel'],
        ];
    }

    /**
     * A refusal names the setting's full key and never the value it refused, in
     * its message or in the arguments of the settings' own frames of its stack
     * trace.
     *
     * @param  string  $setting
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testAMessageNamesTheKeyAndNeverTheValue(string $setting): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        $sentinel = 'S3NTINEL' . str_repeat('x', 64);

        try {
            self::settings([$setting => $sentinel])->validate();
            self::fail('Expected the value to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === FailureSettings::class);

            self::assertNotSame([], $frames);
            self::assertStringContainsString('`audit-log.failure.' . $setting . '`', $exception->getMessage());
            self::assertStringNotContainsString('S3NTINEL', $exception->getMessage());
            self::assertStringNotContainsString('S3NTINEL', print_r($frames, true));
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * Settings over a plain repository holding the failure settings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $failure
     * @return \SineMacula\Laravel\AuditLog\Stores\FailureSettings
     */
    private static function settings(array $failure): FailureSettings
    {
        return new FailureSettings(new Repository(['audit-log' => ['failure' => $failure]]));
    }
}
