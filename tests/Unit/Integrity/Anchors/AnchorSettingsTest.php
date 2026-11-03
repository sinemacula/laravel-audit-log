<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Anchors;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;

/**
 * Unit tests for the anchor settings: the default of each, the values each
 * accepts, the exact message each malformed value fails closed with, a driver
 * that is none whenever it is not `disk` by name, a path that can never leave
 * its namespace, and the reader of every setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorSettings::class)]
final class AnchorSettingsTest extends TestCase
{
    /** @var string The refusal of a driver that names no anchor. */
    private const string DRIVER = '`audit-log.integrity.anchor.driver` must be `null` or `disk`.';

    /** @var string The refusal of a malformed disk. */
    private const string DISK = '`audit-log.integrity.anchor.disk` must be a disk name of 1 to 64 characters, or null or empty for the default disk.';

    /** @var string The refusal of a malformed path. */
    private const string PATH = '`audit-log.integrity.anchor.path` must be 1 to 191 characters of path segments of letters, digits,'
        . ' dots, underscores and hyphens, separated by single slashes, with no `.` or `..` segment.';

    /** @var string The refusal of a batch out of range. */
    private const string BATCH = '`audit-log.integrity.anchor.batch` must be an integer from 1 to 10000.';

    /**
     * Rows of `[anchor configuration]`: every way of leaving the driver unset.
     *
     * @return iterable<string, array{0: array<string, string|null>}>
     */
    public static function provideDriversThatAreNone(): iterable
    {
        yield from [
            'missing'         => [[]],
            'PHP null'        => [['driver' => null]],
            'empty'           => [['driver' => '']],
            'the string null' => [['driver' => 'null']],
        ];
    }

    /**
     * A driver that is missing, `null`, empty or the string `null` is no
     * anchor, so the environment line `null` and an empty one both turn the
     * anchor off.
     *
     * @param  array<string, string|null>  $anchor
     * @return void
     */
    #[DataProvider('provideDriversThatAreNone')]
    public function testTheDriverDefaultsToNone(array $anchor): void
    {
        self::assertSame(AnchorDriver::NONE, self::settings($anchor)->driver());
    }

    /**
     * With none of the package's configuration at all, there is no anchor.
     *
     * @return void
     */
    public function testWithNoConfigurationThereIsNoAnchor(): void
    {
        self::assertSame(AnchorDriver::NONE, (new AnchorSettings(new Repository))->driver());
    }

    /**
     * Every driver is read by its stored value, and each read goes back to the
     * configuration, so a change is seen by the next read.
     *
     * @return void
     */
    public function testTheDriverIsReadAsConfigured(): void
    {
        foreach (AnchorDriver::cases() as $driver) {
            self::assertSame($driver, self::settings(['driver' => $driver->value])->driver());
        }

        $config   = new Repository(['audit-log' => ['integrity' => ['anchor' => ['driver' => 'disk']]]]);
        $settings = new AnchorSettings($config);

        self::assertSame(AnchorDriver::DISK, $settings->driver());

        $config->set('audit-log.integrity.anchor.driver', 'null');

        self::assertSame(AnchorDriver::NONE, $settings->driver());
    }

    /**
     * Rows of `[value]`: what names no driver, or is no string; none of them is
     * read as no anchor or as the disk anchor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideDriversThatAreNoCase(): iterable
    {
        yield from [
            'an unknown name'          => ['s3'],
            'the dropped log anchor'   => ['log'],
            'upper case null'          => ['NULL'],
            'upper case disk'          => ['DISK'],
            'padded'                   => ['disk '],
            'the case name'            => ['none'],
            'false'                    => [false],
            'true'                     => [true],
            'zero'                     => [0],
            'a list'                   => [['disk']],
            'the enum, itself'         => [AnchorDriver::DISK],
            'the string null, wrapped' => ['(null)'],
        ];
    }

    /**
     * Each value that names no driver fails closed with its message, rather
     * than turning the anchor off or on.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideDriversThatAreNoCase')]
    public function testRefusesADriverThatIsNoCase(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::DRIVER);

        self::settings(['driver' => $value])->driver();
    }

    /**
     * A disk that is missing, `null` or empty is the default disk, read on
     * every call, and a configured one is kept as given.
     *
     * @return void
     */
    public function testTheDiskDefaultsToTheDefaultDisk(): void
    {
        foreach ([[], ['disk' => null], ['disk' => '']] as $anchor) {
            self::assertSame('local', self::settings($anchor)->disk());
        }

        self::assertSame('anchors', self::settings(['disk' => 'anchors'])->disk());
        self::assertSame(str_repeat('é', 64), self::settings(['disk' => str_repeat('é', 64)])->disk());

        $config   = new Repository(['filesystems' => ['default' => 'local']]);
        $settings = new AnchorSettings($config);

        self::assertSame('local', $settings->disk());

        $config->set('filesystems.default', 's3');

        self::assertSame('s3', $settings->disk());

        $config->set('audit-log.integrity.anchor.disk', 'anchors');

        self::assertSame('anchors', $settings->disk());
    }

    /**
     * Rows of `[anchor configuration, filesystems configuration]`: a disk that
     * is no name, too long or not UTF-8, and a default disk that is no string
     * when none is configured.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideMalformedDisks(): iterable
    {
        yield from [
            '65 characters'               => [['disk' => str_repeat('é', 65)], ['default' => 'local']],
            'not UTF-8'                   => [['disk' => "\xff"], ['default' => 'local']],
            'an integer'                  => [['disk' => 1], ['default' => 'local']],
            'a list'                      => [['disk' => ['local']], ['default' => 'local']],
            'false'                       => [['disk' => false], ['default' => 'local']],
            'no default disk'             => [[], []],
            'a default disk of no string' => [['disk' => null], ['default' => 1]],
            'an empty default disk'       => [['disk' => ''], ['default' => '']],
            'a default disk too long'     => [[], ['default' => str_repeat('a', 65)]],
        ];
    }

    /**
     * Each malformed disk fails closed with its message, and so does a default
     * disk that is no disk name when none is configured.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $anchor
     * @param  array<string, mixed>  $filesystems
     * @return void
     */
    #[DataProvider('provideMalformedDisks')]
    public function testRefusesAMalformedDisk(array $anchor, array $filesystems): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::DISK);

        self::settings($anchor, $filesystems)->disk();
    }

    /**
     * With nothing set the path is `audit-log-anchors`, a configured one is
     * kept as given, its longest form included, and each read goes back to the
     * configuration.
     *
     * @return void
     */
    public function testThePathHasItsDefault(): void
    {
        self::assertSame('audit-log-anchors', self::settings([])->path());
        self::assertSame('audit-log-anchors', (new AnchorSettings(new Repository))->path());

        foreach (['a', 'compliance/audit-log/eu-1', 'a.b/c_d/e-f', '...', '.hidden/x..y', str_repeat('a', 191)] as $path) {
            self::assertSame($path, self::settings(['path' => $path])->path());
        }

        $config   = new Repository;
        $settings = new AnchorSettings($config);

        $config->set('audit-log.integrity.anchor.path', 'anchors/eu');

        self::assertSame('anchors/eu', $settings->path());
    }

    /**
     * Rows of `[value]`: paths that could leave their namespace, or are no path
     * at all.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function providePathsThatCouldLeaveTheirNamespace(): iterable
    {
        yield from [
            'a leading parent'      => ['../x'],
            'an inner parent'       => ['a/../b'],
            'a trailing parent'     => ['a/..'],
            'only a parent'         => ['..'],
            'an absolute path'      => ['/a'],
            'a trailing slash'      => ['a/'],
            'a doubled slash'       => ['a//b'],
            'the current directory' => ['.'],
            'an inner current'      => ['a/./b'],
            '192 characters'        => [str_repeat('a', 192)],
            'a space'               => ['a b'],
            'a backslash'           => ['a\b'],
            'a trailing newline'    => ["a\n"],
            'a non-ASCII letter'    => ['é'],
            'empty'                 => [''],
            'null set explicitly'   => [null],
            'an integer'            => [1],
            'a list'                => [['a']],
        ];
    }

    /**
     * Each path that could leave its namespace, or is no path, fails closed
     * with its message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('providePathsThatCouldLeaveTheirNamespace')]
    public function testRefusesAPathThatCouldLeaveItsNamespace(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::PATH);

        self::settings(['path' => $value])->path();
    }

    /**
     * The path rule is one rule, which a disk anchor holds a path to as these
     * settings do: every string path the settings refuse, the rule refuses, and
     * the longest and the default paths it accepts.
     *
     * @return void
     */
    public function testThePathRuleIsTheOneADiskAnchorHolds(): void
    {
        foreach (self::providePathsThatCouldLeaveTheirNamespace() as $label => [$value]) {
            if (!is_string($value)) {
                continue;
            }

            self::assertFalse(AnchorSettings::isContainedPath($value), $label);
        }

        self::assertTrue(AnchorSettings::isContainedPath(str_repeat('a', 191)));
        self::assertTrue(AnchorSettings::isContainedPath('audit-log-anchors/eu.1_a'));
    }

    /**
     * The batch is 100 with nothing set, takes its least and greatest value as
     * an integer and as the digit string an environment line gives, and fails
     * closed one past either.
     *
     * @return void
     */
    public function testTheBatchHasItsDefaultAndRange(): void
    {
        self::assertSame(100, self::settings([])->batch());
        self::assertSame(100, (new AnchorSettings(new Repository))->batch());
        self::assertSame(1, self::settings(['batch' => 1])->batch());
        self::assertSame(10000, self::settings(['batch' => '10000'])->batch());

        foreach ([0, 10001, '10001', null, '', ' 5', 5.0] as $value) {
            try {
                self::settings(['batch' => $value])->batch();
                self::fail(sprintf('Expected a batch of %s to be refused.', var_export($value, true)));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::BATCH, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[anchor configuration, message]`: one malformed setting at a
     * time, each of those `validate()` reads.
     *
     * @return iterable<string, array{0: array<string, int|string>, 1: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'driver' => [['driver' => 's3'], self::DRIVER],
            'disk'   => [['disk' => 42], self::DISK],
            'path'   => [['path' => '../x'], self::PATH],
            'batch'  => [['batch' => 0], self::BATCH],
        ];
    }

    /**
     * `validate()` reads every setting: each malformed one fails it, alone,
     * with its own message.
     *
     * @param  array<string, int|string>  $anchor
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testValidateReadsEverySetting(array $anchor, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($anchor)->validate();
    }

    /**
     * With every setting malformed, `validate()` fails on the first in its
     * order, then the next once that one is put right, and passes once none is
     * left.
     *
     * @return void
     */
    public function testTheFirstMalformedSettingWins(): void
    {
        $anchor = [];

        foreach (self::provideMalformedSettings() as [$malformed]) {
            $anchor += $malformed;
        }

        foreach (self::provideMalformedSettings() as [$malformed, $message]) {
            try {
                self::settings($anchor)->validate();
                self::fail(sprintf('Expected the settings to be refused with: %s', $message));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }

            $anchor = array_diff_key($anchor, $malformed);
        }

        self::settings($anchor)->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * No refusal names the value it refused, so a misplaced secret in a setting
     * never reaches a log.
     *
     * @return void
     */
    public function testAMessageNamesTheKeyAndNeverTheValue(): void
    {
        $value = 'secret-looking-value';

        foreach (['driver', 'disk', 'path', 'batch'] as $setting) {
            $anchor = [$setting => $setting === 'disk' ? str_repeat($value, 4) : $value . ' /'];

            try {
                self::settings($anchor)->validate();
                self::fail(sprintf('Expected the %s to be refused.', $setting));
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('`audit-log.integrity.anchor.' . $setting . '`', $exception->getMessage());
                self::assertStringNotContainsString($value, $exception->getMessage());
            }
        }
    }

    /**
     * Settings over a plain repository holding the anchor settings and the
     * filesystems configuration, whose default disk is `local` unless given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $anchor
     * @param  ?array<string, mixed>  $filesystems
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings
     */
    private static function settings(array $anchor, ?array $filesystems = null): AnchorSettings
    {
        return new AnchorSettings(new Repository([
            'audit-log'   => ['integrity' => ['anchor' => $anchor]],
            'filesystems' => $filesystems ?? ['default' => 'local'],
        ]));
    }
}
