<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;

/**
 * Unit tests for the definition settings: the default a missing key takes, the
 * real booleans they read, and everything else they fail closed on, without
 * naming the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefinitionSettings::class)]
final class DefinitionSettingsTest extends TestCase
{
    /** @var string The refusal of anything but a boolean. */
    private const string NOT_A_BOOLEAN = '`audit-log.definitions.require_registered` must be true or false.';

    /**
     * With no setting, or none of the package's configuration at all, an
     * unregistered code takes the permissive default.
     *
     * @return void
     */
    public function testDefaultsToFalse(): void
    {
        self::assertFalse((new DefinitionSettings(new Repository))->requiresRegistered());
        self::assertFalse(self::settings([])->requiresRegistered());
    }

    /**
     * `true` requires registration.
     *
     * @return void
     */
    public function testReadsTrue(): void
    {
        self::assertTrue(self::settings(['require_registered' => true])->requiresRegistered());
    }

    /**
     * A `false` that is set reads as `false`, not as a missing key's default.
     *
     * @return void
     */
    public function testReadsFalse(): void
    {
        self::assertFalse(self::settings(['require_registered' => false])->requiresRegistered());
    }

    /**
     * Each read goes back to the configuration, so a change is seen by the next
     * read and the settings hold nothing between calls.
     *
     * @return void
     */
    public function testReadsTheSettingOnEveryCall(): void
    {
        $config   = new Repository;
        $settings = new DefinitionSettings($config);

        self::assertFalse($settings->requiresRegistered());

        $config->set('audit-log.definitions.require_registered', true);

        self::assertTrue($settings->requiresRegistered());
    }

    /**
     * Rows of `[value]`: truthy and falsy values of every other type, and a
     * `null` set explicitly, which is not a missing key.
     *
     * @return iterable<string, array{0: array<never, never>|int|string|null}>
     */
    public static function provideNonBooleans(): iterable
    {
        yield from [
            'the string 1'     => ['1'],
            'the string 0'     => ['0'],
            'the integer 1'    => [1],
            'the integer 0'    => [0],
            'yes'              => ['yes'],
            'the string true'  => ['true'],
            'the string false' => ['false'],
            'an empty string'  => [''],
            'an empty array'   => [[]],
            'an explicit null' => [null],
        ];
    }

    /**
     * Only a real boolean passes: nothing else is coerced, so a truthy string
     * neither turns the rule on nor, read as `false`, leaves it silently off.
     *
     * @param  array<never, never>|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideNonBooleans')]
    public function testRefusesAnythingButABoolean(array|int|string|null $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::NOT_A_BOOLEAN);

        self::settings(['require_registered' => $value])->requiresRegistered();
    }

    /**
     * `validate()` reads the setting: it passes on a well-formed one and fails
     * on a malformed one.
     *
     * @return void
     */
    public function testValidateReadsTheSetting(): void
    {
        self::settings(['require_registered' => true])->validate();
        self::settings([])->validate();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::NOT_A_BOOLEAN);

        self::settings(['require_registered' => 'yes'])->validate();
    }

    /**
     * The refusal says what the setting must be and never what it was.
     *
     * @return void
     */
    public function testNoMessageHoldsTheValue(): void
    {
        try {
            self::settings(['require_registered' => 'leaked-value'])->requiresRegistered();
            self::fail('Expected the value to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('leaked-value', $exception->getMessage());
        }
    }

    /**
     * The settings over the given `audit-log.definitions` configuration.
     *
     * @param  array<string, array<never, never>|bool|int|string|null>  $definitions
     * @return \SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings
     */
    private static function settings(array $definitions): DefinitionSettings
    {
        return new DefinitionSettings(new Repository(['audit-log' => ['definitions' => $definitions]]));
    }
}
