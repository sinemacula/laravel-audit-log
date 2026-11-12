<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the retention policy the package binds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredRetentionPolicy::class)]
final class ConfiguredRetentionPolicyTest extends TestCase
{
    /** @var array<string, array<string, int>|int> A retention section with a default, two categories and a preservation. */
    private const array RETENTION = [
        'after_days' => 30,
        'categories' => ['security' => 2555, 'general' => 365],
        'preserve'   => ['security' => 2555],
    ];

    /** @var string The pinned version of the default settings. */
    private const string DEFAULT_VERSION = 'config:4b814b1a348c39cf';

    /**
     * A category's own days override the default, which applies otherwise.
     *
     * @return void
     */
    public function testACategoryOverridesTheDefault(): void
    {
        $policy = self::policy(self::RETENTION);

        self::assertSame(2555, $policy->retainFor('security', null));
        self::assertSame(365, $policy->retainFor('general', null));
        self::assertSame(30, $policy->retainFor('access', null));
    }

    /**
     * Zero days is forever, as the default or as a category's own.
     *
     * @return void
     */
    public function testZeroIsForever(): void
    {
        self::assertNull(self::policy([])->retainFor('general', null));
        self::assertNull(self::policy(['after_days' => 0, 'categories' => ['security' => 90]])->retainFor('general', null));
        self::assertNull(self::policy(['after_days' => 30, 'categories' => ['security' => 0]])->retainFor('security', null));
        self::assertSame(90, self::policy(['after_days' => 0, 'categories' => ['security' => 90]])->retainFor('security', null));
        self::assertSame(1, self::policy(['after_days' => 1])->retainFor('general', null));
    }

    /**
     * The tenant changes no answer.
     *
     * @return void
     */
    public function testTheTenantIsNotConsulted(): void
    {
        $policy  = self::policy(self::RETENTION);
        $tenants = [null, Reference::of('team', 1), Reference::of('team', 2), Reference::of('organisation', 'acme')];

        foreach ($tenants as $tenant) {
            self::assertSame(2555, $policy->retainFor('security', $tenant));
            self::assertSame(30, $policy->retainFor('access', $tenant));
            self::assertSame(2555, $policy->preserveFor('security', $tenant));
            self::assertNull($policy->preserveFor('access', $tenant));
        }
    }

    /**
     * A preservation of zero days is forever, answered as `PHP_INT_MAX`.
     *
     * @return void
     */
    public function testPreservationZeroIsForever(): void
    {
        $policy = self::policy(['categories' => ['security' => 0], 'preserve' => ['security' => 0, 'general' => 1]]);

        self::assertSame(PHP_INT_MAX, $policy->preserveFor('security', null));
        self::assertSame(1, $policy->preserveFor('general', null));
    }

    /**
     * No preservation answers `null`, and the default never preserves.
     *
     * @return void
     */
    public function testNoPreservationIsNull(): void
    {
        self::assertNull(self::policy([])->preserveFor('security', null));
        self::assertNull(self::policy(self::RETENTION)->preserveFor('general', null));
        self::assertNull(self::policy(['after_days' => 36500])->preserveFor('general', null));
    }

    /**
     * The version is `config:` and 16 hex characters, and changes only with a
     * setting the answers read.
     *
     * @return void
     */
    public function testTheVersionChangesOnlyWithTheSettings(): void
    {
        $version = self::policy(self::RETENTION)->version();

        self::assertMatchesRegularExpression('/\Aconfig:[0-9a-f]{16}\z/', $version);
        self::assertSame($version, self::policy(self::RETENTION)->version());
        self::assertSame($version, self::policy([...self::RETENTION, 'categories' => ['general' => 365, 'security' => 2555]])->version());
        self::assertSame($version, self::policy([...self::RETENTION, 'after_days' => '30', 'categories' => ['general' => '365', 'security' => 2555]])->version());
        self::assertSame($version, self::policy([...self::RETENTION, 'batch' => 100, 'max_seconds' => 60, 'schedule' => null])->version());

        $changed = [
            [...self::RETENTION, 'after_days' => 31],
            [...self::RETENTION, 'categories' => ['security' => 2555, 'general' => 366]],
            [...self::RETENTION, 'categories' => ['security' => 2555, 'general' => 365, 'access' => 30]],
            [...self::RETENTION, 'preserve' => ['security' => 2554]],
            [...self::RETENTION, 'preserve' => []],
        ];

        $versions = array_map(static fn (array $retention): string => self::policy($retention)->version(), $changed);

        self::assertNotContains($version, $versions);
        self::assertCount(count($changed), array_unique($versions));
    }

    /**
     * The version is unkeyed, so rotating the ring never journals a new policy.
     *
     * @return void
     */
    public function testTheVersionDoesNotChangeWithTheRing(): void
    {
        $versions = [];

        foreach ([[], ['keys' => ['k1' => str_repeat('a', 32)], 'current' => 'k1'], ['keys' => ['k2' => str_repeat('b', 32)], 'current' => 'k2']] as $integrity) {
            foreach (['base64:' . base64_encode(str_repeat('x', 32)), 'base64:' . base64_encode(str_repeat('y', 32))] as $applicationKey) {
                $config = new Repository(['app' => ['key' => $applicationKey], 'audit-log' => ['integrity' => $integrity, 'retention' => self::RETENTION]]);

                $versions[] = (new ConfiguredRetentionPolicy(new RetentionSettings($config)))->version();
            }
        }

        self::assertCount(1, array_unique($versions));
        self::assertSame(self::policy(self::RETENTION)->version(), $versions[0]);
    }

    /**
     * The settings are canonical, and the version is pinned for the defaults.
     *
     * @return void
     */
    public function testTheSettingsAreCanonical(): void
    {
        $policy   = self::policy(self::RETENTION);
        $settings = $policy->settings();

        self::assertSame(['after_days' => 30, 'categories' => ['general' => 365, 'security' => 2555], 'preserve' => ['security' => 2555]], $settings);
        self::assertSame(['after_days', 'categories', 'preserve'], array_keys($settings));
        self::assertSame(['general', 'security'], array_keys($settings['categories']));
        self::assertSame('{"after_days":30,"categories":{"general":365,"security":2555},"preserve":{"security":2555}}', CanonicalEncoder::encode($settings));
        self::assertSame('config:' . substr(hash('sha256', CanonicalEncoder::encode($settings)), 0, 16), $policy->version());

        self::assertSame(['after_days' => 0, 'categories' => [], 'preserve' => []], self::policy([])->settings());
        self::assertSame('config:' . substr(hash('sha256', '{"after_days":0,"categories":[],"preserve":[]}'), 0, 16), self::policy([])->version());
        self::assertSame(self::DEFAULT_VERSION, self::policy([])->version());
    }

    /**
     * A malformed or conflicting setting refuses every answer.
     *
     * @return void
     */
    public function testAMalformedSettingRefusesEveryAnswer(): void
    {
        $malformed = [
            ['after_days' => -1],
            ['categories' => [30]],
            ['preserve' => ['Security' => 1]],
            ['batch' => 0],
            ['schedule' => 'nightly'],
            ['categories' => ['security' => 30], 'preserve' => ['security' => 31]],
        ];

        $answers = [
            'version'     => static fn (ConfiguredRetentionPolicy $policy): string => $policy->version(),
            'retainFor'   => static fn (ConfiguredRetentionPolicy $policy): ?int => $policy->retainFor('general', null),
            'preserveFor' => static fn (ConfiguredRetentionPolicy $policy): ?int => $policy->preserveFor('general', null),
            'settings'    => static fn (ConfiguredRetentionPolicy $policy): array => $policy->settings(),
        ];

        foreach ($malformed as $index => $retention) {
            foreach ($answers as $answer => $ask) {
                try {
                    $ask(self::policy($retention));

                    self::fail("Expected {$answer}() to be refused for row {$index}.");
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringStartsWith('`audit-log.retention.', $exception->getMessage(), "{$answer}() for row {$index}");
                }
            }
        }
    }

    /**
     * The configured policy over the retention section given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $retention
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy
     */
    private static function policy(array $retention): ConfiguredRetentionPolicy
    {
        return new ConfiguredRetentionPolicy(new RetentionSettings(new Repository(['audit-log' => ['retention' => $retention]])));
    }
}
