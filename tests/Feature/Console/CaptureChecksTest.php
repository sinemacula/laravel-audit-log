<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\CaptureChecks;
use Tests\TestCase;

/**
 * Feature tests for the capture checks of `audit-log:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureChecks::class)]
final class CaptureChecksTest extends TestCase
{
    /** @var array<string, int|string> A value each reader refuses, by setting, in reader order. */
    private const array BAD_SETTINGS = [
        'audit-log.capture.laravel.except_guards'  => 'web',
        'audit-log.capture.laravel.identifier_key' => 'e mail',
        'audit-log.capture.gate.enabled'           => 'true',
        'audit-log.capture.gate.only_abilities'    => 'update',
        'audit-log.capture.gate.except_abilities'  => 'update',
        'audit-log.capture.gate.reason_codes'      => 'plan_expired',
        'audit-log.capture.bulk.max_members'       => 0,
        'audit-log.capture.bulk.max_bytes'         => 65535,
        'audit-log.entries.artifacts_table'        => 'audit-artifacts',
    ];

    /** @var string The problem of an excepted guard, by its name. */
    private const string UNCONFIGURED = 'The guard [%s] that `audit-log.capture.laravel.except_guards` names is not configured in `auth.guards`.';

    /**
     * The constructor is private; invoking it by reflection covers the line.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(CaptureChecks::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(CaptureChecks::class, $instance);
    }

    /**
     * One reader per capture setting, in order, each refusing its own setting.
     *
     * @return void
     */
    public function testEveryCaptureReaderIsListed(): void
    {
        $config = app(ConfigRepository::class);

        $readers = CaptureChecks::readers($config);

        self::assertCount(count(self::BAD_SETTINGS), $readers);

        foreach ($readers as $reader) {
            $reader();
        }

        $config->set(self::BAD_SETTINGS);

        $named = [];

        foreach (CaptureChecks::readers($config) as $reader) {
            try {
                $reader();
                self::fail('Expected every reader to refuse its malformed setting.');
            } catch (\InvalidArgumentException $exception) {
                $named[] = self::keyNamedBy($exception->getMessage());
            }
        }

        self::assertSame(array_keys(self::BAD_SETTINGS), $named);
    }

    /**
     * The readers read the configuration afresh on every call.
     *
     * @return void
     */
    public function testTheReadersReadTheSettingsOnEveryCall(): void
    {
        $config  = app(ConfigRepository::class);
        $readers = CaptureChecks::readers($config);

        $config->set('audit-log.capture.gate.enabled', true);

        self::assertTrue($readers[2]());

        $config->set('audit-log.entries.artifacts_table', 'reporting_artifacts');

        self::assertSame('reporting_artifacts', $readers[8]());
    }

    /**
     * Each excepted guard `auth.guards` does not configure is named, in order.
     *
     * @return void
     */
    public function testAnExceptGuardAuthDoesNotConfigureIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']);
        $config->set('audit-log.capture.laravel.except_guards', ['second', 'web', 'api', 'first']);

        self::assertSame([sprintf(self::UNCONFIGURED, 'second'), sprintf(self::UNCONFIGURED, 'first')], CaptureChecks::guardProblems($config));

        $config->set('audit-log.capture.laravel.except_guards', ['web', 'api']);

        self::assertSame([], CaptureChecks::guardProblems($config));
    }

    /**
     * Rows of `[the settings changed, the guard named]`: unresolvable guards.
     *
     * @return iterable<string, array{0: array<string, array<string, array<string, string>|string>|list<string>|null>, 1: string}>
     */
    public static function provideUnconfiguredGuards(): iterable
    {
        yield from [
            'a guard configured as a string' => [['auth.guards' => ['web' => 'session'], 'audit-log.capture.laravel.except_guards' => ['web']], 'web'],
            'no guards at all'               => [['auth.guards' => null, 'audit-log.capture.laravel.except_guards' => ['web']], 'web'],
            'a dotted name'                  => [['auth.guards' => ['api.v1' => ['driver' => 'session']], 'audit-log.capture.laravel.except_guards' => ['api.v1']], 'api.v1'],
        ];
    }

    /**
     * A guard `AuthManager` cannot resolve is a problem.
     *
     * @param  array<string, array<string, array<string, string>|string>|list<string>|null>  $settings
     * @param  string  $guard
     * @return void
     */
    #[DataProvider('provideUnconfiguredGuards')]
    public function testAGuardAuthCannotResolveIsAProblem(array $settings, string $guard): void
    {
        $config = app(ConfigRepository::class);

        $config->set($settings);

        self::assertSame([sprintf(self::UNCONFIGURED, $guard)], CaptureChecks::guardProblems($config));
    }

    /**
     * The wildcard and an empty list name no guard, so neither is a problem.
     *
     * @return void
     */
    public function testTheWildcardNamesNoGuard(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('auth.guards', null);
        $config->set('audit-log.capture.laravel.except_guards', ['*']);

        self::assertSame([], CaptureChecks::guardProblems($config));

        $config->set('audit-log.capture.laravel.except_guards', []);

        self::assertSame([], CaptureChecks::guardProblems($config));
    }

    /**
     * Rows of `[except guards]`: lists the reader refuses.
     *
     * @return iterable<string, array{0: list<int|string>|string|null}>
     */
    public static function provideMalformedLists(): iterable
    {
        yield from [
            'a string'                          => ['missing'],
            'an explicit null'                  => [null],
            'an unconfigured name and an int'   => [['missing', 42]],
            'the wildcard beside a missing one' => [['*', 'missing']],
        ];
    }

    /**
     * A malformed list is left to its reader; the guard check reports nothing.
     *
     * @param  list<int|string>|string|null  $guards
     * @return void
     */
    #[DataProvider('provideMalformedLists')]
    public function testAMalformedListIsLeftToItsReader(array|string|null $guards): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.capture.laravel.except_guards', $guards);

        self::assertSame([], CaptureChecks::guardProblems($config));
    }

    /**
     * The setting a refusal names, from the backticked key it opens with.
     *
     * @param  string  $message
     * @return string
     */
    private static function keyNamedBy(string $message): string
    {
        self::assertSame(1, preg_match('/\A`([a-z0-9_.-]+)` /', $message, $matches), "The refusal [{$message}] does not open with the key it names.");

        return $matches[1];
    }
}
