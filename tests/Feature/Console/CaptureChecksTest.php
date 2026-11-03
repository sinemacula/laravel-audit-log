<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\CaptureChecks;
use Tests\TestCase;

/**
 * Feature tests for the capture checks of `audit-log:check`: a reader for each
 * capture setting and for the artifacts table's name, in order, each refusing
 * its own malformed setting, and the problem of each excepted guard
 * `auth.guards` does not configure, none for the wildcard or a malformed list.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureChecks::class)]
final class CaptureChecksTest extends TestCase
{
    /** @var array<string, int|string> A value each reader refuses, by the setting it reads, in the order the readers are listed. */
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
     * `CaptureChecks` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
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
     * There is one reader for each capture setting and the artifacts table's
     * name, in order: with every setting well formed each reads, and with every
     * one malformed the reader at each place refuses the setting at that place,
     * naming it, so a reader dropped, repeated or moved fails here.
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
     * The readers read the configuration they are given on every call, so a
     * setting changed after they are built is the one they read.
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
     * Each excepted guard `auth.guards` does not configure is a problem, named
     * because a guard's name is no secret, in the list's order, and a guard it
     * configures is none.
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
     * Rows of `[the settings changed, the guard named]`: a guard looked up the
     * way `AuthManager` looks it up, so one configured as a string, one under a
     * dotted name it cannot see, and one with no guards configured at all are
     * each not configured.
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
     * A guard `AuthManager` could not resolve is a problem: protects against a
     * mutation that reads the guard's key as a literal or accepts anything set.
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
     * The wildcard excludes every guard and names none, so it is no problem
     * even when no guard is configured; nor is the default, an empty list.
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
     * Rows of `[except guards]`: lists the reader refuses, among them one
     * holding a name `auth.guards` does not configure beside a bad member.
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
     * A malformed list names no guard to look up: it is the problem its reader
     * reports, so the guard check finds none rather than reporting it twice or
     * naming a guard of a list that is not used.
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
