<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds what the package ships to its contract, where the contract is not about
 * which class names which: no frontend (no route, view, component or asset
 * directory, and no provider that loads one), no other package of the suite
 * required, named or configured, the quality tools' dependencies in step with
 * the package's, every type tagged as public surface or internal with the
 * standard author and copyright lines, no branch on the console outside the
 * provider, no static property to outlive a request, and no call that makes a
 * guard load a user.
 *
 * Each scanner reads tokens or text rather than parsing, so each has a
 * self-test that feeds it a fixed source and pins exactly what it finds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PackageBoundaryTest extends TestCase
{
    /** @var string The repository's root. */
    private const string ROOT = __DIR__ . '/../../..';

    /** @var list<string> The directories whose files ship, where they exist. */
    private const array SHIPPED = ['src', 'config', 'database', 'lang'];

    /** @var list<string> The service provider methods that load routes, views or components. */
    private const array LOADERS = ['loadRoutesFrom', 'loadViewsFrom', 'loadViewComponentsAs', 'loadAnonymousComponentsFrom'];

    /** @var list<string> The `composer.json` sections that name other packages. */
    private const array SECTIONS = ['require', 'require-dev', 'suggest', 'conflict', 'replace', 'provide'];

    /** @var string A `composer.json` package name of another package of the suite. */
    private const string SUITE_PACKAGE = '/^sinemacula\/laravel-(?!audit-log$)/i';

    /** @var string Another package of the suite's name, anywhere in a file. */
    private const string SUITE_PACKAGE_TEXT = '/sinemacula\/laravel-(?!audit-log(?![\w-]))[a-z]/i';

    /** @var string Another package of the suite's namespace, anywhere in a file, single or JSON escaped. */
    private const string SUITE_NAMESPACE_TEXT = '/SineMacula\\\{1,2}Laravel\\\{1,2}(?!AuditLog\b)[A-Za-z_]/i';

    /** @var list<string> The configuration repository methods that read a key. */
    private const array READERS = ['get', 'has', 'string', 'integer', 'boolean', 'float', 'array'];

    /** @var list<string> The framework's own configuration files, which the package may read. */
    private const array LARAVEL_CONFIG = ['app', 'auth', 'cache', 'database', 'filesystems', 'logging', 'queue', 'session'];

    /** @var string The package's own configuration file, which the package may read. */
    private const string PACKAGE_CONFIG = 'audit-log';

    /** @var string A tag line marking a type as public surface or internal. */
    private const string VISIBILITY_TAG = '/^\s*\* @(api|internal)$/m';

    /** @var string The standard author line. */
    private const string AUTHOR = '/^\s*\* @author\s+Ben Carey <bdmc@sinemacula\.co\.uk>$/m';

    /** @var string The standard copyright line. */
    private const string COPYRIGHT = '/^\s*\* @copyright\s+2026 Sine Macula Limited$/m';

    /** @var string The only file allowed to ask whether the application runs in the console. */
    private const string PROVIDER = 'src/AuditLogServiceProvider.php';

    /** @var string The package's root namespace. */
    private const string PACKAGE = 'SineMacula\Laravel\AuditLog\\';

    /** @var list<string> The directory and the file that read a guard's user; any other file touches a guard when it resolves one by name. */
    private const array GUARD_READERS = ['src/Contributors/', 'src/Runtime/CachedUser.php'];

    /** @var list<string> The other `GuardHelpers` methods that call `user()`. */
    private const array USER_LOADERS = ['id', 'check', 'guest', 'authenticate'];

    /**
     * Rows of `[path]`: the directories a frontend would ship in.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFrontendPaths(): iterable
    {
        yield from [
            'routes'           => ['routes'],
            'resources'        => ['resources'],
            'public'           => ['public'],
            'assets'           => ['assets'],
            'dist'             => ['dist'],
            'views'            => ['views'],
            'HTTP controllers' => ['src/Http/Controllers'],
            'view classes'     => ['src/View'],
        ];
    }

    /**
     * No frontend directory ships: the package has no routes, views, assets or
     * controllers.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideFrontendPaths')]
    public function testNoFrontendDirectoryShips(string $path): void
    {
        self::assertDirectoryDoesNotExist(self::ROOT . '/' . $path);
    }

    /**
     * No class loads routes, views or components, nor reaches for the Blade
     * compiler.
     *
     * @return void
     */
    public function testNoClassLoadsRoutesViewsOrComponents(): void
    {
        $loads = [];

        foreach (self::files(['src'], 'php') as $file) {
            foreach (self::loadersIn(self::contents($file)) as $loader) {
                $loads[] = "{$file} calls {$loader}";
            }
        }

        self::assertSame([], $loads);
    }

    /**
     * The loader scanner finds each loader, whatever its case, and the Blade
     * compiler's binding in either kind of quotes; and nothing for a comment,
     * another loader, or a binding that only starts the same way.
     *
     * @return void
     */
    public function testTheLoaderScannerFindsEveryCall(): void
    {
        $source = <<<'PHP'
            <?php

            // $this->loadRoutesFrom('ignored, in a comment');
            final class Example extends ServiceProvider
            {
                public function boot(): void
                {
                    $this->loadRoutesFrom(__DIR__ . '/routes.php');
                    $this->LOADVIEWSFROM(__DIR__ . '/views', 'example');
                    $this->loadViewComponentsAs('example', []);
                    $this->loadAnonymousComponentsFrom(__DIR__ . '/components');
                    $this->app->make("blade.compiler");
                    $this->loadMigrationsFrom(__DIR__ . '/migrations');
                    $this->app->make('blade.compiler.extra');
                }
            }
            PHP;

        self::assertSame(['loadRoutesFrom', 'loadViewsFrom', 'loadViewComponentsAs', 'loadAnonymousComponentsFrom', 'blade.compiler'], self::loadersIn($source));
    }

    /**
     * No section of `composer.json` names another package of the suite: the
     * package never requires, suggests, conflicts with, replaces or provides
     * one.
     *
     * @return void
     */
    public function testComposerRequiresNoOtherSuitePackage(): void
    {
        $named = [];

        foreach (self::SECTIONS as $section) {
            foreach (array_keys(self::packages('composer.json', $section)) as $package) {
                $named[] = preg_match(self::SUITE_PACKAGE, $package) === 1 ? "{$section} names {$package}" : null;
            }
        }

        self::assertSame([], array_values(array_filter($named)));
    }

    /**
     * The quality tools' `composer.json` requires every runtime dependency of
     * the package with the same constraint, so the analysers read the code
     * against what it runs on, and requires no package of the suite either.
     *
     * @return void
     */
    public function testTheQualityToolsRequireTheSameRuntimeDependencies(): void
    {
        $isRuntime = static fn (string $package): bool => $package !== 'php' && !str_starts_with($package, 'ext-');
        $runtime   = array_filter(self::packages('composer.json', 'require'), $isRuntime, ARRAY_FILTER_USE_KEY);
        $quality   = self::packages('.qlty/configs/composer.json', 'require');

        self::assertNotSame([], $runtime);

        foreach ($runtime as $package => $constraint) {
            self::assertSame($constraint, $quality[$package] ?? null, "The quality tools do not require {$package} as the package does.");
        }

        self::assertSame([], array_values(array_filter(array_keys($quality), static fn (string $package): bool => preg_match('/^sinemacula\/laravel-/i', $package) === 1)));
    }

    /**
     * The patterns tell this package from another of the suite, whatever the
     * case, in a package name or a namespace (single or JSON escaped); a name
     * that only starts with this package's is another package's.
     *
     * @return void
     */
    public function testThePatternsTellThisPackageFromAnother(): void
    {
        $packages = [
            'sinemacula/laravel-audit-log',
            'sinemacula/laravel-other',
            'sinemacula/laravel-audit-log-ui',
            'sinemacula/coding-standards-laravel',
            'laravel/framework',
            'SineMacula/Laravel-Other',
        ];

        $namespaces = [
            'SineMacula\Laravel\AuditLog\Records',
            'SineMacula\\\Laravel\\\AuditLog\\\\',
            'SineMacula\Laravel\Other',
            'SineMacula\\\Laravel\\\Other\\\\',
            'SineMacula\Laravel\AuditLogUi',
            'sinemacula\laravel\other',
            'SineMacula\Coding\Thing',
            'Illuminate\Support',
        ];

        $matching = static fn (string $pattern, array $texts): array => array_values(array_filter($texts, static fn (string $text): bool => preg_match($pattern, $text) === 1));
        $quoted   = static fn (string $package): string => "\"{$package}\": \"^1.0\"";
        $foreign  = ['sinemacula/laravel-other', 'sinemacula/laravel-audit-log-ui', 'SineMacula/Laravel-Other'];

        self::assertSame($foreign, $matching(self::SUITE_PACKAGE, $packages));
        self::assertSame(array_map($quoted, $foreign), $matching(self::SUITE_PACKAGE_TEXT, array_map($quoted, $packages)));
        self::assertSame([$namespaces[2], $namespaces[3], $namespaces[4], $namespaces[5]], $matching(self::SUITE_NAMESPACE_TEXT, $namespaces));
    }

    /**
     * Rows of `[file]`: every file that ships, relative to the root.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideShippedFiles(): iterable
    {
        foreach ([...self::files(self::SHIPPED), 'composer.json'] as $file) {
            yield $file => [$file];
        }
    }

    /**
     * No shipped file names another package of the suite, by its package name
     * or its namespace, in code or in a string.
     *
     * @param  string  $file
     * @return void
     */
    #[DataProvider('provideShippedFiles')]
    public function testNoShippedFileNamesAnotherSuitePackage(string $file): void
    {
        $contents = self::contents($file);

        self::assertDoesNotMatchRegularExpression(self::SUITE_NAMESPACE_TEXT, $contents, "{$file} names another package of the suite's namespace.");
        self::assertDoesNotMatchRegularExpression(self::SUITE_PACKAGE_TEXT, $contents, "{$file} names another package of the suite.");
    }

    /**
     * No shipped class or configuration file reads a key of another package's
     * configuration: every key read is the package's own or one of the
     * framework's files.
     *
     * @return void
     */
    public function testNoShippedFileReadsAnotherPackagesConfiguration(): void
    {
        $reads = [];

        foreach (self::files(['src', 'config'], 'php') as $file) {
            foreach (self::foreignReads(self::configurationReadsIn(self::contents($file))) as $key) {
                $reads[] = "{$file} reads {$key}";
            }
        }

        self::assertSame([], $reads);
    }

    /**
     * The configuration scanner finds the key of each way of reading one: the
     * helper (unqualified, fully qualified or in another case), the facade, an
     * injected or resolved repository, the container's binding and the helper's
     * repository, through each reader method; and nothing for a comment, a
     * docblock, a write, a method of the same name, a non-literal key, or a
     * reader method on something that is not configuration.
     *
     * @return void
     */
    public function testTheConfigurationScannerFindsEveryRead(): void
    {
        $source = <<<'PHP'
            <?php

            // config('ignored.in_a_comment');

            /** config('ignored.in_a_docblock') */
            final class Example
            {
                public function config(): void {}

                public function run(): void
                {
                    config('audit-log.storage.connection');
                    \config("app.name", 'default');
                    CONFIG('other.key');
                    config(['ignored.a_write' => true]);
                    config($key);
                    Config::get('database.default');
                    Config::HAS('queue.default');
                    Config::array('app.providers');
                    $this->config->string('session.driver');
                    $this->app['config']->integer('cache.ttl');
                    $config?->boolean('logging.enabled');
                    config()->float('filesystems.size');
                    report(app(ConfigRepository::class)->array('auth.guards'));
                    $request->get('ignored.not_configuration');
                    $this->config('ignored.a_method');
                    Str::of('ignored.not_a_read');
                }
            }
            PHP;

        $keys = self::configurationReadsIn($source);

        self::assertSame([
            'audit-log.storage.connection',
            'app.name',
            'other.key',
            'database.default',
            'queue.default',
            'app.providers',
            'session.driver',
            'cache.ttl',
            'logging.enabled',
            'filesystems.size',
            'auth.guards',
        ], $keys);

        self::assertSame(['other.key'], self::foreignReads($keys));
    }

    /**
     * Rows of `[file]`: every source file, relative to the root.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSourceFiles(): iterable
    {
        foreach (self::files(['src'], 'php') as $file) {
            yield $file => [$file];
        }
    }

    /**
     * Every type a source file declares carries, in the docblock directly above
     * it, exactly one of `@api` and `@internal` as a tag line, and the standard
     * author and copyright lines.
     *
     * @param  string  $file
     * @return void
     */
    #[DataProvider('provideSourceFiles')]
    public function testEveryTypeIsMarkedApiOrInternal(string $file): void
    {
        $declarations = self::declarationsIn(self::contents($file));

        self::assertNotSame([], $declarations, "{$file} declares no type.");
        self::assertSame([], self::problems($file, $declarations));
    }

    /**
     * The declaration scanner reads the docblock directly above each class,
     * interface, trait and enum, past its modifiers and attributes, and not a
     * member's docblock, an anonymous class or a `::class` constant; the tag
     * check refuses a type without a docblock, with both tags or with a tag
     * only in prose, and without the author and copyright lines.
     *
     * @return void
     */
    public function testTheDeclarationScannerReadsTheDocblockAboveEachType(): void
    {
        $source = <<<'PHP'
            <?php

            namespace Example;

            /**
             * Tagged.
             *
             * @author      Ben Carey <bdmc@sinemacula.co.uk>
             * @copyright   2026 Sine Macula Limited
             *
             * @internal
             */
            #[\Attribute(\Attribute::TARGET_CLASS)]
            #[Marks(['a' => [1]])]
            final readonly class Tagged
            {
                /**
                 * A method, whose docblock is not the class's.
                 *
                 * @api
                 */
                public function run(): string
                {
                    $anonymous = new class {};

                    return Tagged::class;
                }
            }

            interface Untagged {}

            /**
             * Both, and the class is @api in prose.
             *
             * @api
             *
             * @internal
             */
            enum Both: string {}

            /** One line. @api */
            abstract class Abstracted {}

            trait Concern {}
            PHP;

        $declarations = self::declarationsIn($source);

        self::assertSame(['Tagged', 'Untagged', 'Both', 'Abstracted', 'Concern'], array_column($declarations, 0));

        self::assertSame([
            'Example.php: Untagged has no docblock.',
            'Example.php: Both is not tagged exactly one of @api and @internal.',
            'Example.php: Both has no standard @author line.',
            'Example.php: Both has no standard @copyright line.',
            'Example.php: Abstracted is not tagged exactly one of @api and @internal.',
            'Example.php: Abstracted has no standard @author line.',
            'Example.php: Abstracted has no standard @copyright line.',
            'Example.php: Concern has no docblock.',
        ], self::problems('Example.php', $declarations));
    }

    /**
     * Recording never branches on the console: only the provider asks, to
     * publish its files and register its command, and the origin comes from the
     * execution frames.
     *
     * @return void
     */
    public function testNoClassOutsideTheProviderAsksWhetherItRunsInTheConsole(): void
    {
        $asks = [];

        foreach (self::files(['src'], 'php') as $file) {
            foreach ($file === self::PROVIDER ? [] : self::memberCallsIn(self::contents($file), ['runningInConsole']) as $call) {
                $asks[] = "{$file} calls {$call}";
            }
        }

        self::assertSame([], $asks);
    }

    /**
     * The scanner finds the call on an object, through a nullsafe operator and
     * on a class, in any case; and nothing for a comment, a string or a
     * declaration of the same name.
     *
     * @return void
     */
    public function testTheConsoleScannerFindsEveryCall(): void
    {
        $source = <<<'PHP'
            <?php

            // $this->app->runningInConsole();
            final class Example
            {
                public function runningInConsole(): string
                {
                    $this->app->runningInConsole();
                    $this->app?->RUNNINGINCONSOLE();
                    App::runningInConsole();

                    return '$this->app->runningInConsole()';
                }
            }
            PHP;

        self::assertSame(['runningInConsole', 'runningInConsole', 'runningInConsole'], self::memberCallsIn($source, ['runningInConsole']));
    }

    /**
     * No class of the package declares a static property, so nothing survives
     * from one Octane request to the next outside the container. Each property
     * is judged by its declaring class, so a parent's statics, such as those of
     * Laravel's `Facade`, are not counted.
     *
     * @return void
     */
    public function testNoClassDeclaresAStaticProperty(): void
    {
        $declared = [];

        foreach (self::files(['src'], 'php') as $file) {

            $class = self::PACKAGE . str_replace('/', '\\', substr($file, strlen('src/'), -strlen('.php')));

            self::assertTrue(class_exists($class) || interface_exists($class) || trait_exists($class) || enum_exists($class), "{$file} does not declare {$class}.");

            $declared = [...$declared, ...self::staticPropertiesOf($class)];
        }

        self::assertSame([], $declared);
        self::assertContains('Illuminate\Support\Facades\Facade::$app', self::staticPropertiesOf('Illuminate\Support\Facades\Facade'));
    }

    /**
     * No class calls `user()` on anything, since it loads a user and dispatches
     * `Authenticated`. And where a guard is touched, none calls the helpers
     * that call it on a `GuardHelpers` guard.
     *
     * @return void
     */
    public function testNoClassCallsAGuardsUser(): void
    {
        $calls = [];

        foreach (self::files(['src'], 'php') as $file) {

            $names = self::touchesAGuard($file) ? ['user', ...self::USER_LOADERS] : ['user'];

            foreach (self::memberCallsIn(self::contents($file), $names) as $call) {
                $calls[] = "{$file} calls {$call}";
            }
        }

        self::assertSame([], $calls);
    }

    /**
     * The scanner finds each form of the call: on a property, through a
     * nullsafe operator, on a class, in any case, and as a first-class
     * callable; and nothing for a comment, a string, a declaration, a read of a
     * property of the same name, or a method with a longer name.
     *
     * @return void
     */
    public function testTheGuardCallScannerFindsEveryForm(): void
    {
        $source = <<<'PHP'
            <?php

            // $guard->user();
            /** $guard->check() */
            final class Example
            {
                public function user(): string
                {
                    $guard->user();
                    $this->guard?->USER();
                    Auth::user();
                    $guard->user(...);
                    $guard->id();
                    $guard->check();
                    $guard->guest();
                    $guard->authenticate();
                    $auth->guard('web')->check();
                    $read = $bound->user;
                    $guard->username();
                    $guard->hasUser();

                    return '$guard->user()';
                }
            }
            PHP;

        self::assertSame(['user', 'user', 'user', 'user', 'id', 'check', 'guest', 'authenticate', 'check'], self::memberCallsIn($source, ['user', ...self::USER_LOADERS]));
    }

    /**
     * Rows of `[source, whether it resolves a guard]`: each form of resolving a
     * guard by name, on the manager, through a nullsafe operator, on the
     * facade, in any case and as a first-class callable; and nothing for a
     * comment, a string, a declaration, a read of a property of the same name,
     * or a method with a longer name.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideGuardResolutions(): iterable
    {
        yield from [
            'on the manager'              => ['<?php $auth->guard($name);', true],
            'with no name'                => ['<?php $this->auth->guard();', true],
            'through a nullsafe'          => ['<?php $auth?->guard(\'web\');', true],
            'on the facade'               => ['<?php Auth::guard(\'web\');', true],
            'in another case'             => ['<?php $auth->GUARD(\'web\');', true],
            'as a first-class callable'   => ['<?php $resolve = $auth->guard(...);', true],
            'in a comment'                => ["<?php\n// \$auth->guard('web');\n/** \$auth->guard('web') */", false],
            'in a string'                 => ['<?php $call = \'$auth->guard()\';', false],
            'as a declaration'            => ['<?php final class A { public function guard(): void {} }', false],
            'a property of the name'      => ['<?php $name = $event->guard;', false],
            'a method with a longer name' => ['<?php $pending->fillGuard($guard);', false],
        ];
    }

    /**
     * A file that resolves a guard by name touches one, so a call there of a
     * helper that loads the guard's user is refused too, wherever the file is.
     *
     * @param  string  $source
     * @param  bool  $resolves
     * @return void
     */
    #[DataProvider('provideGuardResolutions')]
    public function testTheGuardScannerFindsEveryResolutionOfAGuard(string $source, bool $resolves): void
    {
        self::assertSame($resolves, self::resolvesAGuard($source));
    }

    /**
     * The core sign-in listener resolves the guard an event names, so it is
     * held to the helpers' rule; a listener that never resolves a guard is held
     * only to the rule on `user()`.
     *
     * @return void
     */
    public function testTheAuthListenerTouchesAGuard(): void
    {
        self::assertTrue(self::touchesAGuard('src/Listeners/RecordLaravelAuthEvent.php'));
        self::assertTrue(self::touchesAGuard('src/Contributors/AmbientActor.php'));
        self::assertTrue(self::touchesAGuard('src/Runtime/CachedUser.php'));
        self::assertFalse(self::touchesAGuard('src/Listeners/RecordGateDenial.php'));
    }

    /**
     * The files under the directories that exist, relative to the root and
     * sorted, keeping only those with the extension when one is given.
     *
     * @param  list<string>  $directories
     * @param  ?string  $extension
     * @return list<string>
     */
    private static function files(array $directories, ?string $extension = null): array
    {
        $files = [];

        foreach (array_filter($directories, static fn (string $directory): bool => is_dir(self::ROOT . '/' . $directory)) as $directory) {

            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::ROOT . '/' . $directory, \FilesystemIterator::SKIP_DOTS));

            foreach ($iterator as $file) {

                assert($file instanceof \SplFileInfo);

                if ($extension !== null && $file->getExtension() !== $extension) {
                    continue;
                }

                $files[] = substr($file->getPathname(), strlen(self::ROOT) + 1);
            }
        }

        sort($files);

        return $files;
    }

    /**
     * The contents of the file, relative to the root.
     *
     * @param  string  $file
     * @return string
     */
    private static function contents(string $file): string
    {
        return (string) file_get_contents(self::ROOT . '/' . $file);
    }

    /**
     * The packages a section of a `composer.json` names, with their
     * constraints; an empty list when the section is absent.
     *
     * @param  string  $file
     * @param  string  $section
     * @return array<string, string>
     *
     * @throws \JsonException
     */
    private static function packages(string $file, string $section): array
    {
        $composer = json_decode(self::contents($file), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($composer, "{$file} is not a JSON object.");

        $packages = $composer[$section] ?? [];

        self::assertIsArray($packages, "{$file}'s {$section} is not a JSON object.");

        $constraints = [];

        foreach ($packages as $package => $constraint) {
            $constraints[(string) $package] = is_string($constraint) ? $constraint : '';
        }

        return $constraints;
    }

    /**
     * The loaders the source calls, each as the provider declares it, and the
     * Blade compiler's binding wherever a string names it, in order.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function loadersIn(string $source): array
    {
        $loaders = array_combine(array_map(strtolower(...), self::LOADERS), self::LOADERS);
        $found   = [];

        foreach (self::tokens($source) as $token) {

            if (!is_array($token)) {
                continue;
            }

            $found[] = match ($token[0]) {
                T_STRING                   => $loaders[strtolower($token[1])] ?? null,
                T_CONSTANT_ENCAPSED_STRING => substr($token[1], 1, -1) === 'blade.compiler' ? 'blade.compiler' : null,
                default                    => null,
            };
        }

        return array_values(array_filter($found, static fn (?string $loader): bool => $loader !== null));
    }

    /**
     * The configuration keys the source reads through a string literal as the
     * first argument, in order.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function configurationReadsIn(string $source): array
    {
        $tokens = self::tokens($source);
        $keys   = [];

        foreach (array_keys($tokens) as $index) {

            $key = $tokens[$index + 2] ?? null;

            if (!is_array($key) || $key[0] !== T_CONSTANT_ENCAPSED_STRING || !self::isConfigurationRead($tokens, $index)) {
                continue;
            }

            $keys[] = substr($key[1], 1, -1);
        }

        return $keys;
    }

    /**
     * Whether the token at the index calls something that reads configuration:
     * the `config()` helper, or a reader method on a receiver that names
     * configuration.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return bool
     */
    private static function isConfigurationRead(array $tokens, int $index): bool
    {
        $token  = $tokens[$index];
        $before = $tokens[$index - 1] ?? null;

        if (!is_array($token) || ($tokens[$index + 1] ?? null) !== '(') {
            return false;
        }

        $name = strtolower(ltrim($token[1], '\\'));

        if ($name === 'config' && in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)) {
            return !is_array($before) || !in_array($before[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true);
        }

        return in_array($name, self::READERS, true)
            && is_array($before)
            && in_array($before[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)
            && self::isConfigurationReceiver($tokens, $index - 1);
    }

    /**
     * Whether the receiver before the member operator at the index names
     * configuration: walking back over its chain of names, variables, member
     * operators and bracketed arguments, one of its tokens mentions `config` in
     * any case.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $operator
     * @return bool
     */
    private static function isConfigurationReceiver(array $tokens, int $operator): bool
    {
        $depth = 0;

        for ($index = $operator - 1; $index >= 0; $index--) {

            $token = $tokens[$index];
            $text  = is_array($token) ? $token[1] : $token;

            $depth += match ($text) {
                ')', ']' => 1,
                '(', '[' => -1,
                default  => 0,
            };

            if ($depth < 0 || ($depth === 0 && !in_array($text, ['(', '['], true) && !self::isChained($token))) {
                return false;
            }

            if (stripos($text, 'config') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the token can sit in a receiver's chain outside its brackets: a
     * name, a variable, `static` or a member operator.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return bool
     */
    private static function isChained(array|string $token): bool
    {
        $chain = [T_VARIABLE, T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE, T_STATIC, T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON];

        return is_array($token) && in_array($token[0], $chain, true);
    }

    /**
     * The keys whose first segment is neither the package's configuration nor
     * one of the framework's files.
     *
     * @param  list<string>  $keys
     * @return list<string>
     */
    private static function foreignReads(array $keys): array
    {
        $allowed = [self::PACKAGE_CONFIG, ...self::LARAVEL_CONFIG];

        return array_values(array_filter($keys, static fn (string $key): bool => !in_array(explode('.', $key, 2)[0], $allowed, true)));
    }

    /**
     * Each class, interface, trait and enum the source declares, in order, with
     * the docblock directly above it, or `null` when it has none.
     *
     * @param  string  $source
     * @return list<array{0: string, 1: ?string}>
     */
    private static function declarationsIn(string $source): array
    {
        $tokens       = self::tokens($source, false);
        $declarations = [];

        foreach ($tokens as $index => $token) {

            $name = $tokens[$index + 1] ?? null;

            if (!is_array($token) || !in_array($token[0], [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM], true) || !is_array($name) || $name[0] !== T_STRING) {
                continue;
            }

            $declarations[] = [$name[1], self::docblockBefore($tokens, $index)];
        }

        return $declarations;
    }

    /**
     * The docblock directly above the declaration at the index, past its
     * modifiers and attributes, or `null` when something else comes first.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return ?string
     */
    private static function docblockBefore(array $tokens, int $index): ?string
    {
        for ($index--; $index >= 0; $index--) {

            $token = $tokens[$index];

            if ($token === ']') {
                $index = self::attributeStart($tokens, $index);

                continue;
            }

            if (!is_array($token) || !in_array($token[0], [T_FINAL, T_ABSTRACT, T_READONLY, T_DOC_COMMENT], true)) {
                return null;
            }

            if ($token[0] === T_DOC_COMMENT) {
                return $token[1];
            }
        }

        return null;
    }

    /**
     * The index of the `#[` that opens the attribute whose closing `]` is at
     * the index.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return int
     */
    private static function attributeStart(array $tokens, int $index): int
    {
        for ($depth = 0; $index >= 0; $index--) {

            $token = $tokens[$index];

            $depth += match (true) {
                $token === ']'                                                => 1,
                $token === '[', is_array($token) && $token[0] === T_ATTRIBUTE => -1,
                default                                                       => 0,
            };

            if ($depth === 0) {
                return $index;
            }
        }

        return $index;
    }

    /**
     * What is wrong with the docblock above each declared type of the file.
     *
     * @param  string  $file
     * @param  list<array{0: string, 1: ?string}>  $declarations
     * @return list<string>
     */
    private static function problems(string $file, array $declarations): array
    {
        $problems = [];

        foreach ($declarations as [$type, $docblock]) {

            if ($docblock === null) {
                $problems[] = "{$file}: {$type} has no docblock.";

                continue;
            }

            $checks = [
                'is not tagged exactly one of @api and @internal' => preg_match_all(self::VISIBILITY_TAG, $docblock) === 1,
                'has no standard @author line'                    => preg_match(self::AUTHOR, $docblock)             === 1,
                'has no standard @copyright line'                 => preg_match(self::COPYRIGHT, $docblock)          === 1,
            ];

            foreach (array_keys(array_filter($checks, static fn (bool $passes): bool => !$passes)) as $problem) {
                $problems[] = "{$file}: {$type} {$problem}.";
            }
        }

        return $problems;
    }

    /**
     * The source's tokens, without whitespace and comments; docblocks are
     * dropped too unless they are kept.
     *
     * @param  string  $source
     * @param  bool  $withoutDocblocks
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function tokens(string $source, bool $withoutDocblocks = true): array
    {
        $ignored    = $withoutDocblocks ? [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT] : [T_WHITESPACE, T_COMMENT];
        $meaningful = static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], $ignored, true);

        return array_values(array_filter(token_get_all($source), $meaningful));
    }

    /**
     * The calls of any of the named methods the source makes on an object or a
     * class, each as it is named here, in order.
     *
     * @param  string  $source
     * @param  list<string>  $names
     * @return list<string>
     */
    private static function memberCallsIn(string $source, array $names): array
    {
        $wanted = array_combine(array_map(strtolower(...), $names), $names);
        $tokens = self::tokens($source);
        $calls  = [];

        foreach ($tokens as $index => $token) {

            $before = $tokens[$index - 1] ?? null;

            if (!is_array($token) || $token[0] !== T_STRING || !isset($wanted[strtolower($token[1])]) || ($tokens[$index + 1] ?? null) !== '(') {
                continue;
            }

            if (!is_array($before) || !in_array($before[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
                continue;
            }

            $calls[] = $wanted[strtolower($token[1])];
        }

        return $calls;
    }

    /**
     * Whether the file touches a guard: it is one of those that read a guard's
     * user, or it resolves a guard by name.
     *
     * @param  string  $file
     * @return bool
     */
    private static function touchesAGuard(string $file): bool
    {
        foreach (self::GUARD_READERS as $reader) {
            if (str_starts_with($file, $reader)) {
                return true;
            }
        }

        return self::resolvesAGuard(self::contents($file));
    }

    /**
     * Whether the source resolves a guard by name, on the manager or the
     * facade.
     *
     * @param  string  $source
     * @return bool
     */
    private static function resolvesAGuard(string $source): bool
    {
        return self::memberCallsIn($source, ['guard']) !== [];
    }

    /**
     * The static properties the class itself declares, named with it.
     *
     * @param  class-string  $class
     * @return list<string>
     */
    private static function staticPropertiesOf(string $class): array
    {
        $declared = [];

        foreach ((new \ReflectionClass($class))->getProperties(\ReflectionProperty::IS_STATIC) as $property) {
            if ($property->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            $declared[] = $class . '::$' . $property->getName();
        }

        return $declared;
    }
}
