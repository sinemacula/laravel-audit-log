<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Container\Container;
use Illuminate\Foundation\Testing\Concerns\MakesHttpRequests;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;

/**
 * A drift guard for the README's PHP snippets: every class a snippet imports
 * exists; every class it names by its short name, statically, with `new` or
 * after `implements`, is one it imports, one of the package's own, the
 * framework's scheduler or one of the example application's own; every static
 * method or constant it reads on such a class exists, a call on the facade
 * being a method of the recorder or the facade's own; and every method it calls
 * on an object is one a class of the package declares, one of the framework
 * methods the snippets use, or one of the example application's own. So a class
 * or a method renamed in the code fails here until the README is changed with
 * it.
 *
 * It catches a name that does not exist, not a call on the wrong object or with
 * the wrong arguments: what a snippet does is held to the code by review, and
 * the README's first snippet runs verbatim in a feature test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ReadmeSnippetsTest extends TestCase
{
    /** @var string The package's namespace. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var list<string> The example application's own classes the snippets name, which exist only in the example. */
    private const array APPLICATION_CLASSES = ['Invoice', 'InvoiceActivity', 'OrderShipped', 'OrderShippedMapper', 'OrganisationAuditPolicy', 'OrganisationContributor', 'User'];

    /** @var array<string, class-string> The framework classes the snippets name without importing them, by short name: the scheduler the `Schedule` facade stands for. */
    private const array FRAMEWORK_CLASSES = ['Schedule' => Schedule::class];

    /** @var list<class-string> The framework classes whose methods the snippets call on an object: the container, a scheduled event and a test's requests. */
    private const array FRAMEWORK_CALLERS = [Container::class, Event::class, MakesHttpRequests::class];

    /** @var list<string> The methods the snippets call that are the example application's own. */
    private const array APPLICATION_CALLS = ['isAuditor'];

    /** @var ?list<string> The public methods the package's classes declare, read once. */
    private static ?array $packageMethods = null;

    /**
     * Every PHP snippet of the README names only classes, static members and
     * methods that exist.
     *
     * @return void
     */
    public function testEverySnippetNamesOnlyWhatExists(): void
    {
        $readme = file_get_contents(dirname(__DIR__, 3) . '/README.md');

        self::assertIsString($readme);

        preg_match_all('/^```php\n(.*?)^```[ \t]*$/ms', $readme, $blocks);

        $problems = [];

        foreach ($blocks[1] as $block) {
            array_push($problems, ...self::problemsIn($block));
        }

        self::assertNotSame([], $blocks[1], 'The README shows no PHP snippet.');
        self::assertSame([], $problems, 'The README\'s snippets name what does not exist.');
    }

    /**
     * The scanner finds a missing import, an unknown class, an unknown static
     * method or constant, a call the facade does not offer and a method no
     * class declares, and nothing in a snippet that names only what exists.
     *
     * @return void
     */
    public function testTheScannerFindsEveryNameThatDoesNotExist(): void
    {
        $valid = <<<'PHP'
            use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
            use SineMacula\Laravel\AuditLog\Lifecycle\Authority;

            AuditLog::event('invoice.approved')->on($invoice)->by($user)->record();
            $page = AuditLog::trail()->visibleTo($user)->forSubject(Invoice::class)->cursorPaginate();
            $owner = KeyOwner::ACTOR;
            $authority = new Authority(Reference::to($user), 'case.closed');
            Schedule::command('audit-log:drain')->everyMinute();
            PHP;

        $invalid = <<<'PHP'
            use SineMacula\Laravel\AuditLog\Records\Nothing;
            use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;

            AuditLog::recordAll('invoice.approved');
            HoldScope::nowhere();
            $owner = KeyOwner::NOBODY;
            $authority = new Authorities('case.closed');
            final class Policy implements AuditPolicy {}
            AuditLog::event('invoice.approved')->recordd();
            PHP;

        self::assertSame([], self::problemsIn($valid));
        self::assertSame([
            'import SineMacula\Laravel\AuditLog\Records\Nothing',
            'class Authorities',
            'class AuditPolicy',
            'AuditLog::recordAll',
            'HoldScope::nowhere',
            'KeyOwner::NOBODY',
            'method recordd',
        ], self::problemsIn($invalid));
    }

    /**
     * What a snippet names that does not exist: an import, a class, a static
     * member or a method called on an object, each once, in that order.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function problemsIn(string $code): array
    {
        $imports = self::importsIn($code);

        return [...self::missingImports($imports), ...self::unknownClassesIn($code, $imports), ...self::unknownStaticsIn($code, $imports), ...self::unknownCallsIn($code)];
    }

    /**
     * The classes the snippet imports from a namespace, by the short name each
     * is imported as.
     *
     * @param  string  $code
     * @return array<string, string>
     */
    private static function importsIn(string $code): array
    {
        preg_match_all('/^\s*use\s+([A-Za-z_][\w\\\]*\\\[\w\\\]+)\s*;/m', $code, $matches);

        $imports = [];

        foreach ($matches[1] as $import) {
            $imports[substr((string) strrchr('\\' . $import, '\\'), 1)] = $import;
        }

        return $imports;
    }

    /**
     * The imports that name no class, interface, enum or trait.
     *
     * @param  array<string, string>  $imports
     * @return list<string>
     */
    private static function missingImports(array $imports): array
    {
        $missing = array_filter($imports, static fn (string $import): bool => !self::exists($import));

        return array_values(array_map(static fn (string $import): string => 'import ' . $import, $missing));
    }

    /**
     * The short names the snippet makes with `new` or implements that are not
     * classes it may name.
     *
     * @param  string  $code
     * @param  array<string, string>  $imports
     * @return list<string>
     */
    private static function unknownClassesIn(string $code, array $imports): array
    {
        preg_match_all('/\b(?:new|implements)\s+\\\?([A-Z]\w*)/', $code, $matches);

        $unknown = array_filter(array_unique($matches[1]), static fn (string $class): bool => !self::isKnownClass($class, $imports));

        return array_values(array_map(static fn (string $class): string => 'class ' . $class, $unknown));
    }

    /**
     * The static members the snippet reads, but `::class`, that do not exist on
     * the class their short name stands for.
     *
     * @param  string  $code
     * @param  array<string, string>  $imports
     * @return list<string>
     */
    private static function unknownStaticsIn(string $code, array $imports): array
    {
        preg_match_all('/(?<![\w\\\$])([A-Z]\w*)::([A-Za-z_]\w*)/', $code, $matches, PREG_SET_ORDER);

        $statics = array_unique(array_map(static fn (array $match): string => $match[1] . '::' . $match[2], $matches));

        return array_values(array_filter($statics, static function (string $static) use ($imports): bool {

            [$class, $member] = explode('::', $static);

            return $member !== 'class' && !self::isKnownStatic($class, $member, $imports);
        }));
    }

    /**
     * The methods the snippet calls on an object that no class of the package
     * declares, nor the framework classes the snippets use, nor the example
     * application.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function unknownCallsIn(string $code): array
    {
        preg_match_all('/(?:->|\?->)\s*([a-zA-Z_]\w*)\s*\(/', $code, $matches);

        $unknown = array_filter(array_unique($matches[1]), static fn (string $call): bool => !in_array($call, self::APPLICATION_CALLS, true) && !self::isKnownMethod($call));

        return array_values(array_map(static fn (string $call): string => 'method ' . $call, $unknown));
    }

    /**
     * Whether the short name is a class the snippet may name: one it imports
     * that exists, one of the package's own, the framework's scheduler or one
     * of the example application's own.
     *
     * @param  string  $class
     * @param  array<string, string>  $imports
     * @return bool
     */
    private static function isKnownClass(string $class, array $imports): bool
    {
        return in_array($class, self::APPLICATION_CLASSES, true) || self::resolve($class, $imports) !== null;
    }

    /**
     * Whether the static member exists on the class the short name resolves to:
     * a method, a constant or an enum case, or, on the facade, a method of the
     * recorder or of the facade. The example application's own classes hold
     * whatever the example says.
     *
     * @param  string  $class
     * @param  string  $member
     * @param  array<string, string>  $imports
     * @return bool
     */
    private static function isKnownStatic(string $class, string $member, array $imports): bool
    {
        if (in_array($class, self::APPLICATION_CLASSES, true)) {
            return true;
        }

        $resolved = self::resolve($class, $imports);

        if ($resolved === null) {
            return false;
        }

        if ($resolved === AuditLog::class) {
            return method_exists(Recorder::class, $member) || method_exists(AuditLog::class, $member);
        }

        return method_exists($resolved, $member) || defined($resolved . '::' . $member);
    }

    /**
     * Whether a class of the package, or one of the framework classes the
     * snippets call, declares the method.
     *
     * @param  string  $method
     * @return bool
     */
    private static function isKnownMethod(string $method): bool
    {
        foreach (self::FRAMEWORK_CALLERS as $class) {
            if (method_exists($class, $method)) {
                return true;
            }
        }

        return in_array(strtolower($method), self::packageMethods(), true);
    }

    /**
     * The class the short name stands for: the import of that name when it
     * exists, else the package's own class of that name, else the framework
     * class the snippets name, else none.
     *
     * @param  string  $class
     * @param  array<string, string>  $imports
     * @return ?string
     */
    private static function resolve(string $class, array $imports): ?string
    {
        if (isset($imports[$class])) {
            return self::exists($imports[$class]) ? $imports[$class] : null;
        }

        return self::packageClasses()[$class] ?? self::FRAMEWORK_CLASSES[$class] ?? null;
    }

    /**
     * Whether the name is a class, an interface, an enum or a trait that
     * exists.
     *
     * @param  string  $name
     * @return bool
     */
    private static function exists(string $name): bool
    {
        return class_exists($name) || interface_exists($name) || enum_exists($name) || trait_exists($name);
    }

    /**
     * The lower-cased public methods the package's classes declare, those of
     * their traits included and those inherited from the framework not.
     *
     * @return list<string>
     */
    private static function packageMethods(): array
    {
        if (self::$packageMethods !== null) {
            return self::$packageMethods;
        }

        $methods = [];

        foreach (self::packageClasses() as $class) {
            foreach ((new \ReflectionClass($class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

                if (!str_starts_with($method->getDeclaringClass()->getName(), self::PACKAGE_NAMESPACE)) {
                    continue;
                }

                $methods[] = strtolower($method->getName());
            }
        }

        return self::$packageMethods = array_values(array_unique($methods));
    }

    /**
     * The package's classes, interfaces, enums and traits, by short name.
     *
     * @return array<string, class-string>
     */
    private static function packageClasses(): array
    {
        $root    = dirname(__DIR__, 3) . '/src/';
        $classes = [];
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $class = self::PACKAGE_NAMESPACE . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -4));

            if (!class_exists($class) && !interface_exists($class) && !enum_exists($class) && !trait_exists($class)) {
                continue;
            }

            $classes[$file->getBasename('.php')] = $class;
        }

        return $classes;
    }
}
