<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds the package's namespaces to the dependency rules its design states:
 * which classes may not name which others. Each rule is data in `RULES`, so a
 * change that moves a class or narrows a dependency adds or tightens a rule
 * there. A rule applies to the classes in its `from` namespaces or classes (`*`
 * for every class of the package) except those in `except`, and forbids them to
 * name anything in its `forbids` namespaces or classes except what `allows`
 * lists; every name is relative to the package. The capture layer names neither
 * the stores nor the read model, and only its coordinator, the recorder and the
 * access recorder reach the record pipeline, so nothing a mapper or a listener
 * runs can write a record of its own. The read path names neither the console
 * nor the stores' writers, and access control names nothing of the package but
 * the values it compiles and the key tables an owner's filter reads.
 *
 * The same scanner holds the package to the framework: `FRAMEWORK_RULES` are
 * read the same way, with `forbids` and `allows` relative to the framework, so
 * nothing ships a route or a view, nothing reads authentication state, and the
 * domain reaches for no facade or container. Only the contributors, the cached
 * user, the core capture listeners, the user reference and the service provider
 * read authentication state, as the classes that touch `Auth` and the guards,
 * name its events or read the user an event carries; naming the authenticatable
 * type alone, as a viewer of the trail and an access policy do, reads none. And
 * no class names another package of the suite: anything under the suite's
 * namespace but outside this package's is refused.
 *
 * A class names another through an import (`use`, grouped or aliased), a
 * qualified or fully qualified name in its code, or a fully qualified type in a
 * docblock. Names resolve as PHP resolves them, without regard to case, and a
 * qualified name only through a class or namespace import. The source is
 * tokenised, not parsed, so a name built at run time (a class name in a string,
 * say) and an unqualified name of a class in the same namespace are not seen:
 * the test is a backstop for the rules, not a proof of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NamespaceDependenciesTest extends TestCase
{
    /** @var string The namespace every package name below is relative to. */
    private const string PACKAGE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The namespace every package of the suite sits under. */
    private const string VENDOR = 'SineMacula\Laravel\\';

    /** @var string The namespace every framework name below is relative to. */
    private const string FRAMEWORK = 'Illuminate\\';

    /** @var string A fully qualified suite or framework name in a docblock. */
    private const string DOCBLOCK_NAME = '/\\\((?:SineMacula|Illuminate)\\\[A-Za-z0-9_\\\]+)/i';

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The rules, by what each holds. */
    private const array RULES = [
        'the enums name nothing of the package but other enums' => [
            'from' => [
                'Records\Enums',
                'Definitions\Enums',
                'Runtime\Enums',
                'Privacy\Enums',
                'Delivery\Enums',
                'Stores\Enums',
                'Integrity\Enums',
                'Access\Enums',
                'Export\Enums',
                'Lifecycle\Enums',
            ],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => [
                'Records\Enums',
                'Definitions\Enums',
                'Runtime\Enums',
                'Privacy\Enums',
                'Delivery\Enums',
                'Stores\Enums',
                'Integrity\Enums',
                'Access\Enums',
                'Export\Enums',
                'Lifecycle\Enums',
            ],
        ],
        'the support helpers name nothing of the package but the support helpers, references and the clock contract' => [
            'from'    => ['Support'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Support', 'Records\Reference', 'Contracts\Clock'],
        ],
        'the record model names nothing of the definitions but the key owners' => [
            'from'    => ['Records'],
            'except'  => [],
            'forbids' => ['Definitions'],
            'allows'  => ['Definitions\Enums\KeyOwner'],
        ],
        'the definitions name nothing of the record model but event codes' => [
            'from'    => ['Definitions'],
            'except'  => [],
            'forbids' => ['Records'],
            'allows'  => ['Records\EventCode'],
        ],
        'contracts name nothing of the package but contracts, the definitions, access scopes and field readings they return, the records, '
        . 'references, pending records, read purposes, encrypted fields, field contexts and seal values they take and the conflict they raise' => [
            'from'    => ['Contracts'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => [
                'Contracts',
                'Definitions\EventDefinition',
                'Access\AccessScope',
                'Access\Enums\ReadPurpose',
                'Records\FinalisedRecord',
                'Records\Contribution',
                'Records\Reference',
                'Records\PendingRecord',
                'Privacy\EncryptedField',
                'Privacy\FieldContext',
                'Privacy\FieldReading',
                'Stores\RecordConflictException',
                'Integrity\SealSummary',
                'Integrity\AnchoredHead',
                'Integrity\PruneRecord',
                'Integrity\Anchors\AnchorConflictException',
            ],
        ],
        'the records name nothing of the stores, the read model, the console, the database helpers or anything that runs them' => [
            'from'    => ['Records'],
            'except'  => [],
            'forbids' => ['Stores', 'Models', 'Casts', 'Console', 'Database', 'Delivery', 'Contributors', 'Runtime', 'Listeners', 'Testing', 'Facades', 'Recorder', 'Http'],
            'allows'  => [],
        ],
        'the record values name nothing of the integrity layer but the finaliser, the codec and the manifests, which encode canonically' => [
            'from'    => ['Records'],
            'except'  => ['Records\RecordFinaliser', 'Records\EnvelopeCodec', 'Records\DisclosureManifest', 'Records\ExportManifest'],
            'forbids' => ['Integrity'],
            'allows'  => [],
        ],
        'the integrity layer names nothing of the read model or the console' => [
            'from'    => ['Integrity'],
            'except'  => [],
            'forbids' => ['Models', 'Casts', 'Console'],
            'allows'  => [],
        ],
        'the integrity layer names of the database helpers and the stores only the storage connection, the entries settings, '
        . 'the integrity tables and progress, the lifecycle tables, the key tables, the installation identity, the failure classifier and the row codec' => [
            'from'    => ['Integrity'],
            'except'  => [],
            'forbids' => ['Database', 'Stores'],
            'allows'  => [
                'Database\StorageConnection',
                'Database\EntrySettings',
                'Database\IntegrityTables',
                'Database\IntegrityProgress',
                'Database\LifecycleTables',
                'Database\KeyTables',
                'Database\InstallationIdentity',
                'Database\FailureClassifier',
                'Stores\RowCodec',
            ],
        ],
        'the integrity layer names nothing of the lifecycle' => [
            'from'    => ['Integrity'],
            'except'  => [],
            'forbids' => ['Lifecycle'],
            'allows'  => [],
        ],
        'the anchors name nothing of the database, the stores or the console' => [
            'from'    => ['Integrity\Anchors'],
            'except'  => [],
            'forbids' => ['Database', 'Stores', 'Console'],
            'allows'  => [],
        ],
        'the stores name nothing of the read model or the console' => [
            'from'    => ['Stores'],
            'except'  => [],
            'forbids' => ['Models', 'Casts', 'Console'],
            'allows'  => [],
        ],
        'the read model names nothing of the records, the stores, the integrity layer or the console' => [
            'from'    => ['Models', 'Casts'],
            'except'  => [],
            'forbids' => ['Records', 'Stores', 'Integrity', 'Console'],
            'allows'  => [],
        ],
        'the database helpers name nothing of the package but each other' => [
            'from'    => ['Database'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Database'],
        ],
        'only the service provider names the console' => [
            'from'    => ['*'],
            'except'  => ['Console', 'AuditLogServiceProvider'],
            'forbids' => ['Console'],
            'allows'  => [],
        ],
        'nothing names the service provider' => [
            'from'    => ['*'],
            'except'  => ['AuditLogServiceProvider'],
            'forbids' => ['AuditLogServiceProvider'],
            'allows'  => [],
        ],
        'only the delivery writes to the store' => [
            'from'    => ['*'],
            'except'  => ['Delivery', 'Stores', 'Testing', 'Contracts', 'AuditLogServiceProvider'],
            'forbids' => ['Contracts\AuditStore'],
            'allows'  => [],
        ],
        'only the testing helpers, the facade and the production check name the testing helpers' => [
            'from'    => ['*'],
            'except'  => ['Testing', 'Facades', 'Console\ProductionChecks'],
            'forbids' => ['Testing'],
            'allows'  => [],
        ],
        'only the facade names the facade' => [
            'from'    => ['*'],
            'except'  => ['Facades'],
            'forbids' => ['Facades'],
            'allows'  => [],
        ],
        'the runtime names nothing of the recorder, the delivery, the stores or the contributors' => [
            'from'    => ['Runtime'],
            'except'  => [],
            'forbids' => ['Recorder', 'Delivery', 'Stores', 'Contributors', 'Listeners', 'Http'],
            'allows'  => [],
        ],
        'the contributors name nothing of the recorder, the delivery or the stores' => [
            'from'    => ['Contributors'],
            'except'  => [],
            'forbids' => ['Recorder', 'Delivery', 'Stores'],
            'allows'  => [],
        ],
        'the events name nothing of the package but contracts' => [
            'from'    => ['Events'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Contracts'],
        ],
        'the privacy layer names nothing of the stores, the read model, the console, the database helpers or anything that runs them' => [
            'from'    => ['Privacy'],
            'except'  => [],
            'forbids' => ['Stores', 'Models', 'Casts', 'Console', 'Database', 'Delivery', 'Contributors', 'Runtime', 'Listeners', 'Testing', 'Facades', 'Recorder', 'Http'],
            'allows'  => [],
        ],
        'the records name nothing of the privacy layer but the minimised value' => [
            'from'    => ['Records'],
            'except'  => [],
            'forbids' => ['Privacy'],
            'allows'  => ['Privacy\Minimised'],
        ],
        'the formatters name nothing of the stores, the read model, the console, the database helpers or the delivery' => [
            'from'    => ['Export'],
            'except'  => [],
            'forbids' => ['Stores', 'Models', 'Casts', 'Console', 'Database', 'Delivery', 'Runtime', 'Listeners', 'Testing', 'Facades', 'Recorder'],
            'allows'  => [],
        ],
        'the delivery names nothing of the console or the read model' => [
            'from'    => ['Delivery'],
            'except'  => [],
            'forbids' => ['Console', 'Models', 'Casts'],
            'allows'  => [],
        ],
        'the capture layer names nothing of the stores, the read model, the console or the testing helpers' => [
            'from'    => ['Capture'],
            'except'  => [],
            'forbids' => ['Stores', 'Models', 'Casts', 'Console', 'Testing', 'Facades'],
            'allows'  => [],
        ],
        'the capture enums name nothing of the package but other enums, the definitions and the defining contract' => [
            'from'    => ['Capture\Enums'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => [
                'Capture\Enums',
                'Records\Enums',
                'Runtime\Enums',
                'Privacy\Enums',
                'Delivery\Enums',
                'Stores\Enums',
                'Integrity\Enums',
                'Definitions',
                'Contracts\DefinesAuditEvents',
            ],
        ],
        'the listeners name nothing of the stores, the console or the delivery' => [
            'from'    => ['Listeners'],
            'except'  => [],
            'forbids' => ['Stores', 'Console', 'Delivery'],
            'allows'  => [],
        ],
        'only the capture coordinator, the recorder, the access recorder and the lifecycle recorder write through the record pipeline' => [
            'from'    => ['*'],
            'except'  => ['Capture\CaptureCoordinator', 'Recorder', 'Querying\AccessRecorder', 'Lifecycle\LifecycleRecorder', 'RecordPipeline'],
            'forbids' => ['RecordPipeline'],
            'allows'  => [],
        ],
        'the read path names nothing of the console, the read model, the stores\' writers or the testing helpers' => [
            'from'    => ['Querying'],
            'except'  => [],
            'forbids' => ['Console', 'Models', 'Casts', 'Testing', 'Facades', 'Stores'],
            'allows'  => ['Stores\RowCodec', 'Stores\AuditWriteFailedException'],
        ],
        'the lifecycle names nothing of the console, the read model, the testing helpers or the facade' => [
            'from'    => ['Lifecycle'],
            'except'  => [],
            'forbids' => ['Console', 'Models', 'Casts', 'Testing', 'Facades'],
            'allows'  => [],
        ],
        'access control names nothing of the package but references, the read path\'s filters and positions, the definitions\' grammar, '
        . 'the canonical encoder and the key tables' => [
            'from'    => ['Access'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => [
                'Access',
                'Contracts\AuditAccessPolicy',
                'Records\Reference',
                'Querying\TrailFilters',
                'Querying\Position',
                'Definitions\EventDefinition',
                'Integrity\CanonicalEncoder',
                'Support\StoredTime',
                'Database\KeyTables',
            ],
        ],
        'the records name nothing of the read path or access control but the package\'s own codes' => [
            'from'    => ['Records'],
            'except'  => [],
            'forbids' => ['Querying', 'Access'],
            'allows'  => ['Querying\Enums\PackageActivity'],
        ],
        'the key store names nothing of the stores but the row codec, the read path, access control, the delivery, the lifecycle but the key-use '
        . 'rebuild\'s result, the console, the read model, the recorder, the facade or the testing helpers' => [
            'from'    => ['Keys'],
            'except'  => [],
            'forbids' => ['Stores', 'Querying', 'Access', 'Delivery', 'Lifecycle', 'Console', 'Models', 'Casts', 'Recorder', 'Facades', 'Testing'],
            'allows'  => ['Stores\RowCodec', 'Lifecycle\KeyUseRebuildResult'],
        ],
        'the read enums name nothing of the package but other enums, the definitions, event codes and the defining contract' => [
            'from'    => ['Querying\Enums'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => [
                'Querying\Enums',
                'Access\Enums',
                'Records\Enums',
                'Runtime\Enums',
                'Privacy\Enums',
                'Delivery\Enums',
                'Stores\Enums',
                'Integrity\Enums',
                'Definitions',
                'Records\EventCode',
                'Contracts\DefinesAuditEvents',
            ],
        ],
    ];

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The framework rules, by what each holds. */
    private const array FRAMEWORK_RULES = [
        'nothing ships a route, a controller, a view or a component' => [
            'from'    => ['*'],
            'except'  => [],
            'forbids' => ['Routing', 'Support\Facades\Route', 'View', 'Contracts\View', 'Support\Facades\View', 'Support\Facades\Blade'],
            'allows'  => ['Routing\Route'],
        ],
        'only the contributors, the cached user, the core capture listeners, the user reference and the service provider read authentication state; '
        . 'naming the authenticatable type reads none' => [
            'from'   => ['*'],
            'except' => [
                'Contributors',
                'Runtime\CachedUser',
                'Listeners\RecordLaravelAuthEvent',
                'Listeners\RecordGateDenial',
                'Capture\UserReference',
                'AuditLogServiceProvider',
            ],
            'forbids' => ['Auth', 'Contracts\Auth', 'Support\Facades\Auth'],
            'allows'  => ['Contracts\Auth\Authenticatable'],
        ],
        'the domain uses no facade and no application container, naming at most the failure to resolve a connection' => [
            'from'    => ['Records', 'Definitions', 'Support', 'Contracts', 'Integrity', 'Stores', 'Contributors', 'Runtime', 'Events', 'Privacy', 'Access', 'Keys'],
            'except'  => [],
            'forbids' => ['Support\Facades', 'Foundation', 'Container', 'Contracts\Foundation', 'Contracts\Container'],
            'allows'  => ['Contracts\Container\BindingResolutionException'],
        ],
    ];

    /** @var array<string, array<string, list<string>>> Every class of the package and the names it names under each prefix, read once per prefix. */
    private static array $names = [];

    /** @var ?array<string, string> Every class of the package and its source, read once. */
    private static ?array $sources = null;

    /**
     * Rows of `[from, except, forbids, allows]`: each rule.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>, 3: list<string>}>
     */
    public static function provideRules(): iterable
    {
        foreach (self::RULES as $rule => $scope) {
            yield $rule => [$scope['from'], $scope['except'], $scope['forbids'], $scope['allows']];
        }
    }

    /**
     * No class a rule applies to names anything it forbids.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testNoClassNamesWhatItsRuleForbids(array $from, array $except, array $forbids, array $allows): void
    {
        self::assertSame([], self::violations(self::names(), $from, $except, $forbids, $allows));
    }

    /**
     * Every namespace or class a rule names has a class in it, so a rule left
     * behind by a move fails rather than holding over nothing.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testEveryNameARuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        foreach ([...$from, ...$except, ...$forbids, ...$allows] as $named) {
            self::assertTrue(self::isPackageScope($named), "No class of the package is in {$named}.");
        }
    }

    /**
     * Rows of `[from, except, forbids, allows]`: each framework rule.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>, 3: list<string>}>
     */
    public static function provideFrameworkRules(): iterable
    {
        foreach (self::FRAMEWORK_RULES as $rule => $scope) {
            yield $rule => [$scope['from'], $scope['except'], $scope['forbids'], $scope['allows']];
        }
    }

    /**
     * No class a framework rule applies to names anything of the framework it
     * forbids.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideFrameworkRules')]
    public function testNoClassNamesWhatAFrameworkRuleForbids(array $from, array $except, array $forbids, array $allows): void
    {
        self::assertSame([], self::violations(self::names(self::FRAMEWORK), $from, $except, $forbids, $allows));
    }

    /**
     * Every namespace or class of the package a framework rule applies to, or
     * excepts, has a class in it.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideFrameworkRules')]
    public function testEveryPackageNameAFrameworkRuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        foreach ([...$from, ...$except] as $named) {
            self::assertTrue(self::isPackageScope($named), "No class of the package is in {$named}.");
        }
    }

    /**
     * Every namespace or class of the framework a framework rule forbids or
     * allows exists in the installed framework, so a misspelt name fails rather
     * than forbidding nothing.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideFrameworkRules')]
    public function testEveryFrameworkNameAFrameworkRuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        $framework = dirname((string) (new \ReflectionClass(ServiceProvider::class))->getFileName(), 2);

        foreach ([...$forbids, ...$allows] as $named) {

            $exists = is_dir($framework . '/' . str_replace('\\', '/', $named))
                || class_exists(self::FRAMEWORK . $named)
                || interface_exists(self::FRAMEWORK . $named);

            self::assertTrue($exists, "Nothing of the framework is in {$named}.");
        }
    }

    /**
     * No class names another package of the suite: every name under the suite's
     * namespace is within this package's.
     *
     * @return void
     */
    public function testNoClassNamesAnotherSuitePackage(): void
    {
        $violations = [];

        foreach (self::names(self::VENDOR) as $class => $names) {
            foreach ($names as $name) {

                if (self::isWithin($name, ['AuditLog'])) {
                    continue;
                }

                $violations[] = "{$class} names SineMacula\\Laravel\\{$name}";
            }
        }

        self::assertSame([], $violations);
    }

    /**
     * The scanner finds a package name however a class names it: imported
     * alone, aliased, grouped, as a function or a constant (alone or within a
     * group), through an alias or relative to its namespace, fully qualified in
     * code or in a docblock; and nothing for an unqualified name, a closure's
     * `use`, or a name outside the package.
     *
     * @return void
     */
    public function testTheScannerFindsEveryWayOfNamingAClass(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\AuditLog\Records;

            use Illuminate\Support\Str;
            use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
            use SineMacula\Laravel\AuditLog\Definitions as Defining;
            use SineMacula\Laravel\AuditLog\Records\{EventCode, Enums\Outcome as Result};
            use function SineMacula\Laravel\AuditLog\Support\helper;
            use SineMacula\Laravel\AuditLog\{function Definitions\define, const Support\FLAG};

            /**
             * @see \SineMacula\Laravel\AuditLog\Support\TextSanitizer
             */
            final class Example
            {
                use Concerns\DescribesTheActivity;

                /** @var \SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents */
                private $definitions;

                public function run(): void
                {
                    $value = 1;

                    $callback = static function () use ($value): int {
                        return $value;
                    };

                    new Defining\EventDefinition;
                    new \SineMacula\Laravel\AuditLog\Support\ValueNormaliser($callback);
                    new namespace\PendingRecord;
                    new AuditRecord;
                    Str::random();
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Contracts\DefinesAuditEvents',
            'Definitions',
            'Definitions\EventCatalogue',
            'Definitions\EventDefinition',
            'Definitions\define',
            'Records\Concerns\DescribesTheActivity',
            'Records\Enums\Outcome',
            'Records\EventCode',
            'Records\PendingRecord',
            'Support\FLAG',
            'Support\TextSanitizer',
            'Support\ValueNormaliser',
            'Support\helper',
        ], $names);
    }

    /**
     * The scanner reads the imports of a bracketed namespace as imports, gives
     * each namespace its own aliases, reads a closure's `use` at the top of a
     * namespace as code, and resolves names in the global namespace from its
     * root.
     *
     * @return void
     */
    public function testTheScannerReadsEachBracketedNamespaceOnItsOwn(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\AuditLog\Definitions {

                use SineMacula\Laravel\AuditLog\Records\EventCode;
                use SineMacula\Laravel\AuditLog\Records as Recording;

                $resolve = static function () use ($container): void {
                    new \SineMacula\Laravel\AuditLog\Support\ValueNormaliser;
                };

                final class Example
                {
                    use Concerns\DescribesDefinitions;
                }
            }

            namespace {

                new Recording\PendingRecord;
                new SineMacula\Laravel\AuditLog\Records\Reference;
                new namespace\SineMacula\Laravel\AuditLog\Support\TextSanitizer;
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Definitions\Concerns\DescribesDefinitions',
            'Records',
            'Records\EventCode',
            'Records\Reference',
            'Support\TextSanitizer',
            'Support\ValueNormaliser',
        ], $names);
    }

    /**
     * A qualified name resolves through the class or namespace import its first
     * segment names, whatever its case, and not through a function's or a
     * constant's import of the same name, alone or within a group; a rule
     * catches a forbidden name whatever its case, fully qualified in code or in
     * a docblock.
     *
     * @return void
     */
    public function testTheScannerResolvesAQualifiedNameAsPhpDoes(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\AuditLog\Support;

            use SineMacula\Laravel\AuditLog as Audit;
            use SineMacula\Laravel\AuditLog\Definitions as Defining;
            use SineMacula\Laravel\AuditLog\Records as Recording;
            use function Other\Audit;
            use CONST Other\Defining;
            use Other\{FUNCTION record as Recording, const Audit};

            /**
             * @see \sinemacula\laravel\auditlog\definitions\EventCatalogue
             */
            final class Example
            {
                public function run(): void
                {
                    new Audit\Records\EventCode;
                    new audit\Definitions\EventDefinition;
                    new DEFINING\FieldRule;
                    new recording\Reference;
                    new \sinemacula\laravel\auditlog\records\AuditRecord;
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Definitions',
            'Definitions\EventDefinition',
            'Definitions\FieldRule',
            'Records',
            'Records\EventCode',
            'Records\Reference',
            'definitions\EventCatalogue',
            'records\AuditRecord',
        ], $names);

        self::assertSame([
            'Support\Example names Definitions',
            'Support\Example names Definitions\EventDefinition',
            'Support\Example names Definitions\FieldRule',
            'Support\Example names Records',
            'Support\Example names Records\EventCode',
            'Support\Example names Records\Reference',
            'Support\Example names definitions\EventCatalogue',
            'Support\Example names records\AuditRecord',
        ], self::violations(['Support\Example' => $names], ['support'], [], ['DEFINITIONS', 'Records'], []));
    }

    /**
     * The scanner finds names under whichever prefix it is given, in code and
     * in docblocks alike, so the one tokeniser serves the package rules, the
     * suite check and the framework rules; a name of another package of the
     * suite is found under the suite's prefix and not under the package's.
     *
     * @return void
     */
    public function testTheScannerFindsNamesUnderAnyPrefix(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\AuditLog\Records;

            use SineMacula\Laravel\Other\Thing;
            use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

            /**
             * @see \Illuminate\Support\Facades\Auth
             */
            final class Example
            {
                public function run(): void
                {
                    new \Illuminate\Routing\Router;
                    new Thing;
                }
            }
            PHP;

        $vendor    = self::namesIn($source, self::VENDOR);
        $framework = self::namesIn($source, self::FRAMEWORK);

        sort($vendor);
        sort($framework);

        self::assertSame(['AuditLog\Support\TextSanitizer', 'Other\Thing'], $vendor);
        self::assertSame(['Routing\Router', 'Support\Facades\Auth'], $framework);
        self::assertSame(['Support\TextSanitizer'], self::namesIn($source));
    }

    /**
     * Rows of `[rule, class, name, whether the rule refuses it]`: what each
     * capture rule refuses, and what it leaves to the classes it allows.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: bool}>
     */
    public static function provideCaptureNames(): iterable
    {
        $capture   = 'the capture layer names nothing of the stores, the read model, the console or the testing helpers';
        $enums     = 'the capture enums name nothing of the package but other enums, the definitions and the defining contract';
        $listeners = 'the listeners name nothing of the stores, the console or the delivery';
        $pipeline  = 'only the capture coordinator, the recorder, the access recorder and the lifecycle recorder write through the record pipeline';

        yield from [
            'a watch naming the read model'           => [$capture, 'Capture\ModelWatch', 'Models\AuditEntry', true],
            'a watch naming a cast of the read model' => [$capture, 'Capture\ModelWatch', 'Casts\UtcInstant', true],
            'the coordinator naming a store'          => [$capture, 'Capture\CaptureCoordinator', 'Stores\DatabaseAuditStore', true],
            'the coordinator naming the fake'         => [$capture, 'Capture\CaptureCoordinator', 'Testing\FakeAuditStore', true],
            'the coordinator naming the facade'       => [$capture, 'Capture\CaptureCoordinator', 'Facades\AuditLog', true],
            'the coordinator naming its signal'       => [$capture, 'Capture\CaptureCoordinator', 'Delivery\CaptureSignal', false],
            'a capture enum naming a definition'      => [$enums, 'Capture\Enums\CapturedActivity', 'Definitions\EventDefinition', false],
            'a capture enum naming the contract'      => [$enums, 'Capture\Enums\CapturedActivity', 'Contracts\DefinesAuditEvents', false],
            'a capture enum naming a record enum'     => [$enums, 'Capture\Enums\ModelEvent', 'Records\Enums\Outcome', false],
            'a capture enum naming another contract'  => [$enums, 'Capture\Enums\CapturedActivity', 'Contracts\EventMapper', true],
            'a capture enum naming the coordinator'   => [$enums, 'Capture\Enums\ModelEvent', 'Capture\CaptureCoordinator', true],
            'a listener naming the delivery'          => [$listeners, 'Listeners\RecordGateDenial', 'Delivery\RecordDelivery', true],
            'a listener naming a store'               => [$listeners, 'Listeners\RecordModelChange', 'Stores\NullAuditStore', true],
            'a listener naming the coordinator'       => [$listeners, 'Listeners\RecordGateDenial', 'Capture\CaptureCoordinator', false],
            'a listener naming the pipeline'          => [$pipeline, 'Listeners\RecordModelChange', 'RecordPipeline', true],
            'the facade naming the pipeline'          => [$pipeline, 'Facades\AuditLog', 'RecordPipeline', true],
            'the capture settings naming it'          => [$pipeline, 'Capture\CaptureSettings', 'RecordPipeline', true],
            'the coordinator naming the pipeline'     => [$pipeline, 'Capture\CaptureCoordinator', 'RecordPipeline', false],
            'the recorder naming the pipeline'        => [$pipeline, 'Recorder', 'RecordPipeline', false],
            'the access recorder naming the pipeline' => [$pipeline, 'Querying\AccessRecorder', 'RecordPipeline', false],
            'the lifecycle recorder naming it'        => [$pipeline, 'Lifecycle\LifecycleRecorder', 'RecordPipeline', false],
            'another lifecycle class naming it'       => [$pipeline, 'Lifecycle\LifecycleEvidence', 'RecordPipeline', true],
            'the trail reader naming the pipeline'    => [$pipeline, 'Querying\TrailReader', 'RecordPipeline', true],
        ];
    }

    /**
     * Each capture rule refuses what it forbids and leaves what it allows, or
     * what a class it excepts names, so a rule that held over nothing, or one
     * widened to let a listener or a mapper reach the record pipeline, fails.
     *
     * @param  string  $rule
     * @param  string  $class
     * @param  string  $name
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('provideCaptureNames')]
    public function testEachCaptureRuleRefusesWhatItForbids(string $rule, string $class, string $name, bool $refused): void
    {
        $scope      = self::RULES[$rule];
        $violations = self::violations([$class => [$name]], $scope['from'], $scope['except'], $scope['forbids'], $scope['allows']);

        self::assertSame($refused ? ["{$class} names {$name}"] : [], $violations);
    }

    /**
     * What each class a rule applies to names that the rule forbids.
     *
     * @param  array<string, list<string>>  $classes
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return list<string>
     */
    private static function violations(array $classes, array $from, array $except, array $forbids, array $allows): array
    {
        $violations = [];

        foreach ($classes as $class => $names) {

            if (!self::isWithin($class, $from) || self::isWithin($class, $except)) {
                continue;
            }

            foreach ($names as $name) {

                if (!self::isWithin($name, $forbids) || self::isWithin($name, $allows)) {
                    continue;
                }

                $violations[] = "{$class} names {$name}";
            }
        }

        return $violations;
    }

    /**
     * Whether the namespace or class of the package has a class of the package
     * in it.
     *
     * @param  string  $named
     * @return bool
     */
    private static function isPackageScope(string $named): bool
    {
        $classes = array_keys(self::sources());

        return array_filter($classes, static fn (string $class): bool => self::isWithin($class, [$named])) !== [];
    }

    /**
     * Every class of the package and the names under the prefix it names,
     * relative to the prefix, read once per prefix.
     *
     * @param  string  $prefix
     * @return array<string, list<string>>
     */
    private static function names(string $prefix = self::PACKAGE): array
    {
        return self::$names[$prefix] ??= array_map(static fn (string $source): array => self::namesIn($source, $prefix), self::sources());
    }

    /**
     * Every class of the package and its source, by its name relative to the
     * package, read once.
     *
     * @return array<string, string>
     */
    private static function sources(): array
    {
        if (self::$sources !== null) {
            return self::$sources;
        }

        $source  = dirname(__DIR__, 3) . '/src/';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $sources = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $class = str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4));

            $sources[$class] = (string) file_get_contents($file->getPathname());
        }

        ksort($sources);

        return self::$sources = $sources;
    }

    /**
     * The distinct names under the prefix the source names, relative to the
     * prefix.
     *
     * An import is read as one statement, so its names are not read again as
     * names in code; each namespace's body, whether it ends at the next
     * `namespace` or at its closing brace, has its own aliases. The names of a
     * trait's or a closure's `use` are read as names in code.
     *
     * @param  string  $source
     * @param  string  $prefix
     * @return list<string>
     */
    private static function namesIn(string $source, string $prefix = self::PACKAGE): array
    {
        $tokens    = self::tokens($source);
        $depths    = self::depths($tokens);
        $namespace = '';
        $body      = 0;
        $aliases   = [];
        $names     = [];

        for ($index = 0, $count = count($tokens); $index < $count; $index++) {

            [$id, $text] = is_array($tokens[$index]) ? $tokens[$index] : [null, $tokens[$index]];

            if ($id === T_NAMESPACE) {
                [$namespace, $body, $index] = self::declared($tokens, $depths, $index);

                $aliases = [];
            } elseif ($id === T_USE && self::isImport($tokens, $depths, $index, $body)) {
                [$statement, $index] = self::statement($tokens, $index + 1);

                array_push($names, ...self::imports($statement, $aliases));
            } elseif ($id === T_DOC_COMMENT) {
                array_push($names, ...self::documented($text));
            } elseif ($id !== null) {
                $names[] = self::qualified($id, $text, $namespace, $aliases);
            }
        }

        $prefixed = array_filter($names, static fn (?string $name): bool => $name !== null && strncasecmp($name, $prefix, strlen($prefix)) === 0);

        return array_values(array_unique(array_map(static fn (string $name): string => substr($name, strlen($prefix)), $prefixed)));
    }

    /**
     * The namespace declared at the index, the depth of the braces its imports
     * sit in, and the index of its last token before its body.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @return array{0: string, 1: int, 2: int}
     */
    private static function declared(array $tokens, array $depths, int $index): array
    {
        $namespace = is_array($tokens[$index + 1]) ? self::text($tokens[++$index]) : '';
        $body      = ($tokens[$index + 1] ?? null) === '{' ? $depths[$index] + 1 : $depths[$index];

        return [$namespace, $body, $index];
    }

    /**
     * Whether the `use` at the index is an import: one directly in the
     * namespace's body, not a trait's in a class or a closure's after its
     * parameters.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @param  int  $body
     * @return bool
     */
    private static function isImport(array $tokens, array $depths, int $index, int $body): bool
    {
        return $depths[$index] === $body && $tokens[$index - 1] !== ')';
    }

    /**
     * The source's tokens, without whitespace and plain comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function tokens(string $source): array
    {
        $meaningful = static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT], true);

        return array_values(array_filter(token_get_all($source), $meaningful));
    }

    /**
     * How many braces are open before each token.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @return list<int>
     */
    private static function depths(array $tokens): array
    {
        $depths = [];
        $depth  = 0;

        foreach ($tokens as $token) {

            $depths[] = $depth;

            $depth += match (true) {
                $token === '{', is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) => 1,
                $token === '}'                                                                                            => -1,
                default                                                                                                   => 0,
            };
        }

        return $depths;
    }

    /**
     * The import statement that starts at the index, as text without its
     * whitespace, and the index of its `;`.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return array{0: string, 1: int}
     */
    private static function statement(array $tokens, int $index): array
    {
        $statement = '';

        for (; ($tokens[$index] ?? ';') !== ';'; $index++) {
            $statement .= self::text($tokens[$index]);
        }

        return [$statement, $index];
    }

    /**
     * The text of the token, with a space around `as` and after `function` or
     * `const`, the words an import statement may hold.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return string
     */
    private static function text(array|string $token): string
    {
        if (!is_array($token)) {
            return $token;
        }

        return match ($token[0]) {
            T_AS                => ' as ',
            T_FUNCTION, T_CONST => $token[1] . ' ',
            default             => $token[1],
        };
    }

    /**
     * The names an import statement imports, recording the alias each class or
     * namespace import gives by its lower case. A qualified name resolves only
     * through those, without regard to case: a function's or a constant's
     * import of the same name is kept apart from them.
     *
     * @param  string  $statement
     * @param  array<string, string>  $aliases
     * @return list<string>
     */
    private static function imports(string $statement, array &$aliases): array
    {
        [$kind, $statement] = self::kind($statement, '');

        $prefix = '';

        if (preg_match('/^(.*)\\\\\{(.*)\}$/', $statement, $group) === 1) {
            [, $prefix, $statement] = $group;

            $prefix .= '\\';
        }

        $names = [];

        foreach (explode(',', $statement) as $import) {

            [$member, $import] = self::kind($import, $kind);

            $parts = explode(' as ', $import);
            $name  = ltrim($prefix . $parts[0], '\\');
            $alias = $parts[1] ?? substr((string) strrchr('\\' . $name, '\\'), 1);

            if ($member === '') {
                $aliases[strtolower($alias)] = $name;
            }

            $names[] = $name;
        }

        return $names;
    }

    /**
     * What the import imports, `function`, `const` or `''` for a class or a
     * namespace, and the import without the word that gives it: a whole
     * statement's, or one member's of a group, which imports what its statement
     * does unless it gives its own.
     *
     * @param  string  $import
     * @param  string  $kind
     * @return array{0: string, 1: string}
     */
    private static function kind(string $import, string $kind): array
    {
        if (preg_match('/^(function|const) (.*)$/i', $import, $match) === 1) {
            return [strtolower($match[1]), $match[2]];
        }

        return [$kind, $import];
    }

    /**
     * The fully qualified name a name token stands for: a qualified name
     * through the alias its first segment names, whatever its case, or else
     * relative to the namespace; `null` for any other token.
     *
     * @param  int  $id
     * @param  string  $text
     * @param  string  $namespace
     * @param  array<string, string>  $aliases
     * @return ?string
     */
    private static function qualified(int $id, string $text, string $namespace, array $aliases): ?string
    {
        if ($id === T_NAME_FULLY_QUALIFIED) {
            return substr($text, 1);
        }

        if ($id === T_NAME_RELATIVE) {
            return ltrim($namespace . substr($text, strlen('namespace')), '\\');
        }

        if ($id !== T_NAME_QUALIFIED) {
            return null;
        }

        [$first, $rest] = explode('\\', $text, 2);

        $alias = strtolower($first);

        return isset($aliases[$alias]) ? $aliases[$alias] . '\\' . $rest : ltrim($namespace . '\\' . $text, '\\');
    }

    /**
     * The fully qualified suite and framework names a docblock gives.
     *
     * @param  string  $docblock
     * @return list<string>
     */
    private static function documented(string $docblock): array
    {
        preg_match_all(self::DOCBLOCK_NAME, $docblock, $matches);

        return array_map(static fn (string $name): string => rtrim($name, '\\'), $matches[1]);
    }

    /**
     * Whether the name is one of the namespaces or classes, or inside one of
     * them, without regard to case; `*` stands for the whole package.
     *
     * @param  string  $name
     * @param  list<string>  $scopes
     * @return bool
     */
    private static function isWithin(string $name, array $scopes): bool
    {
        $name = strtolower($name);

        foreach (array_map(strtolower(...), $scopes) as $scope) {
            if ($scope === '*' || $name === $scope || str_starts_with($name, $scope . '\\')) {
                return true;
            }
        }

        return false;
    }
}
