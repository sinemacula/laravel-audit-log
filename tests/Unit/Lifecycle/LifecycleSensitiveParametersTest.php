<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Rewrapper;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Holds `src/Lifecycle` and the retention contract to marking each payload
 * parameter `#[\SensitiveParameter]`, so stack traces keep no payload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleSensitiveParametersTest extends TestCase
{
    /** @var string The namespace every source file is named under. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The folders under `src` the rule holds. */
    private const array FOLDERS = ['Lifecycle'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = ['Contracts/RetentionPolicy.php'];

    /** @var list<string> The names a parameter holding a payload goes by. */
    private const array PAYLOAD_NAMES = [
        'row', 'rows', 'record', 'records', 'payload', 'line', 'lines', 'envelope', 'plaintext', 'ciphertext', 'members', 'properties', 'dataKey', 'wrapped',
    ];

    /** @var list<string> The types a payload parameter goes by. */
    private const array PAYLOAD_TYPES = [
        \Closure::class,
        AuditRecord::class,
        FinalisedRecord::class,
        PendingRecord::class,
        SubjectKeyRow::class,
        self::HOLD_SCOPE,
        self::NAMESPACE . 'Lifecycle\ImportLine',
    ];

    /** @var string The hold scope, whose reference parameters are all payload. */
    private const string HOLD_SCOPE = self::NAMESPACE . 'Lifecycle\HoldScope';

    /** @var string The hold scope's file, relative to `src`. */
    private const string HOLD_SCOPE_FILE = 'Lifecycle/HoldScope.php';

    /** @var string Matches a closure payload parameter's type in source, where none resolves. */
    private const string PAYLOAD_TYPE_IN_SOURCE = '/\b(?:AuditRecord|FinalisedRecord|PendingRecord|SubjectKeyRow|HoldScope|ImportLine|Closure)\b/';

    /** @var string Matches a closure reference parameter's type in source, where none resolves. */
    private const string REFERENCE_TYPE_IN_SOURCE = '/\bReference\b/';

    /** @var list<class-string> The classes the scan must read, from those this suite already holds. */
    private const array MUST_READ = [RetentionPolicy::class, RetentionDecisions::class, RetentionSettings::class, ImportStatus::class, Rewrapper::class];

    /** @var list<string> The files whose closures the source scan must read. */
    private const array MUST_READ_CLOSURES_OF = ['Lifecycle/RetentionSettings.php', 'Lifecycle/Rewrapper.php'];

    /** @var string The class a source is written for, to show what the scan flags. */
    private const string FIXTURE = 'Tests\Unit\Lifecycle\Scanned\EveryKind';

    /** @var string The setting as it was before the test. */
    private string $ignoreArgs = '';

    /**
     * Keep every frame's arguments.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoreArgs = (string) ini_get(self::IGNORE_ARGS);

        ini_set(self::IGNORE_ARGS, '0');
    }

    /**
     * Put the setting back as it was.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ini_set(self::IGNORE_ARGS, $this->ignoreArgs);

        parent::tearDown();
    }

    /**
     * Every method marks each payload parameter, the hold scope references.
     *
     * @return void
     */
    public function testEveryPayloadParameterIsMarkedSensitive(): void
    {
        $unmarked = [];

        foreach (self::scanned() as $class) {
            foreach (self::payloadParametersOf($class) as $parameter) {
                if ($parameter->getAttributes(\SensitiveParameter::class) !== []) {
                    continue;
                }

                $unmarked[] = self::named($parameter);
            }
        }

        self::assertSame([], $unmarked);
    }

    /**
     * The scan reads every class of the namespace once, each a real type.
     *
     * @return void
     */
    public function testTheScanReadsEveryClassOfTheNamespace(): void
    {
        $scanned = self::scanned();

        self::assertSame([], array_values(array_diff(self::MUST_READ, $scanned)));
        self::assertCount(count(array_unique($scanned)), $scanned);
        self::assertSame([], array_values(array_filter($scanned, static fn (string $class): bool => !class_exists($class) && !interface_exists($class) && !enum_exists($class))));
        self::assertGreaterThanOrEqual(count(self::MUST_READ), count($scanned));
    }

    /**
     * A fixture class is flagged exactly where it should be.
     *
     * @return void
     */
    public function testTheScanFindsEveryKind(): void
    {
        $source = <<<'PHP'
            <?php

            declare(strict_types = 1);

            namespace Tests\Unit\Lifecycle\Scanned;

            use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
            use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
            use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
            use SineMacula\Laravel\AuditLog\Records\AuditRecord;
            use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
            use SineMacula\Laravel\AuditLog\Records\PendingRecord;
            use SineMacula\Laravel\AuditLog\Records\Reference;

            final class EveryKind
            {
                public function kinds(
                    array $row,
                    array $rows,
                    AuditRecord $record,
                    array $records,
                    string $payload,
                    string $line,
                    array $lines,
                    string $envelope,
                    string $plaintext,
                    string $ciphertext,
                    string $members,
                    array $properties,
                    string $dataKey,
                    string $wrapped,
                    FinalisedRecord $finalised,
                    PendingRecord $built,
                    ?SubjectKeyRow $key,
                    HoldScope $scope,
                    ?HoldScope $narrowed,
                    ImportLine $parsed,
                    \Closure $work,
                    ?\Closure $then,
                    string $operationId,
                    string $code,
                    int $count,
                    string $digest,
                    int $sequence,
                    string $class,
                    ?Reference $tenant,
                    Reference ...$about,
                ): void {
                    $later = static fn (ImportLine $parsed, int $number): int => $number;
                }
            }
            PHP;

        $fixture = self::declared(self::FIXTURE, $source);

        $flagged = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), self::payloadParametersOf($fixture, false));

        self::assertSame(
            [
                'row', 'rows', 'record', 'records', 'payload', 'line', 'lines', 'envelope', 'plaintext', 'ciphertext', 'members', 'properties',
                'dataKey', 'wrapped', 'finalised', 'built', 'key', 'scope', 'narrowed', 'parsed', 'work', 'then',
            ],
            $flagged,
        );

        $asAScope = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), self::payloadParametersOf($fixture, false, $fixture));

        self::assertSame([...$flagged, 'tenant', 'about'], $asAScope);

        self::assertSame([['ImportLine $parsed', 'int $number']], self::closureParametersIn($source));
        self::assertSame(['parsed'], self::unmarkedIn(self::closureParametersIn($source)[0]));
    }

    /**
     * Every payload parameter of a closure, read from source, is marked.
     *
     * @return void
     */
    public function testEveryPayloadParameterOfAClosureIsMarkedSensitive(): void
    {
        $unmarked = [];
        $read     = [];

        foreach (self::sourceFiles() as $file) {
            $source = (string) file_get_contents(self::src() . $file);

            foreach (self::closureParametersIn($source) as $parameters) {
                $read[] = $file;

                array_push($unmarked, ...array_map(static fn (string $name): string => "{$file}:{$name}", self::unmarkedIn($parameters, $file === self::HOLD_SCOPE_FILE)));
            }
        }

        self::assertSame([], $unmarked);
        self::assertSame([], array_values(array_diff(self::MUST_READ_CLOSURES_OF, $read)));
    }

    /**
     * Rows of `[source, the closures' parameters]`: each closure form to read.
     *
     * @return iterable<string, array{0: string, 1: list<list<string>>}>
     */
    public static function provideClosures(): iterable
    {
        yield from [
            'a closure'                 => ['<?php $a = function (int $b) {};', [['int $b']]],
            'a static closure'          => ['<?php $a = static function (int $b) {};', [['int $b']]],
            'an arrow function'         => ['<?php $a = fn (int $b) => 1;', [['int $b']]],
            'a static arrow function'   => ['<?php $a = static fn (int $b) => 1;', [['int $b']]],
            'a default holding a comma' => ['<?php $a = fn (array $b = [1, 2], $c = 3) => 1;', [['array $b = [1, 2]', '$c = 3']]],
            'a marked parameter'        => ['<?php $a = fn (#[\SensitiveParameter] int $b, int $c) => 1;', [['#[\SensitiveParameter] int $b', 'int $c']]],
            'over several lines'        => ["<?php \$a = fn (\n    int \$b,\n    int \$c,\n) => 1;", [['int $b', 'int $c']]],
            'a closure inside a call'   => ['<?php run(static fn (int $b) => 1, static fn (int $c) => 2);', [['int $b'], ['int $c']]],
            'a commented parameter'     => ['<?php $a = fn (/* the row */ int $b) => 1;', [['int $b']]],
            'no parameter'              => ['<?php $a = fn () => 1;', []],
            'a named method'            => ['<?php class A { public function b(int $c) {} }', []],
        ];
    }

    /**
     * The source scan finds every closure's parameters and no method's.
     *
     * @param  string  $source
     * @param  list<list<string>>  $parameters
     * @return void
     */
    #[DataProvider('provideClosures')]
    public function testTheSourceScanReadsEveryClosure(string $source, array $parameters): void
    {
        self::assertSame($parameters, self::closureParametersIn($source));
    }

    /**
     * Rows of `[parameters, in the hold scope, flagged names]`.
     *
     * @return iterable<string, array{0: list<string>, 1: bool, 2: list<string>}>
     */
    public static function provideClosureVerdicts(): iterable
    {
        yield from [
            'a marked row'                => [['#[\SensitiveParameter] array $row'], false, []],
            'an unmarked row'             => [['array $row'], false, ['row']],
            'an unmarked line'            => [['string $line'], false, ['line']],
            'an unmarked parsed line'     => [['ImportLine $parsed'], false, ['parsed']],
            'an unmarked record'          => [['AuditRecord $kept'], false, ['kept']],
            'an unmarked finalised one'   => [['?FinalisedRecord $kept'], false, ['kept']],
            'an unmarked hold scope'      => [['HoldScope $scope'], false, ['scope']],
            'an unmarked key row'         => [['SubjectKeyRow $key'], false, ['key']],
            'an unmarked data key'        => [['string $dataKey'], false, ['dataKey']],
            'an unmarked wrapped key'     => [['?string $wrapped'], false, ['wrapped']],
            'a closure'                   => [['\Closure $work'], false, ['work']],
            'a payload by its name'       => [['string $payload'], false, ['payload']],
            'properties by their name'    => [['array $properties'], false, ['properties']],
            'a reference outside a scope' => [['Reference $tenant'], false, []],
            'a reference of a scope'      => [['Reference $tenant'], true, ['tenant']],
            'a marked scope reference'    => [['#[\SensitiveParameter] Reference $tenant'], true, []],
            'an id and a count'           => [['string $id', 'int $count'], true, []],
            'one of two marked'           => [['#[\SensitiveParameter] array $rows', 'string $members'], false, ['members']],
        ];
    }

    /**
     * The closure scan flags an unmarked payload by name or type.
     *
     * @param  list<string>  $parameters
     * @param  bool  $inHoldScope
     * @param  list<string>  $flagged
     * @return void
     */
    #[DataProvider('provideClosureVerdicts')]
    public function testTheClosureScanFlagsAnUnmarkedPayload(array $parameters, bool $inHoldScope, array $flagged): void
    {
        self::assertSame($flagged, self::unmarkedIn($parameters, $inHoldScope));
    }

    /**
     * An unmarked frame keeps the value a marked one hides.
     *
     * @return void
     */
    public function testAnUnmarkedFrameKeepsWhatAMarkedOneHides(): void
    {
        $unmarked = static fn (string $held): \RuntimeException => new \RuntimeException('Fixed.');
        $marked   = static fn (#[\SensitiveParameter] string $held): \RuntimeException => new \RuntimeException('Fixed.');

        self::assertSame('held', $unmarked('held')->getTrace()[0]['args'][0] ?? null);
        self::assertInstanceOf(\SensitiveParameterValue::class, $marked('held')->getTrace()[0]['args'][0] ?? null);
    }

    /**
     * The class of the name, declared from the source unless it already is.
     *
     * @param  string  $class
     * @param  string  $source
     * @return class-string
     */
    private static function declared(string $class, string $source): string
    {
        if (!class_exists($class, false)) {
            $file = (string) tempnam(sys_get_temp_dir(), 'scan');

            file_put_contents($file, $source);

            require $file;

            unlink($file);
        }

        if (!class_exists($class)) {
            self::fail("The source does not declare {$class}.");
        }

        return $class;
    }

    /**
     * The class's own payload parameters, skipping PHP and framework methods;
     * in the hold scope, every reference.
     *
     * @param  class-string  $class
     * @param  bool  $ownMethodsOnly
     * @param  string  $holdScope
     * @return list<\ReflectionParameter>
     */
    private static function payloadParametersOf(string $class, bool $ownMethodsOnly = true, string $holdScope = self::HOLD_SCOPE): array
    {
        $parameters = [];

        foreach ((new \ReflectionClass($class))->getMethods() as $method) {
            if ($ownMethodsOnly && !str_starts_with((string) $method->getFileName(), self::src())) {
                continue;
            }

            $holdsReferences = $method->getDeclaringClass()->getName() === $holdScope;

            array_push($parameters, ...array_values(array_filter(
                $method->getParameters(),
                static fn (\ReflectionParameter $parameter): bool => self::holdsAPayload($parameter) || ($holdsReferences && self::isTyped($parameter, [Reference::class])),
            )));
        }

        return $parameters;
    }

    /**
     * Whether the parameter holds a payload, by its name or by its type.
     *
     * @param  \ReflectionParameter  $parameter
     * @return bool
     */
    private static function holdsAPayload(\ReflectionParameter $parameter): bool
    {
        return in_array($parameter->getName(), self::PAYLOAD_NAMES, true) || self::isTyped($parameter, self::PAYLOAD_TYPES);
    }

    /**
     * Whether the parameter's type, or one of its union, is among those named.
     *
     * @param  \ReflectionParameter  $parameter
     * @param  list<string>  $names
     * @return bool
     */
    private static function isTyped(\ReflectionParameter $parameter, array $names): bool
    {
        $type  = $parameter->getType();
        $types = $type instanceof \ReflectionNamedType ? [$type] : ($type instanceof \ReflectionUnionType ? $type->getTypes() : []);

        foreach ($types as $member) {
            if ($member instanceof \ReflectionNamedType && in_array($member->getName(), $names, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The parameter, as `class::method.parameter`.
     *
     * @param  \ReflectionParameter  $parameter
     * @return string
     */
    private static function named(\ReflectionParameter $parameter): string
    {
        $method = $parameter->getDeclaringFunction();
        $class  = $parameter->getDeclaringClass();

        return ($class === null ? '' : $class->getName()) . '::' . $method->getName() . '.' . $parameter->getName();
    }

    /**
     * A closure's unmarked payload parameters, in the hold scope references.
     *
     * @param  list<string>  $parameters
     * @param  bool  $inHoldScope
     * @return list<string>
     */
    private static function unmarkedIn(array $parameters, bool $inHoldScope = false): array
    {
        $names = [];

        foreach ($parameters as $parameter) {
            if (str_contains($parameter, \SensitiveParameter::class) || preg_match('/\$(\w+)/', $parameter, $match) !== 1) {
                continue;
            }

            $held = in_array($match[1], self::PAYLOAD_NAMES, true)
                || preg_match(self::PAYLOAD_TYPE_IN_SOURCE, $parameter) === 1
                || ($inHoldScope && preg_match(self::REFERENCE_TYPE_IN_SOURCE, $parameter) === 1);

            if (!$held) {
                continue;
            }

            $names[] = $match[1];
        }

        return $names;
    }

    /**
     * Each closure's parameters: `function` or `fn` straight before a bracket.
     *
     * @param  string  $source
     * @return list<list<string>>
     */
    private static function closureParametersIn(string $source): array
    {
        $tokens     = self::significantTokens($source);
        $parameters = [];

        foreach ($tokens as $index => $token) {
            if (!is_array($token) || !in_array($token[0], [T_FUNCTION, T_FN], true)) {
                continue;
            }

            $open = self::nextAfter($tokens, $index);

            if (($tokens[$open] ?? null) !== '(') {
                continue;
            }

            $inside = self::argumentsAt($tokens, $open);

            if ($inside === []) {
                continue;
            }

            $parameters[] = $inside;
        }

        return $parameters;
    }

    /**
     * The index of the first token after the index that is not a space.
     *
     * @param  array<int, array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return int
     */
    private static function nextAfter(array $tokens, int $index): int
    {
        do {
            $index++;
        } while (($tokens[$index] ?? null) === ' ');

        return $index;
    }

    /**
     * The trimmed arguments of the bracket at the index, split at its commas.
     *
     * @param  array<int, array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $open
     * @return list<string>
     */
    private static function argumentsAt(array $tokens, int $open): array
    {
        $depth     = 1;
        $arguments = [''];
        $count     = count($tokens);

        for ($index = $open + 1; $index < $count; $index++) {
            $text = is_array($tokens[$index]) ? $tokens[$index][1] : $tokens[$index];

            $depth += self::depthChangeOf($text);

            if ($depth === 0) {
                break;
            }

            if ($depth === 1 && $text === ',') {
                $arguments[] = '';

                continue;
            }

            $arguments[array_key_last($arguments)] .= $text;
        }

        return array_values(array_filter(array_map(trim(...), $arguments), static fn (string $argument): bool => $argument !== ''));
    }

    /**
     * What the text does to how many brackets are open.
     *
     * @param  string  $text
     * @return int
     */
    private static function depthChangeOf(string $text): int
    {
        return match ($text) {
            '(', '[', '#[', '{' => 1,
            ')', ']', '}'       => -1,
            default             => 0,
        };
    }

    /**
     * The source's tokens without comments, each whitespace run one space.
     *
     * @param  string  $source
     * @return array<int, array{0: int, 1: string, 2: int}|string>
     */
    private static function significantTokens(string $source): array
    {
        $tokens = [];

        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $tokens[] = is_array($token) && $token[0] === T_WHITESPACE ? ' ' : $token;
        }

        return $tokens;
    }

    /**
     * Every class the rule holds, from the files under `src`.
     *
     * @return list<class-string>
     */
    private static function scanned(): array
    {
        /** @var list<class-string> */
        return array_map(static fn (string $file): string => self::NAMESPACE . str_replace('/', '\\', substr($file, 0, -strlen('.php'))), self::sourceFiles());
    }

    /**
     * Every file the rule holds, relative to `src`, in order.
     *
     * @return list<string>
     */
    private static function sourceFiles(): array
    {
        $files = self::FILES;

        foreach (self::FOLDERS as $folder) {
            array_push($files, ...self::filesUnder($folder));
        }

        sort($files);

        return $files;
    }

    /**
     * Every PHP file under the folder of `src`, relative to `src`.
     *
     * @param  string  $folder
     * @return list<string>
     */
    private static function filesUnder(string $folder): array
    {
        $files = [];

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::src() . $folder, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $files[] = substr($file->getPathname(), strlen(self::src()));
        }

        return $files;
    }

    /**
     * The path to `src`, with its trailing slash.
     *
     * @return string
     */
    private static function src(): string
    {
        return dirname(__DIR__, 3) . '/src/';
    }
}
