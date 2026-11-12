<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Querying\Viewer;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Holds `src/Querying`, `src/Access` and the policy contract to marking each
 * payload parameter `#[\SensitiveParameter]`, keeping it out of stack traces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class QueryingSensitiveParametersTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The namespace every source file is named under. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The folders under `src` the rule holds. */
    private const array FOLDERS = ['Querying', 'Access'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = ['Contracts/AuditAccessPolicy.php'];

    /** @var list<string> The names a parameter holding a payload goes by. */
    private const array PAYLOAD_NAMES = ['row', 'rows', 'envelope', 'payload', 'plaintext', 'ciphertext', 'members', 'viewer'];

    /** @var list<string> The types a payload parameter goes by, any authenticatable user included. */
    private const array PAYLOAD_TYPES = [
        \Closure::class,
        AuditRecord::class,
        FinalisedRecord::class,
        PendingRecord::class,
        Viewer::class,
        self::NAMESPACE . 'Querying\StoredEntry',
        self::NAMESPACE . 'Querying\TrailEntry',
    ];

    /** @var string Matches a closure payload parameter's type in source, where none resolves. */
    private const string PAYLOAD_TYPE_IN_SOURCE = '/\b(?:StoredEntry|TrailEntry|AuditRecord|FinalisedRecord|PendingRecord|Viewer|Closure|Authenticatable)\b/';

    /** @var list<class-string> The classes the scan must find a payload parameter in. */
    private const array MUST_HOLD_ONE = [AuditAccessPolicy::class, DenyAllPolicy::class, Viewer::class];

    /** @var list<string> The parameters the scan must find, as `class::method.parameter`. */
    private const array MUST_FIND = [
        AuditAccessPolicy::class . '::scope.viewer',
        DenyAllPolicy::class . '::scope.viewer',
        Viewer::class . '::of.viewer',
        Viewer::class . '::__construct.original',
    ];

    /** @var list<string> The files whose closures the source scan must read. */
    private const array MUST_READ_CLOSURES_OF = ['Access/AccessScope.php', 'Access/ScopeCompiler.php'];

    /** @var string The class a source is written for, to show what the scan flags. */
    private const string FIXTURE = 'Tests\Unit\Querying\Scanned\EveryKind';

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
     * Every method, private ones included, marks each payload parameter.
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
     * The scan finds each expected parameter and reads every class once.
     *
     * @return void
     */
    public function testTheScanFindsAParameterInEachClass(): void
    {
        $classes = [];
        $found   = [];

        foreach (self::scanned() as $class) {
            $parameters = array_map(self::named(...), self::payloadParametersOf($class));

            if ($parameters === []) {
                continue;
            }

            $classes[] = $class;

            array_push($found, ...$parameters);
        }

        self::assertSame([], array_values(array_diff(self::MUST_HOLD_ONE, $classes)));
        self::assertSame([], array_values(array_diff(self::MUST_FIND, $found)));
        self::assertContains(self::NAMESPACE . 'Access\Enums\ReadPurpose', self::scanned());
        self::assertContains(self::NAMESPACE . 'Querying\Enums\PackageActivity', self::scanned());
        self::assertContains(self::NAMESPACE . 'Access\ScopeCompiler', self::scanned());
        self::assertCount(count(array_unique(self::scanned())), self::scanned());
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

            namespace Tests\Unit\Querying\Scanned;

            use Illuminate\Contracts\Auth\Authenticatable;
            use SineMacula\Laravel\AuditLog\Querying\Position;
            use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
            use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
            use SineMacula\Laravel\AuditLog\Querying\Viewer;
            use SineMacula\Laravel\AuditLog\Records\AuditRecord;
            use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
            use SineMacula\Laravel\AuditLog\Records\PendingRecord;
            use SineMacula\Laravel\AuditLog\Records\Reference;

            final class EveryKind
            {
                public function kinds(
                    array $row,
                    array $rows,
                    string $envelope,
                    StoredEntry $stored,
                    TrailEntry $shown,
                    AuditRecord $audit,
                    FinalisedRecord $finalised,
                    PendingRecord $built,
                    string $plaintext,
                    string $ciphertext,
                    string $members,
                    Authenticatable|Reference $reader,
                    Authenticatable $user,
                    Viewer $who,
                    \Closure $work,
                    ?\Closure $then,
                    string $code,
                    string $fingerprint,
                    string $class,
                    string $id,
                    Reference $tenant,
                    Position $position,
                    string $cursor,
                ): void {
                    $later = static fn (StoredEntry $entry, int $count): int => $count;
                }
            }
            PHP;

        $fixture = self::declared(self::FIXTURE, $source);

        $flagged = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), self::payloadParametersOf($fixture, false));

        self::assertSame(
            ['row', 'rows', 'envelope', 'stored', 'shown', 'audit', 'finalised', 'built', 'plaintext', 'ciphertext', 'members', 'reader', 'user', 'who', 'work', 'then'],
            $flagged,
        );

        self::assertSame([['StoredEntry $entry', 'int $count']], self::closureParametersIn($source));
        self::assertSame(['entry'], self::unmarkedIn(self::closureParametersIn($source)[0]));
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

                array_push($unmarked, ...array_map(static fn (string $name): string => "{$file}:{$name}", self::unmarkedIn($parameters)));
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
     * Rows of `[a closure's parameters, the names the scan must flag]`.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideClosureVerdicts(): iterable
    {
        yield from [
            'a marked stored entry'      => [['#[\SensitiveParameter] StoredEntry $entry'], []],
            'an unmarked stored entry'   => [['StoredEntry $entry'], ['entry']],
            'an unmarked shown entry'    => [['?TrailEntry $shown'], ['shown']],
            'an unmarked record'         => [['FinalisedRecord $held'], ['held']],
            'an unmarked viewer union'   => [['Authenticatable|Reference $who'], ['who']],
            'an unmarked viewer'         => [['Viewer $reader'], ['reader']],
            'a closure'                  => [['\Closure $work'], ['work']],
            'a row by its name'          => [['array $row'], ['row']],
            'a plaintext by its name'    => [['string $plaintext'], ['plaintext']],
            'a reference and a position' => [['Reference $tenant', 'Position $position'], []],
            'an id and a cursor'         => [['string $id', 'string $cursor'], []],
            'one of two marked'          => [['#[\SensitiveParameter] array $rows', 'string $members'], ['members']],
        ];
    }

    /**
     * The closure scan flags an unmarked payload by name or type.
     *
     * @param  list<string>  $parameters
     * @param  list<string>  $flagged
     * @return void
     */
    #[DataProvider('provideClosureVerdicts')]
    public function testTheClosureScanFlagsAnUnmarkedPayload(array $parameters, array $flagged): void
    {
        self::assertSame($flagged, self::unmarkedIn($parameters));
    }

    /**
     * A viewer's own frame hides it behind PHP's sensitive placeholder.
     *
     * @return void
     */
    public function testAStackFrameOfAViewerHidesTheViewer(): void
    {
        $user = \Mockery::mock(Authenticatable::class);

        $user->shouldReceive('getAuthIdentifier')->once()->andReturnUsing(static function (): never {
            throw new \RuntimeException('Fixed.');
        });

        try {
            Viewer::of($user);

            self::fail('Expected the viewer to throw.');
        } catch (\RuntimeException $thrown) {
            $frames = array_values(array_filter($thrown->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === Viewer::class));

            self::assertSame(['of'], array_column($frames, 'function'));
            self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0] ?? null);
            self::assertStringContainsString(Viewer::class . '::of(Object(SensitiveParameterValue))', $thrown->getTraceAsString());
        }
    }

    /**
     * An unmarked frame of the same call keeps the value a marked one hides.
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
     * The class's own payload parameters, skipping PHP and framework methods.
     *
     * @param  class-string  $class
     * @param  bool  $ownMethodsOnly
     * @return list<\ReflectionParameter>
     */
    private static function payloadParametersOf(string $class, bool $ownMethodsOnly = true): array
    {
        $parameters = [];

        foreach ((new \ReflectionClass($class))->getMethods() as $method) {
            if ($ownMethodsOnly && !str_starts_with((string) $method->getFileName(), self::src())) {
                continue;
            }

            array_push($parameters, ...array_filter($method->getParameters(), self::holdsAPayload(...)));
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
        if (in_array($parameter->getName(), self::PAYLOAD_NAMES, true)) {
            return true;
        }

        $type  = $parameter->getType();
        $types = $type instanceof \ReflectionNamedType ? [$type] : ($type instanceof \ReflectionUnionType ? $type->getTypes() : []);

        foreach ($types as $member) {
            $name = $member instanceof \ReflectionNamedType ? $member->getName() : '';

            if (in_array($name, self::PAYLOAD_TYPES, true) || is_a($name, Authenticatable::class, true)) {
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
     * A closure's unmarked payload parameters, by name or type.
     *
     * @param  list<string>  $parameters
     * @return list<string>
     */
    private static function unmarkedIn(array $parameters): array
    {
        $names = [];

        foreach ($parameters as $parameter) {
            if (str_contains($parameter, \SensitiveParameter::class) || preg_match('/\$(\w+)/', $parameter, $match) !== 1) {
                continue;
            }

            if (!in_array($match[1], self::PAYLOAD_NAMES, true) && preg_match(self::PAYLOAD_TYPE_IN_SOURCE, $parameter) !== 1) {
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
