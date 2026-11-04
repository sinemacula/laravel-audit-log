<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Holds the lifecycle to the rule that keeps what it handles out of a stack
 * trace: with `zend.exception_ignore_args` off every frame keeps its arguments,
 * so a parameter that holds a row, a record, a payload, a line of an import
 * file, a record's properties, a hold scope or one of its references, or a
 * closure is marked `#[\SensitiveParameter]` on every method it passes through,
 * and a closure's own parameters too, which reflection of a class cannot reach
 * and so are read from the source. Ids, codes, counts, digests, sequences,
 * class names and a decision's tenant are not payload.
 *
 * Every class under `src/Lifecycle` is held, whatever it holds when the test
 * runs, and the retention policy contract beside them. The scan must read each
 * class of the namespace, so it cannot pass by reading nothing, and a class
 * written for the test with a parameter of each kind shows it flags exactly
 * what it should.
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

    /** @var list<string> The folders under `src` the rule holds, whatever is added to them. */
    private const array FOLDERS = ['Lifecycle'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = ['Contracts/RetentionPolicy.php'];

    /** @var list<string> The names a parameter holding a payload goes by. */
    private const array PAYLOAD_NAMES = ['row', 'rows', 'record', 'records', 'payload', 'line', 'lines', 'envelope', 'plaintext', 'ciphertext', 'members', 'properties'];

    /** @var list<string> The types a parameter holding a payload goes by: a closure, a record, a hold scope and a parsed import line. */
    private const array PAYLOAD_TYPES = [
        \Closure::class,
        AuditRecord::class,
        FinalisedRecord::class,
        PendingRecord::class,
        self::HOLD_SCOPE,
        self::NAMESPACE . 'Lifecycle\ImportLine',
    ];

    /** @var string The hold scope, whose every reference parameter holds one of the scope's references. */
    private const string HOLD_SCOPE = self::NAMESPACE . 'Lifecycle\HoldScope';

    /** @var string The hold scope's file, relative to `src`, whose closures' references are payload too. */
    private const string HOLD_SCOPE_FILE = 'Lifecycle/HoldScope.php';

    /** @var string What a closure's parameter holding a payload is typed as, read from the source, where no type can be resolved. */
    private const string PAYLOAD_TYPE_IN_SOURCE = '/\b(?:AuditRecord|FinalisedRecord|PendingRecord|HoldScope|ImportLine|Closure)\b/';

    /** @var string What a closure's parameter holding a reference is typed as, read from the source. */
    private const string REFERENCE_TYPE_IN_SOURCE = '/\bReference\b/';

    /** @var list<class-string> The classes the scan must read, from those this suite already holds. */
    private const array MUST_READ = [RetentionPolicy::class, RetentionDecisions::class, RetentionSettings::class, ImportStatus::class];

    /** @var list<string> The files whose closures the source scan must read. */
    private const array MUST_READ_CLOSURES_OF = ['Lifecycle/RetentionSettings.php'];

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
     * Every method of every class the rule holds, private ones included, marks
     * a parameter that goes by a payload's name or type, and the hold scope
     * marks every reference it takes.
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
     * The scan reads every class of the folders the rule holds, the enums
     * included, and the contract beside them, each once, and every file it
     * reads names a class, an interface or an enum that exists.
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
     * A class written with a parameter of each kind, and of each kind that is
     * not payload, is flagged by name or by type exactly where it should be, a
     * reference only in a hold scope, and a closure in it is read from its
     * source: protects against a scan that passes by flagging nothing, or by
     * flagging everything.
     *
     * @return void
     */
    public function testTheScanFindsEveryKind(): void
    {
        $source = <<<'PHP'
            <?php

            declare(strict_types = 1);

            namespace Tests\Unit\Lifecycle\Scanned;

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
                    FinalisedRecord $finalised,
                    PendingRecord $built,
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

        if (!class_exists(self::FIXTURE, false)) {
            $file = (string) tempnam(sys_get_temp_dir(), 'scan');

            file_put_contents($file, $source);

            require $file;

            unlink($file);
        }

        $fixture = self::FIXTURE;

        self::assertTrue(class_exists($fixture));

        $flagged = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), self::payloadParametersOf($fixture, false));

        self::assertSame(
            [
                'row', 'rows', 'record', 'records', 'payload', 'line', 'lines', 'envelope', 'plaintext', 'ciphertext', 'members', 'properties',
                'finalised', 'built', 'scope', 'narrowed', 'parsed', 'work', 'then',
            ],
            $flagged,
        );

        $asAScope = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), self::payloadParametersOf($fixture, false, $fixture));

        self::assertSame([...$flagged, 'tenant', 'about'], $asAScope);

        self::assertSame([['ImportLine $parsed', 'int $number']], self::closureParametersIn($source));
        self::assertSame(['parsed'], self::unmarkedIn(self::closureParametersIn($source)[0]));
    }

    /**
     * A closure's parameters are out of a scan of methods, so they are read
     * from the source: every one that goes by a payload's name or type is
     * marked, a reference too in the hold scope, and the files whose closures
     * the scan must read have some.
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
     * Rows of `[source, the closures' parameters]`: each form of closure the
     * source scan must read, and what it must leave alone.
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
     * The source scan finds the parameters of every form of closure and of no
     * method, which reflection reads already.
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
     * Rows of `[a closure's parameters, whether it is the hold scope's, the
     * names the scan must flag]`: a payload is flagged by its name or its type
     * unless it is marked, a reference only in the hold scope, and anything
     * else is left alone.
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
     * The closure scan flags a payload that is unmarked, by its name or its
     * type, and reads each parameter's marking apart.
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
     * What the marking hides is really in the frame's reach: an unmarked frame
     * keeps the value a marked one replaces, so the rule has something to hide.
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
     * The parameters of the class's own methods that hold a payload; none for a
     * method PHP or a framework trait declares, since neither can be marked,
     * unless the class is not the package's own. In the class that holds a hold
     * scope's references, every reference parameter is one.
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
     * Whether the parameter's type, or a member of its union, is one of the
     * types named.
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
     * The names of a closure's parameters that hold a payload and are not
     * marked, by their name or their type, and in the hold scope a reference.
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
     * The parameters of each closure in the source that takes any, in order,
     * read from its tokens: a `function` or `fn` followed straight by a
     * bracket, which a named method never is.
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
     * The arguments of the bracket that opens at the index, split at its
     * top-level commas, each as its text with its spaces trimmed; a trailing
     * comma adds none.
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
     * The source's tokens with its comments gone and each run of whitespace one
     * space, so a list of parameters over many lines reads as one over one.
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
