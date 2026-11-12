<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\ReplayCommand;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Delivery\FailedWrite;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxClaim;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Delivery\SpillLine;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Holds the write path's parameters that carry a payload or a failure to
 * `#[\SensitiveParameter]`, since a frame keeps its arguments when
 * `zend.exception_ignore_args` is off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DeliverySensitiveParametersTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The namespace every source file is named under. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The folders under `src` the rule holds, whatever is added to them. */
    private const array FOLDERS = ['Delivery', 'Stores', 'Export'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = [
        'Records/EnvelopeCodec.php',
        'Console/ReplayCommand.php',
        'Runtime/WriteGuard.php',
        'Database/AfterCommit.php',
        'Database/FailureClassifier.php',
    ];

    /** @var list<string> The one file that reads a failure's chain, to classify it and to mask it. */
    private const array READS_TO_CLASSIFY = ['Database/FailureClassifier.php'];

    /** @var list<string> The names a parameter holding a payload goes by, the token's among them. */
    private const array PAYLOAD_NAMES = ['record', 'finalised', 'failure', 'exception', 'payload', 'json', 'line', 'envelope', 'row', 'fields', 'event', 'value', 'token'];

    /** @var list<class-string> The types a parameter holding a payload goes by, a capture's signal among them since it holds the capture's closure; any class of exception is one too. */
    private const array PAYLOAD_TYPES = [AuditRecord::class, FinalisedRecord::class, FailedWrite::class, CaptureSignal::class, \Closure::class];

    /** @var string What a closure's parameter holding a payload is typed as, read from the source, where no type can be resolved. */
    private const string PAYLOAD_TYPE_IN_SOURCE = '/\b(?:AuditRecord|FinalisedRecord|FailedWrite|CaptureSignal|Closure|Throwable|\w*Exception)\b/';

    /** @var array<string, string> The parameters that go by a payload's name and hold only one fixed case of an enum, as `class::method.parameter`, each with that enum. */
    private const array FIXED_CASES = [
        ReplayResult::class . '::addSkipped.failure' => 'SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure',
        SpillLine::class . '::__construct.failure'   => 'SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure',
    ];

    /** @var array<string, string> The closures that go by a payload's name or type yet call nothing and cannot throw, so no frame ever holds them, as `file:parameter`, each with its whole list of parameters. */
    private const array CLOSURES_THAT_NEVER_FRAME = [
        'Delivery/FailureHandler.php:secondary' => '?\RuntimeException $secondary',
        'Export/OcsfFormatter.php:value'        => 'array|int|string|null $value',
    ];

    /** @var list<class-string> The classes the scan must find a payload parameter in. */
    private const array MUST_HOLD_ONE = [
        AfterCommit::class,
        CaptureSignal::class,
        CefFormatter::class,
        DatabaseAuditStore::class,
        DeliveryCoordinator::class,
        EnvelopeCodec::class,
        FailedWrite::class,
        FailureClassifier::class,
        FailureHandler::class,
        FailureSpill::class,
        LogAuditStore::class,
        NdjsonFormatter::class,
        NullAuditStore::class,
        OcsfFormatter::class,
        Outbox::class,
        OutboxClaim::class,
        OutboxDrainer::class,
        OutboxWriter::class,
        RecordDelivery::class,
        RecordedNotifier::class,
        ReplayCommand::class,
        Replayer::class,
        RowCodec::class,
        SpillLine::class,
        SpillReader::class,
        StackAuditStore::class,
        WriteDiagnostics::class,
        WriteGuard::class,
    ];

    /** @var array<class-string, int> Each delivery exception, with the most arguments its constructor may be given before the next would be a previous exception. */
    private const array UNCHAINED = [
        AuditWriteFailedException::class => 1,
        StackDeliveryException::class    => 6,
        DeadlockException::class         => 2,
    ];

    /** @var string What a read of a failure's text looks like: only a refusal of an argument may say its message, and neither the SQL nor the driver's message is ever read. */
    private const string FAILURE_TEXT = '/->(?:getSql|getBindings|getPrevious|getTraceAsString)\(\)|->getRawSql\(\)|errorInfo\[2\]|\bdebug_backtrace\(/';

    /** @var list<string> The files that say a caught exception's message, each only of a refusal of an argument, which names a path or a setting. */
    private const array SAYS_A_REFUSALS_MESSAGE = ['Console/ReplayCommand.php'];

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
     * Every method of every held class marks a parameter that goes by a
     * payload's name or type, bar the listed enums.
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

        self::assertSame([], array_values(array_diff($unmarked, array_keys(self::FIXED_CASES))));
    }

    /**
     * The scan finds a payload parameter in each class that must hold one, and
     * reads every class of the held folders.
     *
     * @return void
     */
    public function testTheScanFindsAParameterInEachClass(): void
    {
        $found = [];

        foreach (self::scanned() as $class) {
            if (self::payloadParametersOf($class) === []) {
                continue;
            }

            $found[] = $class;
        }

        self::assertSame([], array_values(array_diff(self::MUST_HOLD_ONE, $found)));
        self::assertContains(self::NAMESPACE . 'Delivery\Enums\FailureRule', self::scanned());
        self::assertContains(self::NAMESPACE . 'Stores\Enums\FailedOperation', self::scanned());
        self::assertCount(count(array_unique(self::scanned())), self::scanned());
    }

    /**
     * Rows of `[parameter, what the scan must say of it]`: each way a parameter
     * can be one the rule holds, and each way it can be free of it.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideScanVerdicts(): iterable
    {
        yield from [
            'a record by its type'          => ['typedRecord', true],
            'a finalised record'            => ['typedFinalised', true],
            'a failed write'                => ['typedFailedWrite', true],
            'a throwable'                   => ['typedThrowable', true],
            'a class of exception'          => ['typedException', true],
            'a nullable class of exception' => ['nullableException', true],
            'one of a union of exceptions'  => ['unionOfExceptions', true],
            'a closure'                     => ['typedClosure', true],
            'a capture\'s signal'           => ['typedSignal', true],
            'a string named `json`'         => ['json', true],
            'a string named `token`'        => ['token', true],
            'an array named `row`'          => ['row', true],
            'a mixed `value`'               => ['value', true],
            'an id'                         => ['id', false],
            'an untyped `other`'            => ['other', false],
        ];
    }

    /**
     * The scan flags a parameter by its name or type, and nothing else.
     *
     * @param  string  $parameter
     * @param  bool  $held
     * @return void
     */
    #[DataProvider('provideScanVerdicts')]
    public function testTheScanReadsANameOrAType(string $parameter, bool $held): void
    {
        $fixture = new class {
            /**
             * Parameters of every kind for the scan to read.
             *
             * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $typedRecord
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $typedFinalised
             * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $typedFailedWrite
             * @param  \Throwable  $typedThrowable
             * @param  \RuntimeException  $typedException
             * @param  ?\RuntimeException  $nullableException
             * @param  \LogicException|\RuntimeException  $unionOfExceptions
             * @param  \Closure(): void  $typedClosure
             * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $typedSignal
             * @param  string  $json
             * @param  string  $token
             * @param  array<string, string>  $row
             * @param  mixed  $value
             * @param  string  $id
             * @param  string  $other
             * @return void
             */
            public function everyKind(
                #[\SensitiveParameter]
                AuditRecord $typedRecord,
                #[\SensitiveParameter]
                FinalisedRecord $typedFinalised,
                #[\SensitiveParameter]
                FailedWrite $typedFailedWrite,
                #[\SensitiveParameter]
                \Throwable $typedThrowable,
                #[\SensitiveParameter]
                \RuntimeException $typedException,
                #[\SensitiveParameter]
                ?\RuntimeException $nullableException,
                #[\SensitiveParameter]
                \LogicException|\RuntimeException $unionOfExceptions,
                #[\SensitiveParameter]
                \Closure $typedClosure,
                #[\SensitiveParameter]
                ?CaptureSignal $typedSignal,
                #[\SensitiveParameter]
                string $json,
                #[\SensitiveParameter]
                string $token,
                #[\SensitiveParameter]
                array $row,
                #[\SensitiveParameter]
                mixed $value,
                string $id,
                string $other,
            ): void {}
        };

        $reflected = new \ReflectionParameter([$fixture, 'everyKind'], $parameter);

        self::assertSame($held, self::holdsAPayload($reflected));
    }

    /**
     * Each exemption names a payload-named parameter typed by its enum, so a
     * rename or a retype fails.
     *
     * @return void
     */
    public function testEveryExemptionHoldsAFixedCase(): void
    {
        foreach (self::FIXED_CASES as $exemption => $enum) {
            [$class, $member]     = explode('::', $exemption);
            [$method, $parameter] = explode('.', $member);

            /** @var class-string $class */
            $reflected = new \ReflectionParameter([$class, $method], $parameter);
            $type      = $reflected->getType();

            self::assertContains($parameter, self::PAYLOAD_NAMES, $exemption);
            self::assertInstanceOf(\ReflectionNamedType::class, $type, $exemption);
            self::assertSame($enum, $type->getName(), $exemption);
            self::assertTrue(enum_exists($enum), $exemption);
        }
    }

    /**
     * Every closure parameter that goes by a payload's name or type is marked,
     * bar closures that cannot throw.
     *
     * @return void
     */
    public function testEveryPayloadParameterOfAClosureIsMarkedSensitive(): void
    {
        $unmarked = [];

        foreach (self::sourceFiles() as $file) {
            $source = (string) file_get_contents(self::src() . $file);

            foreach (self::closureParametersIn($source) as $parameters) {
                array_push($unmarked, ...array_map(static fn (string $name): string => "{$file}:{$name}", self::unmarkedIn($parameters)));
            }
        }

        self::assertSame(array_keys(self::CLOSURES_THAT_NEVER_FRAME), $unmarked);
    }

    /**
     * Each exempt closure is still there with its parameters and only compares
     * with `null`, so it calls nothing.
     *
     * @return void
     */
    public function testEveryClosureLetGoComparesWithNull(): void
    {
        foreach (self::CLOSURES_THAT_NEVER_FRAME as $exempt => $parameters) {
            [$file, $name] = explode(':', $exempt);

            $source = (string) file_get_contents(self::src() . $file);

            self::assertStringContainsString("static fn ({$parameters}): bool => \${$name} !== null", $source, $exempt);
        }
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
     * Rows of `[a closure's parameters, the names the scan must flag]`.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideClosureVerdicts(): iterable
    {
        yield from [
            'a marked record'     => [['#[\SensitiveParameter] FinalisedRecord $record'], []],
            'an unmarked record'  => [['FinalisedRecord $record'], ['record']],
            'an unmarked type'    => [['AuditRecord $held'], ['held']],
            'a failure'           => [['?\RuntimeException $thing'], ['thing']],
            'a marked failure'    => [['#[\SensitiveParameter] \Throwable $thing'], []],
            'a closure'           => [['\Closure $work'], ['work']],
            'a capture\'s signal' => [['?CaptureSignal $capture'], ['capture']],
            'a value and an id'   => [['string $id', 'mixed $value'], ['value']],
            'neither'             => [['Connection $nested', 'string $id'], []],
            'two payloads marked' => [['#[\SensitiveParameter] array $row', '#[\SensitiveParameter] string $json'], []],
            'one of two marked'   => [['#[\SensitiveParameter] array $row', 'string $json'], ['json']],
        ];
    }

    /**
     * The closure scan flags a payload that is unmarked, by its name or its
     * type, and reads each parameter's marking apart.
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
     * A real failed write's exception shows nothing of the record or the
     * failure in any frame that held them.
     *
     * @return void
     */
    public function testAStackFrameOfAWriteHidesThePayload(): void
    {
        $thrown = self::thrownByAFailedWrite();

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);

        $frames = array_values(array_filter($thrown->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === FailureHandler::class));

        self::assertSame(['exceptionOf', 'handle'], array_column($frames, 'function'));

        [$building, $handling] = array_map(static fn (array $frame): array => $frame['args'] ?? [], $frames);

        self::assertInstanceOf(\SensitiveParameterValue::class, $building[0]);
        self::assertSame(FailedOperation::STORE, $building[1]);
        self::assertInstanceOf(\SensitiveParameterValue::class, $building[2]);
        self::assertInstanceOf(\SensitiveParameterValue::class, $handling[0]);
        self::assertSame(FailureRule::THROW, $handling[1]);

        self::assertStringContainsString('Object(SensitiveParameterValue)', $thrown->getTraceAsString());
        self::assertHoldsNoSecret($thrown->getTrace(), 'the frames');
        self::assertHoldsNoSecret($thrown, 'the exception');
    }

    /**
     * An unmarked frame of the same call keeps the secret, so the test above
     * has something to hide.
     *
     * @return void
     */
    public function testAnUnmarkedFrameKeepsWhatAMarkedOneHides(): void
    {
        $unmarked = static fn (string $held): \RuntimeException => new \RuntimeException('Fixed.');
        $marked   = static fn (#[\SensitiveParameter] string $held): \RuntimeException => new \RuntimeException('Fixed.');

        self::assertSame(self::SECRET, $unmarked(self::SECRET)->getTrace()[0]['args'][0] ?? null);
        self::assertInstanceOf(\SensitiveParameterValue::class, $marked(self::SECRET)->getTrace()[0]['args'][0] ?? null);
    }

    /**
     * A synchronous capture's fatal failure is thrown through the failure
     * handler, whose frame hides the capture's signal.
     *
     * @return void
     */
    public function testAStackFrameOfACapturesFatalFailureHidesItsSignal(): void
    {
        $container = new Container;

        $container->instance(WriteGuard::class, new WriteGuard);
        $container->instance(DispatcherContract::class, new Dispatcher($container));

        $told   = [];
        $held   = self::SECRET;
        $signal = new CaptureSignal(static function (string $exceptionClass) use (&$told, $held): void {
            $told[$exceptionClass] = $held;
        });
        $driver  = new \PDOException('Deadlock found when trying to get lock ' . self::SECRET);
        $failure = new QueryException('testing', 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], $driver);
        $record  = RecordFactory::captured(['note' => self::SECRET]);
        $failed  = new FailedWrite($record, null, $failure, FailedOperation::STORE, DatabaseAuditStore::class, 'testing', true, ['testing']);
        $thrown  = null;

        self::assertTrue(self::holdsText($signal, self::SECRET));

        try {
            (new FailureHandler($container))->handle($failed, FailureRule::REPORT, null, $signal);
        } catch (DeadlockException $caught) {
            $thrown = $caught;
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertTrue($signal->isFatal());
        self::assertSame([QueryException::class => self::SECRET], $told);

        $handles = static fn (array $frame): bool => $frame['function'] === 'handle' && ($frame['class'] ?? null) === FailureHandler::class;
        $frames  = array_values(array_filter($thrown->getTrace(), $handles));

        self::assertCount(1, $frames);
        self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][3] ?? null);
        self::assertHoldsNoSecret($thrown->getTrace(), 'the frames');
    }

    /**
     * No `new` of a delivery exception, nor its parent constructor call, passes
     * a previous exception, and each is found.
     *
     * @return void
     */
    public function testNothingChainsADeliveryException(): void
    {
        $sources = self::everySource();

        foreach (self::UNCHAINED as $class => $most) {
            $short = substr((string) strrchr($class, '\\'), 1);
            $found = 0;

            foreach ($sources as $file => $source) {
                foreach (self::argumentsOfEachNew($source, $short) as $arguments) {
                    $found++;

                    self::assertLessThanOrEqual($most, count($arguments), "{$file} gives {$short} a previous exception.");
                    self::assertSame([], preg_grep('/^\s*previous\s*:/', $arguments), "{$file} gives {$short} a previous exception.");
                }
            }

            self::assertGreaterThan(0, $found, "No file makes a {$short}.");
        }

        foreach ([AuditWriteFailedException::class, StackDeliveryException::class] as $class) {
            $source     = (string) file_get_contents((string) (new \ReflectionClass($class))->getFileName());
            $parameters = (new \ReflectionMethod($class, '__construct'))->getParameters();

            self::assertSame([1], array_map(count(...), self::argumentsOfEachParentConstructor($source)), $class);
            self::assertNotContains('previous', array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters), $class);
        }
    }

    /**
     * Rows of `[source, the arguments of each new of Target]`: each form the
     * source scan must read, so a previous exception cannot slip past it.
     *
     * @return iterable<string, array{0: string, 1: list<list<string>>}>
     */
    public static function provideNews(): iterable
    {
        yield from [
            'no parentheses'        => ['<?php new Target;', [[]]],
            'no arguments'          => ['<?php new Target();', [[]]],
            'one argument'          => ['<?php new Target($a);', [['$a']]],
            'a comma inside a call' => ['<?php new Target(f($a, $b), $c);', [['f($a, $b)', '$c']]],
            'a comma inside a list' => ['<?php new Target([$a, $b]);', [['[$a, $b]']]],
            'a comma in a string'   => ['<?php new Target("a, b");', [['"a, b"']]],
            'a trailing comma'      => ['<?php new Target($a,);', [['$a']]],
            'a named previous'      => ['<?php new Target($a, previous: $b);', [['$a', 'previous: $b']]],
            'a qualified name'      => ['<?php new \Space\Target($a);', [['$a']]],
            'two of them'           => ['<?php new Target($a); new Target($b, $c);', [['$a'], ['$b', '$c']]],
            'another class'         => ['<?php new Targets($a); new Other($b);', []],
        ];
    }

    /**
     * The source scan reads each `new` of the class, whichever way it is named,
     * and counts its arguments by the top-level commas alone.
     *
     * @param  string  $source
     * @param  list<list<string>>  $news
     * @return void
     */
    #[DataProvider('provideNews')]
    public function testTheSourceScanCountsEachNewsArguments(string $source, array $news): void
    {
        self::assertSame($news, self::argumentsOfEachNew($source, 'Target'));
    }

    /**
     * Only the classifier reads a failure's SQL, bindings, previous exception
     * or driver message; only the replay command says a caught message.
     *
     * @return void
     */
    public function testNothingReadsAFailuresText(): void
    {
        foreach (self::sourceFiles() as $file) {
            $source = self::withoutComments((string) file_get_contents(self::src() . $file));

            self::assertSame(in_array($file, self::READS_TO_CLASSIFY, true) ? 1 : 0, preg_match(self::FAILURE_TEXT, $source), "{$file} reads a failure's text.");

            if (in_array($file, self::SAYS_A_REFUSALS_MESSAGE, true)) {
                self::assertSame(1, substr_count($source, '->getMessage()'), $file);
                self::assertMatchesRegularExpression('/catch \(\\\InvalidArgumentException \$exception\) \{\s*\$this->error\(\$exception->getMessage\(\)\);/', $source);

                continue;
            }

            self::assertStringNotContainsString('->getMessage()', $source, "{$file} reads a failure's message.");
        }
    }

    /**
     * What a failed write of a record holding the secret throws, with the
     * failure holding it too.
     *
     * @return \RuntimeException
     */
    private static function thrownByAFailedWrite(): \RuntimeException
    {
        $container = new Container;

        $container->instance(WriteGuard::class, new WriteGuard);
        $container->instance(DispatcherContract::class, new Dispatcher($container));

        $previous = new \PDOException('Duplicate entry ' . self::SECRET);

        $previous->errorInfo = ['23000', 1062, 'Duplicate entry ' . self::SECRET];

        $failure = new QueryException('testing', 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], $previous);
        $record  = RecordFactory::captured(['note' => self::SECRET]);
        $failed  = new FailedWrite($record, null, $failure, FailedOperation::STORE, DatabaseAuditStore::class, 'testing', false);

        self::assertTrue(self::holdsText($record, self::SECRET));

        try {
            (new FailureHandler($container))->handle($failed, FailureRule::THROW);
        } catch (\RuntimeException $thrown) {
            return $thrown;
        }

        self::fail('Expected the failed write to throw.');
    }

    /**
     * The parameters of the class's own methods that hold a payload; none for a
     * method PHP or a framework trait declares, since neither can be marked.
     *
     * @param  class-string  $class
     * @return list<\ReflectionParameter>
     */
    private static function payloadParametersOf(string $class): array
    {
        $parameters = [];

        foreach ((new \ReflectionClass($class))->getMethods() as $method) {
            if (!str_starts_with((string) $method->getFileName(), self::src())) {
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

            if (in_array($name, self::PAYLOAD_TYPES, true) || is_a($name, \Throwable::class, true)) {
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
     * marked.
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
     * The parameters of each closure in the source, in order, read from its
     * tokens.
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
     * The arguments of each `new` of the class in the source, in order, each as
     * its text.
     *
     * @param  string  $source
     * @param  string  $short
     * @return list<list<string>>
     */
    private static function argumentsOfEachNew(string $source, string $short): array
    {
        $tokens = self::significantTokens($source);
        $news   = [];

        foreach ($tokens as $index => $token) {
            if (!is_array($token) || $token[0] !== T_NEW) {
                continue;
            }

            $named = self::nextAfter($tokens, $index);
            $name  = $tokens[$named] ?? null;

            if (!is_array($name) || substr((string) strrchr('\\' . $name[1], '\\'), 1) !== $short) {
                continue;
            }

            $open = self::nextAfter($tokens, $named);

            $news[] = ($tokens[$open] ?? null) === '(' ? self::argumentsAt($tokens, $open) : [];
        }

        return $news;
    }

    /**
     * The arguments of each call of the parent's constructor in the source, in
     * order, each as its text.
     *
     * @param  string  $source
     * @return list<list<string>>
     */
    private static function argumentsOfEachParentConstructor(string $source): array
    {
        $tokens = self::significantTokens($source);
        $calls  = [];

        foreach ($tokens as $index => $token) {
            if (!is_array($token) || $token[1] !== '__construct' || !is_array($tokens[$index - 2] ?? null) || $tokens[$index - 2][1] !== 'parent') {
                continue;
            }

            $calls[] = self::argumentsAt($tokens, self::nextAfter($tokens, $index));
        }

        return $calls;
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
     * The top-level arguments of the bracket that opens at the index, trimmed.
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
     * The source with its comments removed, so a docblock that says what a
     * class never reads is not read as reading it.
     *
     * @param  string  $source
     * @return string
     */
    private static function withoutComments(string $source): string
    {
        $kept = '';

        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $kept .= is_array($token) ? $token[1] : $token;
        }

        return $kept;
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
     * Every file of the package, relative to `src`, with its source.
     *
     * @return array<string, string>
     */
    private static function everySource(): array
    {
        $sources = [];

        foreach (self::filesUnder('') as $file) {
            $sources[$file] = (string) file_get_contents(self::src() . $file);
        }

        return $sources;
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
