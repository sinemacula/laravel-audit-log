<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\GateArguments;
use SineMacula\Laravel\AuditLog\Capture\ModelChangeDescriber;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use Tests\Concerns\SearchesForSecrets;

/**
 * Holds the capture layer, the listeners and the record pipeline to the rule
 * that keeps what a capture reads out of a stack trace: with
 * `zend.exception_ignore_args` off every frame keeps its arguments, so a
 * parameter that holds an event, a model, a user, a record or a payload, a
 * failure, or a closure capturing any of them is marked
 * `#[\SensitiveParameter]` on every method it passes through, and a closure's
 * own parameters too, which reflection of a class cannot reach and so are read
 * from the source.
 *
 * Each scan must find what it expects, so it cannot pass by finding nothing,
 * and is shown to flag what it should. Real throws through a user's reference
 * and a mapping window then show what the marking leaves in a frame.
 *
 * The listeners that carry context into jobs and track command and job frames
 * read the framework's own lifecycle events for an id or a frame, never for
 * anything a capture records; their parameters are listed apart, each pinned to
 * its type and to being unmarked, so marking one shrinks the list and any other
 * listener is held to the rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class CaptureSensitiveParametersTest extends TestCase
{
    use MockeryPHPUnitIntegration, SearchesForSecrets;

    /** @var string The namespace every source file is named under. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The folders under `src` the rule holds, whatever is added to them. */
    private const array FOLDERS = ['Capture', 'Listeners'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = ['RecordPipeline.php'];

    /** @var list<string> The names a parameter holding a payload goes by, a single Gate argument and a model's raw attributes among them. */
    private const array PAYLOAD_NAMES = [
        'event',
        'model',
        'record',
        'pending',
        'payload',
        'arguments',
        'argument',
        'attributes',
        'result',
        'failure',
        'exception',
        'user',
        'credentials',
    ];

    /** @var list<class-string> The types a parameter holding a payload goes by, a capture's signal among them since it holds the capture's closure; any model, authenticatable user or throwable is one too. */
    private const array PAYLOAD_TYPES = [\Closure::class, PendingRecord::class, AuditRecord::class, CaptureSignal::class];

    /** @var list<class-string> The types whose every subtype holds a payload. */
    private const array PAYLOAD_PARENTS = [Model::class, Authenticatable::class, \Throwable::class];

    /** @var string What a closure's parameter holding a payload is typed as, read from the source, where no type can be resolved. */
    private const string PAYLOAD_TYPE_IN_SOURCE = '/\b(?:AuditRecord|PendingRecord|CaptureSignal|Closure|Model|Authenticatable|Throwable|\w*Exception)\b/';

    /** @var array<string, non-empty-list<class-string>> The lifecycle listeners' parameters, as `class::method.parameter`, each with the types it takes: a framework event read for an id or a frame, and a failure only reported. */
    private const array LIFECYCLE_PARAMETERS = [
        CarryContextIntoJobs::class . '::__invoke.event'   => [ContextDehydrating::class],
        CarryContextIntoJobs::class . '::report.exception' => [\Throwable::class],
        TrackCommandFrames::class . '::__invoke.event'     => [CommandFinished::class, CommandStarting::class],
        TrackJobFrames::class . '::__invoke.event'         => [JobExceptionOccurred::class, JobFailed::class, JobProcessed::class, JobProcessing::class],
    ];

    /** @var array<string, string> The parameters that go by a payload's name yet hold only a name or a reference, as `class::method.parameter`, each with its type: the wildcard's event name, and a user already reduced to its reference, which the package passes unmarked as it does every actor. */
    private const array NAMES_AND_REFERENCES = [
        CaptureMappedEvent::class . '::handle.event'               => 'string',
        RecordLaravelAuthEvent::class . '::actedOnThemselves.user' => '?SineMacula\Laravel\AuditLog\Records\Reference',
    ];

    /** @var list<class-string> The classes the scan must find a payload parameter in. */
    private const array MUST_HOLD_ONE = [
        CaptureCoordinator::class,
        CaptureFailedException::class,
        CaptureMappedEvent::class,
        CapturedEvents::class,
        CarryContextIntoJobs::class,
        GateArguments::class,
        ModelChangeDescriber::class,
        RecordGateDenial::class,
        RecordLaravelAuthEvent::class,
        RecordModelChange::class,
        RecordPipeline::class,
        TrackCommandFrames::class,
        TrackJobFrames::class,
        UserReference::class,
    ];

    /** @var list<string> The parameters the scan must find, as `class::method.parameter`: an event, a model, a user, a record, a payload, a failure and a closure each among them. */
    private const array MUST_FIND = [
        CaptureCoordinator::class . '::mapped.event',
        CaptureCoordinator::class . '::captured.describe',
        CaptureCoordinator::class . '::contain.failure',
        CaptureCoordinator::class . '::contain.signal',
        CaptureFailedException::class . '::of.failure',
        CapturedEvents::class . '::whileMapping.work',
        CapturedEvents::class . '::whileDescribing.event',
        CapturedEvents::class . '::whileDescribing.describe',
        GateArguments::class . '::of.arguments',
        ModelChangeDescriber::class . '::describe.model',
        ModelChangeDescriber::class . '::describe.record',
        UserReference::class . '::of.user',
        CaptureMappedEvent::class . '::handle.payload',
        RecordGateDenial::class . '::handle.event',
        RecordLaravelAuthEvent::class . '::handle.event',
        RecordModelChange::class . '::created.model',
        RecordPipeline::class . '::write.pending',
        RecordPipeline::class . '::write.capture',
    ];

    /** @var list<string> The closures' payload parameters the scan must find, as `file:parameter`. */
    private const array MUST_FIND_IN_A_CLOSURE = [
        'Capture/CaptureCoordinator.php:pending',
        'Listeners/RecordGateDenial.php:pending',
        'Listeners/RecordLaravelAuthEvent.php:pending',
        'Listeners/RecordModelChange.php:record',
    ];

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
     * a parameter that goes by a payload's name or type, and the only ones left
     * unmarked are the lifecycle listeners' and those that hold only a name or
     * a reference.
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

        sort($unmarked);

        $exempt = [...array_keys(self::LIFECYCLE_PARAMETERS), ...array_keys(self::NAMES_AND_REFERENCES)];

        sort($exempt);

        self::assertSame($exempt, $unmarked);
    }

    /**
     * The scan finds a payload parameter in each class that must hold one, and
     * each parameter it must find, and reads every class of the folders the
     * rule holds, the enums and one added later included.
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
        self::assertContains(self::NAMESPACE . 'Capture\Enums\CapturedActivity', self::scanned());
        self::assertContains(self::NAMESPACE . 'Capture\Enums\ModelEvent', self::scanned());
        self::assertContains(RecordPipeline::class, self::scanned());
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
            'a closure'                    => ['typedClosure', true],
            'a nullable closure'           => ['nullableClosure', true],
            'a model'                      => ['typedModel', true],
            'an authenticatable user'      => ['typedUser', true],
            'a pending record'             => ['typedPending', true],
            'an audit record'              => ['typedRecord', true],
            'a capture\'s signal'          => ['typedSignal', true],
            'a throwable'                  => ['typedThrowable', true],
            'a class of exception'         => ['typedException', true],
            'one of a union of exceptions' => ['unionOfExceptions', true],
            'an object named `event`'      => ['event', true],
            'an array named `payload`'     => ['payload', true],
            'an array named `arguments`'   => ['arguments', true],
            'an array named `credentials`' => ['credentials', true],
            'a mixed `user`'               => ['user', true],
            'a string named `exception`'   => ['exception', true],
            'a class name'                 => ['eventClass', false],
            'a code'                       => ['code', false],
            'an untyped `other`'           => ['other', false],
        ];
    }

    /**
     * The scan reads a parameter as one the rule holds by its name or its type,
     * so it flags what it should and nothing else: protects against a scan that
     * passes by flagging nothing.
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
             * @param  \Closure(): void  $typedClosure
             * @param  ?\Closure(): void  $nullableClosure
             * @param  \Illuminate\Database\Eloquent\Model  $typedModel
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $typedUser
             * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $typedPending
             * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $typedRecord
             * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $typedSignal
             * @param  \Throwable  $typedThrowable
             * @param  \RuntimeException  $typedException
             * @param  \LogicException|\RuntimeException  $unionOfExceptions
             * @param  object  $event
             * @param  array<string, string>  $payload
             * @param  array<int, string>  $arguments
             * @param  array<string, string>  $credentials
             * @param  mixed  $user
             * @param  string  $exception
             * @param  string  $eventClass
             * @param  string  $code
             * @param  string  $other
             * @return void
             */
            public function everyKind(
                #[\SensitiveParameter]
                \Closure $typedClosure,
                #[\SensitiveParameter]
                ?\Closure $nullableClosure,
                #[\SensitiveParameter]
                Model $typedModel,
                #[\SensitiveParameter]
                Authenticatable $typedUser,
                #[\SensitiveParameter]
                PendingRecord $typedPending,
                #[\SensitiveParameter]
                AuditRecord $typedRecord,
                #[\SensitiveParameter]
                ?CaptureSignal $typedSignal,
                #[\SensitiveParameter]
                \Throwable $typedThrowable,
                #[\SensitiveParameter]
                \RuntimeException $typedException,
                #[\SensitiveParameter]
                \LogicException|\RuntimeException $unionOfExceptions,
                #[\SensitiveParameter]
                object $event,
                #[\SensitiveParameter]
                array $payload,
                #[\SensitiveParameter]
                array $arguments,
                #[\SensitiveParameter]
                array $credentials,
                #[\SensitiveParameter]
                mixed $user,
                #[\SensitiveParameter]
                string $exception,
                string $eventClass,
                string $code,
                string $other,
            ): void {}
        };

        $reflected = new \ReflectionParameter([$fixture, 'everyKind'], $parameter);

        self::assertSame($held, self::holdsAPayload($reflected));
    }

    /**
     * Each lifecycle parameter is still there, unmarked, typed by the
     * framework's lifecycle events or a throwable it says: a rename or a change
     * of type fails instead of excusing it, and one marked since is taken off
     * the list.
     *
     * @return void
     */
    public function testEveryLifecycleParameterIsAFrameworkEventOrAFailure(): void
    {
        foreach (self::LIFECYCLE_PARAMETERS as $parameter => $types) {
            [$class, $member] = explode('::', $parameter);
            [$method, $name]  = explode('.', $member);

            /** @var class-string $class */
            $reflected = new \ReflectionParameter([$class, $method], $name);

            self::assertContains($class, [CarryContextIntoJobs::class, TrackCommandFrames::class, TrackJobFrames::class], $parameter);
            self::assertSame(implode('|', $types), (string) $reflected->getType(), $parameter);
            self::assertSame([], $reflected->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }

    /**
     * Each parameter excused as a name or a reference is still there, unmarked,
     * goes by a payload's name and is typed as only a string or a reference can
     * be, so a rename, or a change of its type to something that can hold an
     * event or a user, fails instead of excusing it.
     *
     * @return void
     */
    public function testEveryNameOrReferenceExemptionHoldsNoPayload(): void
    {
        foreach (self::NAMES_AND_REFERENCES as $parameter => $type) {
            [$class, $member] = explode('::', $parameter);
            [$method, $name]  = explode('.', $member);

            /** @var class-string $class */
            $reflected = new \ReflectionParameter([$class, $method], $name);

            self::assertContains($name, self::PAYLOAD_NAMES, $parameter);
            self::assertSame($type, (string) $reflected->getType(), $parameter);
            self::assertSame([], $reflected->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }

    /**
     * A closure's parameters are out of a scan of methods, so they are read
     * from the source: every one that goes by a payload's name or type is
     * marked, and the scan finds each it must.
     *
     * @return void
     */
    public function testEveryPayloadParameterOfAClosureIsMarkedSensitive(): void
    {
        $unmarked = [];
        $found    = [];

        foreach (self::sourceFiles() as $file) {
            $source = (string) file_get_contents(self::src() . $file);

            foreach (self::closureParametersIn($source) as $parameters) {
                array_push($unmarked, ...array_map(static fn (string $name): string => "{$file}:{$name}", self::unmarkedIn($parameters)));
                array_push($found, ...array_map(static fn (string $name): string => "{$file}:{$name}", self::payloadsIn($parameters)));
            }
        }

        self::assertSame([], $unmarked);
        self::assertSame([], array_values(array_diff(self::MUST_FIND_IN_A_CLOSURE, $found)));
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
     * Rows of `[a closure's parameters, the names the scan must flag]`: a
     * payload is flagged by its name or its type unless it is marked, and
     * anything else is left alone.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideClosureVerdicts(): iterable
    {
        yield from [
            'a marked pending record'   => [['#[\SensitiveParameter] PendingRecord $pending'], []],
            'an unmarked pending'       => [['PendingRecord $pending'], ['pending']],
            'an unmarked record type'   => [['PendingRecord $held'], ['held']],
            'an unmarked model'         => [['Model $subject'], ['subject']],
            'an unmarked user'          => [['Authenticatable $who'], ['who']],
            'a failure'                 => [['?\RuntimeException $thing'], ['thing']],
            'a marked failure'          => [['#[\SensitiveParameter] \Throwable $thing'], []],
            'a closure'                 => [['\Closure $work'], ['work']],
            'a capture\'s signal'       => [['?CaptureSignal $capture'], ['capture']],
            'an event by its name'      => [['object $event'], ['event']],
            'a class name and an event' => [['string $exceptionClass', 'object $event'], ['event']],
            'neither'                   => [['string $exceptionClass', 'int $count'], []],
            'one of two marked'         => [['#[\SensitiveParameter] array $payload', 'mixed $user'], ['user']],
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
     * A user whose identifier cannot be read throws through its reference, and
     * each frame that held the user shows the value PHP leaves for a marked
     * parameter, in its arguments and in its trace as a string.
     *
     * @return void
     */
    public function testAStackFrameOfAUsersReferenceHidesTheUser(): void
    {
        $user = \Mockery::mock(Authenticatable::class);

        $user->shouldReceive('getAuthIdentifier')->once()->andReturnUsing(static function (): never {
            throw new \RuntimeException('Fixed.');
        });

        $thrown = self::thrownBy(static function () use ($user): void {
            UserReference::of($user);
        });

        $frames = self::framesOf($thrown, UserReference::class);

        self::assertSame(['byIdentifier', 'of'], array_column($frames, 'function'));
        self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0] ?? null);
        self::assertInstanceOf(\SensitiveParameterValue::class, $frames[1]['args'][0] ?? null);
        self::assertStringContainsString(UserReference::class . '::of(Object(SensitiveParameterValue))', $thrown->getTraceAsString());
    }

    /**
     * Work that throws inside a mapping window leaves the window's frame
     * holding the value PHP leaves for a marked parameter, never the closure,
     * and the window closes all the same.
     *
     * @return void
     */
    public function testAStackFrameOfAMappingWindowHidesItsWork(): void
    {
        $events = new CapturedEvents;

        $thrown = self::thrownBy(static function () use ($events): void {
            $events->whileMapping(static function (): never {
                throw new \RuntimeException('Fixed.');
            });
        });

        $frames = self::framesOf($thrown, CapturedEvents::class);

        self::assertSame(['whileMapping'], array_column($frames, 'function'));
        self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0] ?? null);
        self::assertStringContainsString(CapturedEvents::class . '->whileMapping(Object(SensitiveParameterValue))', $thrown->getTraceAsString());
        self::assertFalse($events->isMapping());
    }

    /**
     * What the marking hides is really in the frame's reach: an unmarked frame
     * of the same call keeps the secret, so the tests above cannot pass by
     * there being nothing to hide.
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
     * What the work throws.
     *
     * @param  \Closure(): void  $work
     * @return \RuntimeException
     */
    private static function thrownBy(\Closure $work): \RuntimeException
    {
        try {
            $work();
        } catch (\RuntimeException $thrown) {
            return $thrown;
        }

        self::fail('Expected the work to throw.');
    }

    /**
     * The frames of the exception's trace that the class's methods make, in
     * order, innermost first.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \RuntimeException  $thrown
     * @param  class-string  $class
     * @return list<array<string, mixed>>
     */
    private static function framesOf(\RuntimeException $thrown, string $class): array
    {
        return array_values(array_filter($thrown->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === $class));
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

            if (in_array($name, self::PAYLOAD_TYPES, true) || self::isPayloadSubtype($name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the type is a model, an authenticatable user or a throwable.
     *
     * @param  string  $type
     * @return bool
     */
    private static function isPayloadSubtype(string $type): bool
    {
        foreach (self::PAYLOAD_PARENTS as $parent) {
            if (is_a($type, $parent, true)) {
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
        $unmarked = array_filter($parameters, static fn (string $parameter): bool => !str_contains($parameter, \SensitiveParameter::class));

        return self::payloadsIn(array_values($unmarked));
    }

    /**
     * The names of a closure's parameters that hold a payload, by their name or
     * their type, marked or not.
     *
     * @param  list<string>  $parameters
     * @return list<string>
     */
    private static function payloadsIn(array $parameters): array
    {
        $names = [];

        foreach ($parameters as $parameter) {
            if (preg_match('/\$(\w+)/', $parameter, $match) !== 1) {
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
