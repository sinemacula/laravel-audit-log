<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Encryption\Encrypter;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\IntegrityAlarm;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverageResult;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\SealContentionException;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealFailedException;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Holds the integrity classes, the seal command and the integrity progress to
 * the rule that keeps key material and entries out of a stack trace: with
 * `zend.exception_ignore_args` off every frame keeps its arguments, so a
 * parameter that holds a secret, an entry row or a failure is marked
 * `#[\SensitiveParameter]` on every method it passes through, private helpers
 * and closures included, and a closure's parameters, which reflection of a
 * class cannot reach, are read from the source.
 *
 * Each scan must find what it expects, so it cannot pass by finding nothing,
 * and is shown to flag what it should. A stored seal row is no personal data,
 * and because the scan reads names it goes by `$stored` or `$seal`, never by
 * `$row`. A source scan shows that nothing chains a failure or reads its text,
 * and real throws of verification and of signing show what the marking leaves
 * in a frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class IntegritySensitiveParametersTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The namespace every source file is named under. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The folders under `src` the rule holds, whatever is added to them. */
    private const array FOLDERS = ['Integrity'];

    /** @var list<string> The further files under `src` the rule holds. */
    private const array FILES = ['Console/IntegrityAlarm.php', 'Console/SealCommand.php', 'Database/IntegrityProgress.php'];

    /** @var list<string> The names a parameter holding key material, an entry row or a failure goes by. */
    private const array HELD_NAMES = ['secret', 'sealKey', 'applicationKey', 'row', 'rows', 'entry', 'failure', 'exception'];

    /** @var list<class-string> The types a parameter holding key material goes by; any class of throwable is one too. */
    private const array HELD_TYPES = [IntegrityKey::class];

    /** @var string What a closure's held parameter is typed as, read from the source, where no type can be resolved. */
    private const string HELD_TYPE_IN_SOURCE = '/\b(?:IntegrityKey|Throwable|\w*Exception)\b/';

    /** @var list<class-string> The classes the scan must find a held parameter in. */
    private const array MUST_HOLD_ONE = [
        Anchorer::class,
        CheckpointWriter::class,
        IntegrityAlarm::class,
        IntegrityKey::class,
        IntegritySettings::class,
        KeyRing::class,
        ManifestVerifier::class,
        RecordSigner::class,
        SealSigner::class,
        Sealer::class,
        SegmentVerifier::class,
    ];

    /** @var list<string> The parameters the scan must find, as `class::method.parameter`: the seal key's secret, the verifier's entry row and the sealer's failure among them. */
    private const array MUST_FIND = [
        SealSigner::class . '::sealKey.secret',
        SealSigner::class . '::signature.key',
        SegmentVerifier::class . '::memberFinding.entry',
        SegmentVerifier::class . '::entryFinding.entry',
        ManifestVerifier::class . '::descriptorOf.entry',
        Sealer::class . '::isLostToAConcurrentWriter.exception',
        Anchorer::class . '::classOf.failure',
        IntegrityAlarm::class . '::report.exception',
        CheckpointWriter::class . '::sealable.rows',
    ];

    /** @var list<string> The closures' held parameters the scan must find, as `file:parameter`. */
    private const array MUST_FIND_IN_A_CLOSURE = ['Integrity/CheckpointWriter.php:row'];

    /** @var list<string> Every parameter named `$row` or `$rows`, as `class::method.parameter` or `file:parameter`; each holds entries, never a seal. */
    private const array ENTRY_ROWS = [
        'Integrity/CheckpointWriter.php:row',
        CheckpointWriter::class . '::positionOf.row',
        CheckpointWriter::class . '::sealable.rows',
        RecordSigner::class . '::capturedDigest.row',
        RecordSigner::class . '::columns.row',
        RecordSigner::class . '::verifies.row',
    ];

    /** @var list<class-string<\Throwable>> The exceptions the package raises that must be found, each with no previous. */
    private const array PACKAGE_EXCEPTIONS = [
        AnchorConflictException::class,
        IntegrityCheckFailedException::class,
        SealChainException::class,
        SealContentionException::class,
        SealFailedException::class,
        UnknownKeyException::class,
    ];

    /** @var array<string, string> The one refusal allowed to chain what it caught, by its file, with its arguments: the encoder's refusal of a string that is not UTF-8 keeps the encoding's `\JsonException`, whose message is PHP's own and whose frames hold no more than the refusal's. */
    private const array CHAINS_THE_ENCODING = ['Integrity/CanonicalEncoder.php' => '\'A string that is not valid UTF-8 cannot be encoded canonically.\', 0, $exception'];

    /** @var int The most arguments a throwable's inherited constructor may be given before the next would be a previous. */
    private const int BEFORE_PREVIOUS = 2;

    /** @var string What a read of a failure's text looks like: its message, its SQL, its bindings, its previous, its trace or its driver's message, or a trace of its own. */
    private const string FAILURE_TEXT = '/(?:->|::)\s*get(?:Message|Sql|RawSql|Bindings|Previous|TraceAsString)\s*\(|\berrorInfo\b|\bdebug_(?:print_)?backtrace\s*\(/';

    /** @var string A secret long enough to be a key, holding the planted secret. */
    private const string LONG_SECRET = 'integrity sensitive scan key s3cr3t 0123456789';

    /** @var string A secret too short to be a key, holding the planted secret. */
    private const string SHORT_SECRET = 'short s3cr3t';

    /** @var string The id of a key. */
    private const string KEY_ID = 'k1';

    /** @var string A digest, and a signature, that is well formed. */
    private const string DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string The id of a seal. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The id of a prune operation. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string An instant in the package's form. */
    private const string INSTANT = '2026-11-01T13:00:00.000000Z';

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
     * a parameter that goes by the name or the type of key material, an entry
     * row or a failure, with no exemption.
     *
     * @return void
     */
    public function testEveryKeyOrRowParameterIsMarkedSensitive(): void
    {
        $unmarked = [];

        foreach (self::scanned() as $class) {
            foreach (self::heldParametersOf($class) as $parameter) {
                if ($parameter->getAttributes(\SensitiveParameter::class) !== []) {
                    continue;
                }

                $unmarked[] = self::named($parameter);
            }
        }

        self::assertSame([], $unmarked);
    }

    /**
     * The scan finds a held parameter in each class that must hold one and each
     * parameter it must find, and reads every class of the folders the rule
     * holds, one in a nested folder and one added later included.
     *
     * @return void
     */
    public function testTheScanFindsAParameterInEachClassThatHasOne(): void
    {
        $classes = [];
        $found   = [];

        foreach (self::scanned() as $class) {
            $held = self::heldParametersOf($class);

            if ($held !== []) {
                $classes[] = $class;
            }

            array_push($found, ...array_map(self::named(...), $held));
        }

        self::assertSame([], array_values(array_diff(self::MUST_HOLD_ONE, $classes)));
        self::assertSame([], array_values(array_diff(self::MUST_FIND, $found)));
        self::assertContains(SealCommand::class, self::scanned());
        self::assertContains(self::NAMESPACE . 'Database\IntegrityProgress', self::scanned());
        self::assertContains(self::NAMESPACE . 'Integrity\Anchors\DiskAnchor', self::scanned());
        self::assertContains(Finding::class, self::scanned());
        self::assertContains(PruneBitmap::class, self::scanned());
        self::assertContains(PruneCoverage::class, self::scanned());
        self::assertContains(PruneCoverageResult::class, self::scanned());
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
            'a key by its type'               => ['typedKey', true],
            'a nullable key'                  => ['nullableKey', true],
            'a throwable'                     => ['typedThrowable', true],
            'a class of exception'            => ['typedException', true],
            'one of a union of exceptions'    => ['unionOfExceptions', true],
            'a string named `secret`'         => ['secret', true],
            'a string named `sealKey`'        => ['sealKey', true],
            'a string named `applicationKey`' => ['applicationKey', true],
            'an array named `row`'            => ['row', true],
            'an array named `rows`'           => ['rows', true],
            'an array named `entry`'          => ['entry', true],
            'a mixed `failure`'               => ['failure', true],
            'a string named `exception`'      => ['exception', true],
            'a stored seal'                   => ['stored', false],
            'a seal'                          => ['seal', false],
            'a key id'                        => ['keyId', false],
            'a digest'                        => ['digest', false],
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
             * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $typedKey
             * @param  ?\SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $nullableKey
             * @param  \Throwable  $typedThrowable
             * @param  \RuntimeException  $typedException
             * @param  \LogicException|\RuntimeException  $unionOfExceptions
             * @param  string  $secret
             * @param  string  $sealKey
             * @param  string  $applicationKey
             * @param  array<string, string>  $row
             * @param  list<array<string, string>>  $rows
             * @param  array<string, string>  $entry
             * @param  mixed  $failure
             * @param  string  $exception
             * @param  array<string, string>  $stored
             * @param  array<string, string>  $seal
             * @param  string  $keyId
             * @param  string  $digest
             * @return void
             */
            public function everyKind(
                #[\SensitiveParameter]
                IntegrityKey $typedKey,
                #[\SensitiveParameter]
                ?IntegrityKey $nullableKey,
                #[\SensitiveParameter]
                \Throwable $typedThrowable,
                #[\SensitiveParameter]
                \RuntimeException $typedException,
                #[\SensitiveParameter]
                \LogicException|\RuntimeException $unionOfExceptions,
                #[\SensitiveParameter]
                string $secret,
                #[\SensitiveParameter]
                string $sealKey,
                #[\SensitiveParameter]
                string $applicationKey,
                #[\SensitiveParameter]
                array $row,
                #[\SensitiveParameter]
                array $rows,
                #[\SensitiveParameter]
                array $entry,
                #[\SensitiveParameter]
                mixed $failure,
                #[\SensitiveParameter]
                string $exception,
                array $stored,
                array $seal,
                string $keyId,
                string $digest,
            ): void {}
        };

        $reflected = new \ReflectionParameter([$fixture, 'everyKind'], $parameter);

        self::assertSame($held, self::isHeld($reflected));
    }

    /**
     * A closure's parameters are out of a scan of methods, so they are read
     * from the source: every one that goes by a held name or type is marked,
     * with no exemption, and the scan finds the ones it must.
     *
     * @return void
     */
    public function testEveryClosureParameterHoldingARowIsMarked(): void
    {
        $unmarked = [];
        $found    = [];

        foreach (self::sourceFiles() as $file) {
            foreach (self::closureParametersIn(self::sourceOf($file)) as $parameters) {
                array_push($unmarked, ...self::prefixed($file, self::heldIn($parameters, false)));
                array_push($found, ...self::prefixed($file, self::heldIn($parameters, true)));
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
            'a closure'                 => ['<?php $a = function (array $row) {};', [['array $row']]],
            'a static closure'          => ['<?php $a = static function (array $row) {};', [['array $row']]],
            'an arrow function'         => ['<?php $a = fn (array $row) => 1;', [['array $row']]],
            'a static arrow function'   => ['<?php $a = static fn (array $row) => 1;', [['array $row']]],
            'a default holding a comma' => ['<?php $a = fn (array $b = [1, 2], $c = 3) => 1;', [['array $b = [1, 2]', '$c = 3']]],
            'a marked parameter'        => ['<?php $a = fn (#[\SensitiveParameter] \stdClass $row, int $c) => 1;', [['#[\SensitiveParameter] \stdClass $row', 'int $c']]],
            'over several lines'        => ["<?php \$a = fn (\n    int \$b,\n    int \$c,\n) => 1;", [['int $b', 'int $c']]],
            'a comment inside'          => ['<?php $a = fn (/* the row */ array $row) => 1;', [['array $row']]],
            'no parameter'              => ['<?php $a = fn () => 1;', []],
            'a named method'            => ['<?php class A { public function b(array $row) {} }', []],
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
     * Rows of `[a closure's parameters, the names the scan must flag]`: a held
     * parameter is flagged by its name or its type unless it is marked, and
     * anything else is left alone.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideClosureVerdicts(): iterable
    {
        yield from [
            'a marked row'      => [['#[\SensitiveParameter] \stdClass $row'], []],
            'an unmarked row'   => [['\stdClass $row'], ['row']],
            'unmarked rows'     => [['array $rows'], ['rows']],
            'an unmarked entry' => [['array $entry'], ['entry']],
            'a key by its type' => [['IntegrityKey $held'], ['held']],
            'a failure'         => [['?\RuntimeException $thing'], ['thing']],
            'a throwable'       => [['\Throwable $caught'], ['caught']],
            'a marked failure'  => [['#[\SensitiveParameter] \Throwable $thing'], []],
            'a secret'          => [['string $secret'], ['secret']],
            'a seal and an id'  => [['array $seal', 'string $id'], []],
            'a stored seal'     => [['mixed $stored'], []],
            'one of two marked' => [['#[\SensitiveParameter] array $row', 'string $secret'], ['secret']],
            'two marked'        => [['#[\SensitiveParameter] array $row', '#[\SensitiveParameter] string $secret'], []],
        ];
    }

    /**
     * The closure scan flags a held parameter that is unmarked, by its name or
     * its type, and reads each parameter's marking apart.
     *
     * @param  list<string>  $parameters
     * @param  list<string>  $flagged
     * @return void
     */
    #[DataProvider('provideClosureVerdicts')]
    public function testTheClosureScanFlagsAnUnmarkedOne(array $parameters, array $flagged): void
    {
        self::assertSame($flagged, self::heldIn($parameters, false));
    }

    /**
     * No parameter named `$row` or `$rows` holds a seal: each one of them,
     * method or closure, is one of the entry rows listed, so a seal row given
     * that name is caught here, and the reading of a stored seal takes it as
     * `$stored` throughout.
     *
     * @return void
     */
    public function testASealRowIsNeverNamedRow(): void
    {
        $rows = [];

        foreach (self::scanned() as $class) {
            foreach (self::heldParametersOf($class) as $parameter) {
                if (!in_array($parameter->getName(), ['row', 'rows'], true)) {
                    continue;
                }

                $rows[] = self::named($parameter);
            }
        }

        foreach (self::sourceFiles() as $file) {
            foreach (self::closureParametersIn(self::sourceOf($file)) as $parameters) {
                array_push($rows, ...self::prefixed($file, array_values(array_intersect(self::namesIn($parameters), ['row', 'rows']))));
            }
        }

        sort($rows);

        self::assertSame(self::ENTRY_ROWS, $rows);

        $fromRow = (new \ReflectionMethod(SealEnvelope::class, 'fromRow'))->getParameters();

        self::assertSame(['stored'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $fromRow));
        self::assertSame('array', (string) $fromRow[0]->getType());
    }

    /**
     * Nothing the rule holds gives an exception a previous one: each `new` of a
     * class of exception passes no more than the arguments before a previous,
     * by position or by name, but for the one refusal allowed; each exception
     * the package raises takes no previous in its own constructor, makes itself
     * with no more arguments than that constructor takes, and gives its parent
     * no previous. Each is found, so the scan cannot pass by finding none.
     *
     * @return void
     */
    public function testNothingChainsAFailure(): void
    {
        $news    = 0;
        $allowed = 0;

        foreach (self::sourceFiles() as $file) {
            foreach (self::argumentsOfEachNew(self::sourceOf($file), '/Exception\z/') as $arguments) {
                $news++;

                if (implode(', ', $arguments) === (self::CHAINS_THE_ENCODING[$file] ?? null)) {
                    $allowed++;

                    continue;
                }

                self::assertLessThanOrEqual(self::BEFORE_PREVIOUS, count($arguments), "{$file} gives an exception a previous one.");
                self::assertSame([], preg_grep('/^\s*previous\s*:/', $arguments), "{$file} gives an exception a previous one.");
            }
        }

        self::assertGreaterThan(0, $news, 'No file makes an exception.');
        self::assertSame(count(self::CHAINS_THE_ENCODING), $allowed);

        $raised = self::raisedExceptions();

        self::assertSame([], array_values(array_diff(self::PACKAGE_EXCEPTIONS, $raised)));

        foreach ($raised as $class) {
            self::assertUnchained($class);
        }
    }

    /**
     * The one refusal allowed to chain what it caught is still there, chaining
     * only the `\JsonException` the encoding of one string threw, which PHP
     * words itself: a refusal changed to chain anything else is held to the
     * rule again.
     *
     * @return void
     */
    public function testTheRefusalAllowedChainsOnlyTheEncoding(): void
    {
        foreach (array_keys(self::CHAINS_THE_ENCODING) as $file) {
            $source = self::withoutComments(self::sourceOf($file));

            self::assertSame(1, substr_count($source, 'catch ('), $file);
            self::assertMatchesRegularExpression('/catch \(\\\JsonException \$exception\) \{\s*throw new \\\UnexpectedValueException\(/', $source, $file);
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
            'a thrown one'          => ['<?php throw new Target($a, 0, $e);', [['$a', '0', '$e']]],
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
        self::assertSame($news, self::argumentsOfEachNew($source, '/\ATarget\z/'));
    }

    /**
     * Rows of `[an exception the package raises, made as the package makes
     * it]`: each named constructor of each of them.
     *
     * @return iterable<string, array{0: \Closure(): \Throwable}>
     */
    public static function provideRaised(): iterable
    {
        yield from [
            'a lost contention'     => [static fn (): \Throwable => SealContentionException::after(3)],
            'a failed seal'         => [static fn (): \Throwable => SealFailedException::stoppedBy(\RuntimeException::class)],
            'a stopped check'       => [static fn (): \Throwable => IntegrityCheckFailedException::stopped('audit-log:verify', \RuntimeException::class)],
            'an anchor conflict'    => [static fn (): \Throwable => AnchorConflictException::forSequence(1)],
            'a head that is edited' => [static fn (): \Throwable => SealChainException::forHead(self::SEAL_ID)],
            'a head of another log' => [static fn (): \Throwable => SealChainException::forLog(self::SEAL_ID)],
            'a key the ring lacks'  => [static fn (): \Throwable => UnknownKeyException::forKey(self::KEY_ID)],
        ];
    }

    /**
     * Each exception the package raises, as the package makes it, carries no
     * previous exception.
     *
     * @param  \Closure(): \Throwable  $make
     * @return void
     */
    #[DataProvider('provideRaised')]
    public function testARaisedExceptionCarriesNoPrevious(\Closure $make): void
    {
        $raised = $make();

        self::assertContains($raised::class, self::PACKAGE_EXCEPTIONS);
        self::assertNull($raised->getPrevious());
    }

    /**
     * Nothing the rule holds reads a failure's message, SQL, bindings, previous
     * exception, trace or driver message, or takes a trace of its own: a caught
     * failure is named by its class alone.
     *
     * @return void
     */
    public function testNothingReadsAFailuresText(): void
    {
        foreach (self::sourceFiles() as $file) {
            self::assertSame(0, preg_match(self::FAILURE_TEXT, self::withoutComments(self::sourceOf($file))), "{$file} reads a failure's text.");
        }
    }

    /**
     * Rows of `[source, whether it reads a failure's text]`: each read the scan
     * must flag, and what it must leave alone, a comment that names one
     * included.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideFailureTextReads(): iterable
    {
        yield from [
            'its message'               => ['<?php $e->getMessage();', true],
            'its message, nullsafe'     => ['<?php $e?->getMessage();', true],
            'its message as a callable' => ['<?php $read = $e->getMessage(...);', true],
            'its SQL'                   => ['<?php $e->getSql();', true],
            'its raw SQL'               => ['<?php $e->getRawSql();', true],
            'its bindings'              => ['<?php $e->getBindings();', true],
            'its previous'              => ['<?php $e->getPrevious();', true],
            'its trace'                 => ['<?php $e->getTraceAsString();', true],
            'its driver message'        => ['<?php $e->errorInfo[2];', true],
            'a trace of its own'        => ['<?php debug_backtrace();', true],
            'a printed trace'           => ['<?php debug_print_backtrace();', true],
            'its class'                 => ['<?php get_debug_type($e);', false],
            'its code'                  => ['<?php $e->getCode();', false],
            'another method'            => ['<?php $bag->getMessages();', false],
            'a comment naming one'      => ['<?php /** never getMessage() */ $a = 1; // nor getSql()', false],
        ];
    }

    /**
     * The text scan flags each read of a failure's text, and reads no comment.
     *
     * @param  string  $source
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideFailureTextReads')]
    public function testTheTextScanFlagsEachRead(string $source, bool $reads): void
    {
        self::assertSame($reads ? 1 : 0, preg_match(self::FAILURE_TEXT, self::withoutComments($source)));
    }

    /**
     * A verification that throws while it checks an entry keeps a frame for
     * each call that held the entry, and each shows the value PHP leaves for a
     * marked parameter where the row was, in its arguments and in its trace as
     * a string, and nothing of the entry. The codec is final and cannot be
     * stubbed, so the entry signer's key ring is malformed instead, and the
     * throw, after the entry is decoded, is one the verifier does not catch.
     *
     * @return void
     */
    public function testAStackFrameOfVerificationHidesTheRow(): void
    {
        $entry = self::storedEntry();

        self::assertTrue(self::holdsText($entry, self::SECRET));

        $database = new DatabaseManager(new Container, new ConnectionFactory(new Container));
        $verifier = new SegmentVerifier(
            new SealSigner(self::ring(['keys' => [self::KEY_ID => self::LONG_SECRET], 'current' => self::KEY_ID])),
            new RecordSigner(self::ring(['keys' => 'not a map'])),
            new RowCodec,
            new SealSettings(new Repository),
            new NullPruneLedger,
            new NullAnchor,
            $database,
            new ManifestVerifier($database, new Encrypter(str_repeat('k', 32), 'aes-256-cbc')),
        );

        $thrown = self::thrownBy(self::memberFindingOf($verifier, $entry));

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);

        $frames = self::framesOf($thrown, [SegmentVerifier::class, RecordSigner::class]);

        self::assertSame([RecordSigner::class . '::verifies', SegmentVerifier::class . '::entryFinding', SegmentVerifier::class . '::memberFinding'], array_keys($frames));

        foreach ($frames as $arguments) {
            self::assertInstanceOf(\SensitiveParameterValue::class, $arguments[0] ?? null);
        }

        self::assertSame(self::DIGEST, $frames[SegmentVerifier::class . '::memberFinding'][1] ?? null);
        self::assertStringContainsString('Object(SensitiveParameterValue)', $thrown->getTraceAsString());
        self::assertHoldsNoSecret($thrown->getTrace(), 'the frames');
        self::assertHoldsNoSecret($thrown, 'the exception');
    }

    /**
     * Rows of `[how the ring refuses its key, whether a frame holds the
     * secret]`: each way a key ring can refuse its key while a seal or a prune
     * record is signed or verified. The rows name the settings rather than hold
     * them, since the frame that runs a test keeps its data unmarked.
     *
     * @return iterable<string, array{0: 'application'|'id'|'short', 1: bool}>
     */
    public static function provideRefusedKeys(): iterable
    {
        yield from [
            'a key id the ring refuses'    => ['id', true],
            'a secret too short'           => ['short', true],
            'an application key too short' => ['application', false],
        ];
    }

    /**
     * Signing and verifying a seal or a prune record under a key the ring
     * refuses keeps the frame that held the secret, which shows the value PHP
     * leaves for a marked parameter, and nothing of the secret anywhere in the
     * trace, its string or the exception.
     *
     * @param  'application'|'id'|'short'  $refusal
     * @param  bool  $framed
     * @return void
     */
    #[DataProvider('provideRefusedKeys')]
    public function testAStackFrameOfSigningHidesTheKey(string $refusal, bool $framed): void
    {
        [$integrity, $app] = match ($refusal) {
            'id'          => [['keys' => ['bad id!' => self::LONG_SECRET], 'current' => 'bad id!'], []],
            'short'       => [['keys' => [self::KEY_ID => self::SHORT_SECRET], 'current' => self::KEY_ID], []],
            'application' => [[], ['key' => self::SHORT_SECRET]],
        };

        $signer = new SealSigner(self::ring($integrity, $app));

        foreach (self::signingOf($signer) as $operation => $work) {
            $thrown = self::thrownBy($work);

            self::assertInstanceOf(\InvalidArgumentException::class, $thrown, $operation);
            self::assertArrayHasKey(SealSigner::class . '::' . $operation, self::framesOf($thrown, [SealSigner::class]), $operation);

            if ($framed) {
                $secret = self::framesOf($thrown, [IntegritySettings::class])[IntegritySettings::class . '::secret'] ?? [];

                self::assertInstanceOf(\SensitiveParameterValue::class, $secret[1] ?? null, $operation);
                self::assertStringContainsString('Object(SensitiveParameterValue)', $thrown->getTraceAsString(), $operation);
            }

            self::assertHoldsNoSecret($thrown->getTrace(), "the frames of {$operation}");
            self::assertHoldsNoSecret($thrown, "the exception of {$operation}");
        }
    }

    /**
     * A key refused as it is made keeps its secret out of the frame of its
     * constructor and out of the exception.
     *
     * @return void
     */
    public function testAStackFrameOfAKeyHidesItsSecret(): void
    {
        $thrown = self::thrownBy(static fn (): IntegrityKey => new IntegrityKey(self::KEY_ID, self::SHORT_SECRET));

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertInstanceOf(\SensitiveParameterValue::class, $thrown->getTrace()[0]['args'][1] ?? null);
        self::assertHoldsNoSecret($thrown->getTrace(), 'the frames');
        self::assertHoldsNoSecret($thrown, 'the exception');
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
     * Fail unless the exception the package raises takes no previous in its own
     * constructor, makes itself with no more arguments than that constructor
     * takes, and gives its parent's constructor no previous.
     *
     * @param  class-string<\Throwable>  $class
     * @return void
     */
    private static function assertUnchained(string $class): void
    {
        $reflected   = new \ReflectionClass($class);
        $source      = (string) file_get_contents((string) $reflected->getFileName());
        $constructor = $reflected->getConstructor();
        $own         = $constructor !== null && $constructor->getDeclaringClass()->getName() === $class;
        $most        = $own ? $constructor->getNumberOfParameters() : self::BEFORE_PREVIOUS;
        $made        = self::argumentsOfEachNew($source, '/\Aself\z/');

        self::assertNotSame([], $made, "{$class} is never made.");

        foreach ($made as $arguments) {
            self::assertLessThanOrEqual($most, count($arguments), "{$class} is made with a previous exception.");
        }

        foreach ($own ? $constructor->getParameters() : [] as $parameter) {
            self::assertNotSame('previous', $parameter->getName(), $class);
            self::assertFalse(self::isHeldByType($parameter), "{$class} takes a throwable.");
        }

        foreach (self::argumentsOfEachParentConstructor($source) as $arguments) {
            self::assertLessThanOrEqual(self::BEFORE_PREVIOUS, count($arguments), "{$class} gives its parent a previous exception.");
            self::assertSame([], preg_grep('/^\s*previous\s*:/', $arguments), "{$class} gives its parent a previous exception.");
        }
    }

    /**
     * The entry row as the verifier reads it: an entry stored as the package
     * stores it, its properties holding the secret, beside the member row that
     * records it.
     *
     * @return array<string, int|string|null>
     */
    private static function storedEntry(): array
    {
        $record = RecordFactory::captured(['note' => self::SECRET]);
        $stored = (new RowCodec)->encode(new FinalisedRecord($record, self::INSTANT, RecordSigner::VERSION, self::KEY_ID, self::DIGEST));

        return [...$stored, 'member_entry_id' => $stored['id'], 'member_hmac' => self::DIGEST];
    }

    /**
     * The work of finding the verifier's finding of the entry, through the
     * verifier's own frames, from a frame that marks the entry itself.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier  $verifier
     * @param  array<string, int|string|null>  $entry
     * @return \Closure(): ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private static function memberFindingOf(SegmentVerifier $verifier, array $entry): \Closure
    {
        // Bound into the verifier's scope, where `self` names the verifier, so
        // the HMAC the member row records is captured instead
        $hmac = self::DIGEST;
        $find = \Closure::bind(fn (#[\SensitiveParameter] array $entry): ?Finding => $this->memberFinding($entry, $hmac), $verifier, SegmentVerifier::class);

        return static fn (): ?Finding => $find($entry);
    }

    /**
     * The work of each signing and verifying of a seal or a prune record, by
     * the signer's method it calls.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $signer
     * @return array<string, \Closure(): (bool|\SineMacula\Laravel\AuditLog\Integrity\PruneRecord|string)>
     */
    private static function signingOf(SealSigner $signer): array
    {
        $seal  = new SealEnvelope('app-eu-1', self::SEAL_ID, 1, null, null, 1, self::DIGEST, self::INSTANT, self::INSTANT, self::INSTANT, self::KEY_ID);
        $prune = new PruneRecord('app-eu-1', self::SEAL_ID, self::DIGEST, 1, 'AQ', 1, self::OPERATION_ID, self::INSTANT, self::KEY_ID, self::DIGEST);

        return [
            'signingKeyId'  => static fn (): string => $signer->signingKeyId(),
            'sign'          => static fn (): string => $signer->sign($seal),
            'verifies'      => static fn (): bool => $signer->verifies($seal, self::DIGEST),
            'signPrune'     => static fn (): PruneRecord => $signer->signPrune('app-eu-1', self::SEAL_ID, self::DIGEST, 1, 'AQ', 1, self::OPERATION_ID, self::INSTANT),
            'verifiesPrune' => static fn (): bool => $signer->verifiesPrune($prune),
        ];
    }

    /**
     * What the work throws. The work holds the secret it is given, so its own
     * frame marks it.
     *
     * @param  \Closure(): (bool|object|string|null)  $work
     * @return \Throwable
     */
    private static function thrownBy(#[\SensitiveParameter] \Closure $work): \Throwable
    {
        try {
            $work();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('Expected the work to throw.');
    }

    /**
     * The arguments of each frame of the throwable in a method of one of the
     * classes, by `class::method`, innermost first; a closure bound into one of
     * them is left out.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Throwable  $thrown
     * @param  list<class-string>  $classes
     * @return array<string, list<mixed>>
     */
    private static function framesOf(\Throwable $thrown, array $classes): array
    {
        $frames = [];

        foreach ($thrown->getTrace() as $frame) {
            $class = $frame['class'] ?? null;

            if (!in_array($class, $classes, true) || str_contains($frame['function'], '{closure')) {
                continue;
            }

            $frames[$class . '::' . $frame['function']] = $frame['args'] ?? [];
        }

        return $frames;
    }

    /**
     * A key ring of the integrity and application settings given.
     *
     * @param  array<string, array<string, string>|string>  $integrity
     * @param  array<string, string>  $app
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $integrity, array $app = []): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity], 'app' => $app])));
    }

    /**
     * The parameters of the class's own methods that the rule holds; none for a
     * method PHP or a framework class or trait declares, since neither can be
     * marked.
     *
     * @param  class-string  $class
     * @return list<\ReflectionParameter>
     */
    private static function heldParametersOf(string $class): array
    {
        $parameters = [];

        foreach ((new \ReflectionClass($class))->getMethods() as $method) {
            if (!str_starts_with((string) $method->getFileName(), self::src())) {
                continue;
            }

            array_push($parameters, ...array_filter($method->getParameters(), self::isHeld(...)));
        }

        return $parameters;
    }

    /**
     * Whether the rule holds the parameter, by its name or by its type.
     *
     * @param  \ReflectionParameter  $parameter
     * @return bool
     */
    private static function isHeld(\ReflectionParameter $parameter): bool
    {
        return in_array($parameter->getName(), self::HELD_NAMES, true) || self::isHeldByType($parameter);
    }

    /**
     * Whether the parameter's type, or one member of its union, is key material
     * or a throwable.
     *
     * @param  \ReflectionParameter  $parameter
     * @return bool
     */
    private static function isHeldByType(\ReflectionParameter $parameter): bool
    {
        $type  = $parameter->getType();
        $types = $type instanceof \ReflectionNamedType ? [$type] : ($type instanceof \ReflectionUnionType ? $type->getTypes() : []);

        foreach ($types as $member) {
            $name = $member instanceof \ReflectionNamedType ? $member->getName() : '';

            if (in_array($name, self::HELD_TYPES, true) || is_a($name, \Throwable::class, true)) {
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
        $class = $parameter->getDeclaringClass();

        return ($class === null ? '' : $class->getName()) . '::' . $parameter->getDeclaringFunction()->getName() . '.' . $parameter->getName();
    }

    /**
     * The names of a closure's parameters that the rule holds, by name or by
     * type, and that are marked or not as asked.
     *
     * @param  list<string>  $parameters
     * @param  bool  $marked
     * @return list<string>
     */
    private static function heldIn(array $parameters, bool $marked): array
    {
        $names = [];

        foreach ($parameters as $parameter) {
            if (str_contains($parameter, \SensitiveParameter::class) !== $marked || preg_match('/\$(\w+)/', $parameter, $match) !== 1) {
                continue;
            }

            if (!in_array($match[1], self::HELD_NAMES, true) && preg_match(self::HELD_TYPE_IN_SOURCE, $parameter) !== 1) {
                continue;
            }

            $names[] = $match[1];
        }

        return $names;
    }

    /**
     * The names of a closure's parameters.
     *
     * @param  list<string>  $parameters
     * @return list<string>
     */
    private static function namesIn(array $parameters): array
    {
        $names = [];

        foreach ($parameters as $parameter) {
            if (preg_match('/\$(\w+)/', $parameter, $match) !== 1) {
                continue;
            }

            $names[] = $match[1];
        }

        return $names;
    }

    /**
     * Each name, as `file:name`.
     *
     * @param  string  $file
     * @param  list<string>  $names
     * @return list<string>
     */
    private static function prefixed(string $file, array $names): array
    {
        return array_map(static fn (string $name): string => "{$file}:{$name}", $names);
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
     * The arguments of each `new` in the source of a class whose short name
     * matches the pattern, in order, each as its text.
     *
     * @param  string  $source
     * @param  string  $pattern
     * @return list<list<string>>
     */
    private static function argumentsOfEachNew(string $source, string $pattern): array
    {
        $tokens = self::significantTokens($source);
        $news   = [];

        foreach ($tokens as $index => $token) {
            if (!is_array($token) || $token[0] !== T_NEW) {
                continue;
            }

            $named = self::nextAfter($tokens, $index);
            $name  = $tokens[$named] ?? null;

            if (!is_array($name) || preg_match($pattern, substr((string) strrchr('\\' . $name[1], '\\'), 1)) !== 1) {
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
     * Every throwable the rule holds, from the files under `src`.
     *
     * @return list<class-string<\Throwable>>
     */
    private static function raisedExceptions(): array
    {
        /** @var list<class-string<\Throwable>> */
        return array_values(array_filter(self::scanned(), static fn (string $class): bool => is_a($class, \Throwable::class, true)));
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
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::src() . $folder, \FilesystemIterator::SKIP_DOTS)) as $file) {
                if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                    continue;
                }

                $files[] = substr($file->getPathname(), strlen(self::src()));
            }
        }

        sort($files);

        return $files;
    }

    /**
     * The source of the file, relative to `src`.
     *
     * @param  string  $file
     * @return string
     */
    private static function sourceOf(string $file): string
    {
        return (string) file_get_contents(self::src() . $file);
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
