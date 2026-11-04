<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException;
use SineMacula\Laravel\AuditLog\Keys\WrappingKey;
use SineMacula\Laravel\AuditLog\Keys\WrappingRing;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Holds every parameter of the key store's classes that carries a data key, a
 * secret, a wrapped key, a key row, a stored row or an owner to
 * `#[\SensitiveParameter]`, because with `zend.exception_ignore_args` off every
 * frame of a thrown exception keeps its arguments, private helpers included.
 *
 * The scan reads every class under `src/Keys` whenever it runs, so a class
 * added to the namespace is held to the rule without editing this test. It
 * reads a parameter by its name or by its type, must find what it expects so it
 * cannot pass by finding nothing, and is shown to flag what it should. Key ids,
 * unit digests, generations, counts and class names are not secrets, and a
 * parameter holding one is left alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class KeysSensitiveParametersTest extends TestCase
{
    /** @var string The namespace of the key store. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\Keys\\';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var list<string> The names a parameter holding a key, a secret, a wrapped key, a row or an owner goes by. */
    private const array HELD_NAMES = ['dataKey', 'secret', 'applicationKey', 'wrapped', 'sealed', 'stored', 'row', 'rows', 'owner', 'owners', 'units'];

    /** @var list<class-string> The types a parameter holding a key, a key row or an owner goes by. */
    private const array HELD_TYPES = [WrappingKey::class, IntegrityKey::class, SubjectKeyRow::class, Reference::class, KeyUnit::class];

    /** @var list<class-string> The classes the scan must find a held parameter in. */
    private const array MUST_HOLD_ONE = [KeySettings::class, KeyUnit::class, LocalKeyWrapper::class, WrappingKey::class, WrappingRing::class];

    /** @var list<string> The parameters the scan must find, as `class::method.parameter`. */
    private const array MUST_FIND = [
        KeySettings::class . '::secret.secret',
        KeyUnit::class . '::__construct.owner',
        KeyUnit::class . '::__construct.tenant',
        LocalKeyWrapper::class . '::wrap.dataKey',
        LocalKeyWrapper::class . '::unwrap.wrapped',
        LocalKeyWrapper::class . '::encrypt.key',
        LocalKeyWrapper::class . '::decrypt.sealed',
        LocalKeyWrapper::class . '::aesKey.key',
        WrappingKey::class . '::__construct.secret',
        WrappingRing::class . '::derive.applicationKey',
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
     * Every method of every class of the key store, private ones included,
     * marks a parameter that goes by the name or the type of a key, a secret, a
     * wrapped key, a row or an owner, with no exemption.
     *
     * @return void
     */
    public function testEveryKeyRowOrOwnerParameterIsMarkedSensitive(): void
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
     * parameter it must find, and reads every class of the namespace, one that
     * holds none included.
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
        self::assertContains(UnknownWrappingKeyException::class, self::scanned());
        self::assertCount(count(array_unique(self::scanned())), self::scanned());

        foreach ((array) glob(self::src() . 'Keys/*.php') as $file) {
            self::assertContains(self::NAMESPACE . basename((string) $file, '.php'), self::scanned());
        }
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
            'a wrapping key by its type'   => ['typedWrappingKey', true],
            'an integrity key by its type' => ['typedIntegrityKey', true],
            'a key row by its type'        => ['typedKeyRow', true],
            'a nullable owner'             => ['nullableOwner', true],
            'a unit by its type'           => ['typedUnit', true],
            'one of a union with a row'    => ['unionWithARow', true],
            'a string named `dataKey`'     => ['dataKey', true],
            'a string named `secret`'      => ['secret', true],
            'a string named `wrapped`'     => ['wrapped', true],
            'an array named `stored`'      => ['stored', true],
            'an array named `rows`'        => ['rows', true],
            'a list named `owners`'        => ['owners', true],
            'a list named `units`'         => ['units', true],
            'a key id'                     => ['keyId', false],
            'a wrapping key id'            => ['wrapKeyId', false],
            'a unit digest'                => ['digest', false],
            'a generation'                 => ['generation', false],
            'a context'                    => ['context', false],
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
             * @param  \SineMacula\Laravel\AuditLog\Keys\WrappingKey  $typedWrappingKey
             * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $typedIntegrityKey
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $typedKeyRow
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $nullableOwner
             * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $typedUnit
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow|string  $unionWithARow
             * @param  string  $dataKey
             * @param  string  $secret
             * @param  string  $wrapped
             * @param  array<string, string>  $stored
             * @param  list<array<string, string>>  $rows
             * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
             * @param  list<\SineMacula\Laravel\AuditLog\Keys\KeyUnit>  $units
             * @param  string  $keyId
             * @param  string  $wrapKeyId
             * @param  string  $digest
             * @param  int  $generation
             * @param  string  $context
             * @return void
             */
            public function everyKind(
                #[\SensitiveParameter]
                WrappingKey $typedWrappingKey,
                #[\SensitiveParameter]
                IntegrityKey $typedIntegrityKey,
                #[\SensitiveParameter]
                SubjectKeyRow $typedKeyRow,
                #[\SensitiveParameter]
                ?Reference $nullableOwner,
                #[\SensitiveParameter]
                KeyUnit $typedUnit,
                #[\SensitiveParameter]
                string|SubjectKeyRow $unionWithARow,
                #[\SensitiveParameter]
                string $dataKey,
                #[\SensitiveParameter]
                string $secret,
                #[\SensitiveParameter]
                string $wrapped,
                #[\SensitiveParameter]
                array $stored,
                #[\SensitiveParameter]
                array $rows,
                #[\SensitiveParameter]
                array $owners,
                #[\SensitiveParameter]
                array $units,
                string $keyId,
                string $wrapKeyId,
                string $digest,
                int $generation,
                string $context,
            ): void {}
        };

        $reflected = new \ReflectionParameter([$fixture, 'everyKind'], $parameter);

        self::assertSame($held, self::isHeld($reflected));
    }

    /**
     * A refused wrapping secret never shows in a frame of the refusal: the
     * frame holds the sensitive wrapper where the secret was.
     *
     * @return void
     */
    public function testAStackFrameOfAKeyHidesItsSecret(): void
    {
        try {
            new WrappingKey('w1', 'short s3cr3t');

            self::fail('Expected the short secret to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frame = $exception->getTrace()[0];

            self::assertSame(WrappingKey::class, $frame['class'] ?? null);
            self::assertInstanceOf(\SensitiveParameterValue::class, ($frame['args'] ?? [])[1] ?? null);
            self::assertStringNotContainsString('s3cr3t', print_r($frame, true));
        }
    }

    /**
     * A failed unwrap through the ring never shows the wrapped key, the ring's
     * application key or its derived secret in a frame of the key store.
     *
     * @return void
     */
    public function testAStackFrameOfAnUnwrapHidesTheKeys(): void
    {
        $config  = new Repository(['audit-log' => ['privacy' => []], 'app' => ['key' => 'application key with s3cr3t inside!']]);
        $wrapper = new LocalKeyWrapper(new WrappingRing(new KeySettings($config, new IntegritySettings($config))));
        $wrapped = $wrapper->wrap(str_repeat('k', 32), $wrapper->currentKeyId(), 'context');

        try {
            $wrapper->unwrap($wrapped, $wrapper->currentKeyId(), 'another context');

            self::fail('Expected the unwrap to fail.');
        } catch (\UnexpectedValueException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => str_starts_with($frame['class'] ?? '', self::NAMESPACE));
            $shown  = print_r($frames, true);

            self::assertNotSame([], $frames);

            foreach ([$wrapped, 's3cr3t', str_repeat('k', 32)] as $hidden) {
                self::assertStringNotContainsString($hidden, $shown);
            }
        }
    }

    /**
     * The parameters of the class's own methods that the rule holds; none for a
     * method PHP or a framework class declares, since neither can be marked.
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
        if (in_array($parameter->getName(), self::HELD_NAMES, true)) {
            return true;
        }

        $type  = $parameter->getType();
        $types = $type instanceof \ReflectionNamedType ? [$type] : ($type instanceof \ReflectionUnionType ? $type->getTypes() : []);

        foreach ($types as $member) {
            if ($member instanceof \ReflectionNamedType && in_array($member->getName(), self::HELD_TYPES, true)) {
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
     * Every class under `src/Keys`, nested folders included, read from its
     * path, in order.
     *
     * @return list<class-string>
     */
    private static function scanned(): array
    {
        $root    = self::src() . 'Keys/';
        $classes = [];

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            /** @var class-string $class */
            $class     = self::NAMESPACE . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -strlen('.php')));
            $classes[] = $class;
        }

        sort($classes);

        return $classes;
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
