<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldPath;
use SineMacula\Laravel\AuditLog\Privacy\ByteBudget;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\IpMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\KeyTokenizer;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\PathMasker;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Privacy\SealingScope;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Concerns\FillsAmbientContext;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * Holds every parameter that carries a raw value or a raw key to
 * `#[\SensitiveParameter]`, because with `zend.exception_ignore_args` off every
 * frame of a thrown exception keeps its arguments, private helpers included: a
 * named table for the way in, and a scan of the whole privacy layer by
 * parameter name, which must find what it expects so that it cannot pass by
 * finding nothing. A concrete path holds raw keys, and a key can be an email
 * address.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SensitiveParametersTest extends TestCase
{
    /** @var string The namespace of the privacy layer. */
    private const string NAMESPACE = 'SineMacula\Laravel\AuditLog\Privacy\\';

    /** @var list<string> The names a parameter holding a raw value or a raw key goes by in the privacy layer. */
    private const array RAW_NAMES = [
        'value',
        'values',
        'node',
        'plaintext',
        'note',
        'identifier',
        'ip',
        'canonicalIp',
        'snapshot',
        'message',
        'path',
        'key',
        'tokens',
        'segments',
        'decisions',
        'candidates',
        'dataKey',
        'fieldKey',
        'wrapped',
        'envelope',
        'ciphertext',
    ];

    /** @var list<string> The parameters that go by a raw name and hold only what the package or its configuration composed, as `class::method.parameter`. */
    private const array COMPOSED_BY_THE_PACKAGE = [
        FieldEncryptionFailedException::class . '::__construct.message',
        FieldPolicy::class . '::referenceAt.segments',
        SealingScope::class . '::refuse.message',
    ];

    /** @var list<class-string> The classes the scan must find a raw parameter in. */
    private const array MUST_HOLD_ONE = [
        Redactor::class,
        FieldPolicy::class,
        ByteBudget::class,
        IdentifierHasher::class,
        IpMinimiser::class,
        EnvelopeSealer::class,
        NoFieldEncrypter::class,
        Minimised::class,
        RecordMinimiser::class,
        KeyCeiling::class,
        KeyTokenizer::class,
        PathMasker::class,
        EncryptedField::class,
        FieldReading::class,
        TypedPlaintext::class,
        FieldContext::class,
        FieldCipher::class,
    ];

    /**
     * Rows of `[class, method, parameter]`: where a raw value enters the
     * package and each helper it passes through on the way to the privacy
     * layer.
     *
     * @return iterable<string, array{0: class-string, 1: string, 2: string}>
     */
    public static function provideRawParameters(): iterable
    {
        yield from [
            'the properties given to a builder'   => [PendingRecord::class, 'withProperties', 'properties'],
            'the identifier given to a builder'   => [PendingRecord::class, 'withIdentifier', 'identifier'],
            'the note given to a builder'         => [PendingRecord::class, 'withNote', 'text'],
            'the note as it is cleaned'           => [PendingRecord::class, 'note', 'text'],
            'the values whose keys are checked'   => [PendingRecord::class, 'checkKeys', 'values'],
            'the values holding a reserved key'   => [PendingRecord::class, 'holdsReservedKey', 'values'],
            'the context filled on a builder'     => [PendingRecord::class, 'fillContext', 'context'],
            'the credential a builder is given'   => [PendingRecord::class, 'usingCredential', 'credentialId'],
            'the context a contributor fills'     => [Contribution::class, 'fillContext', 'context'],
            'the properties given to a recorder'  => [Recorder::class, 'record', 'properties'],
            'the builder a recorder writes'       => [Recorder::class, 'write', 'pending'],
            'the builder a record is made from'   => [AuditRecord::class, 'fromPending', 'pending'],
            'the value normalised'                => [ValueNormaliser::class, 'normalise', 'value'],
            'the value at a depth'                => [ValueNormaliser::class, 'value', 'value'],
            'the object normalised'               => [ValueNormaliser::class, 'object', 'value'],
            'the array normalised'                => [ValueNormaliser::class, 'collection', 'value'],
            'the list normalised'                 => [ValueNormaliser::class, 'list', 'value'],
            'the map normalised'                  => [ValueNormaliser::class, 'map', 'value'],
            'the scalar normalised'               => [ValueNormaliser::class, 'scalar', 'value'],
            'the plaintext an encrypter is given' => [FieldEncrypter::class, 'encrypt', 'plaintext'],
            'the value of a secret setting'       => [SecretSetting::class, 'decode', 'value'],
            'the properties a snapshot holds'     => [PendingSnapshot::class, '__construct', 'properties'],
            'the note a snapshot holds'           => [PendingSnapshot::class, '__construct', 'note'],
            'the context a snapshot holds'        => [PendingSnapshot::class, '__construct', 'context'],
            'the identifier a snapshot holds'     => [PendingSnapshot::class, '__construct', 'identifier'],
            'the address a snapshot holds'        => [PendingSnapshot::class, '__construct', 'ip'],
            'the property collisions it holds'    => [PendingSnapshot::class, '__construct', 'collisions'],
            'the context collisions it holds'     => [PendingSnapshot::class, '__construct', 'contextCollisions'],
            'the snapshot an origin is read from' => [AuditRecord::class, 'originOf', 'snapshot'],
            'the address a builder is filled'     => [FillsAmbientContext::class, 'fillClient', 'ip'],
            'the user agent a builder is filled'  => [FillsAmbientContext::class, 'fillClient', 'userAgent'],
            'the address a contributor fills'     => [Contribution::class, 'fillClient', 'ip'],
            'the user agent a contributor fills'  => [Contribution::class, 'fillClient', 'userAgent'],
            'the path a rule is chosen for'       => [EventDefinition::class, 'ruleFor', 'path'],
            'the path a rule is sought beneath'   => [EventDefinition::class, 'ruleBeneath', 'path'],
            'the path a handling is chosen for'   => [EventDefinition::class, 'handlingFor', 'path'],
            'the path a pattern is matched to'    => [FieldPath::class, 'matches', 'path'],
            'the owner a value is handled for'    => [FieldPolicy::class, 'handled', 'owner'],
            'the owner a value is sealed for'     => [FieldPolicy::class, 'sealed', 'owner'],
            'the owner a sealer is given'         => [EnvelopeSealer::class, 'seal', 'owner'],
            'the subjects of a bulk operation'    => [Manifest::class, 'of', 'subjects'],
            'each subject of a bulk operation'    => [Manifest::class, 'referenceOf', 'subject'],
            'the members a manifest encodes'      => [Manifest::class, 'encode', 'members'],
            'the plaintext a manifest reads'      => [Manifest::class, 'readCanonical', 'plaintext'],
            'the members a manifest holds'        => [Manifest::class, '__construct', 'canonical'],
            'the manifest a builder is given'     => [PendingRecord::class, 'withManifest', 'manifest'],
            'the manifest an attachment seals'    => [Attachment::class, 'sealed', 'manifest'],
            'the members an attachment holds'     => [Attachment::class, '__construct', 'members'],
            'the attachment a bundle carries'     => [Attachment::class, 'fromEnvelope', 'fields'],
            'the attachment a record is built on' => [AuditRecord::class, 'fromPending', 'attachment'],
            'the attachment a record is read on'  => [AuditRecord::class, 'fromEnvelope', 'attachment'],
            'the attachment a record holds'       => [AuditRecord::class, '__construct', 'attachment'],
            'the segments of an encrypted field'  => [EncryptedField::class, '__construct', 'segments'],
            'the ciphertext a field holds'        => [EncryptedField::class, '__construct', 'ciphertext'],
            'the segments a field is read at'     => [EncryptedField::class, 'fromEnvelope', 'segments'],
            'the envelope a field is read from'   => [EncryptedField::class, 'fromEnvelope', 'envelope'],
            'the value a reader reveals'          => [FieldReading::class, 'revealed', 'value'],
            'the value a reading holds'           => [FieldReading::class, '__construct', 'value'],
            'the fields a reader is given'        => [FieldReader::class, 'readAll', 'fields'],
            'the fields the sealed reader reads'  => [SealedFieldReader::class, 'readAll', 'fields'],
            'the value made typed plaintext'      => [TypedPlaintext::class, 'encode', 'value'],
            'the typed plaintext decoded'         => [TypedPlaintext::class, 'decode', 'plaintext'],
            'the path of a field context'         => [FieldContext::class, '__construct', 'path'],
            'the owners of a field context'       => [FieldContext::class, '__construct', 'owners'],
            'the data key a field is sealed with' => [FieldCipher::class, 'seal', 'dataKey'],
            'the plaintext a field cipher seals'  => [FieldCipher::class, 'seal', 'plaintext'],
            'the data key a field is opened with' => [FieldCipher::class, 'open', 'dataKey'],
            'the ciphertext a field cipher opens' => [FieldCipher::class, 'open', 'ciphertext'],
            'the data key a field key comes from' => [FieldCipher::class, 'fieldKey', 'dataKey'],
            'the data key a wrapper wraps'        => [KeyWrapper::class, 'wrap', 'dataKey'],
            'the wrapped key a wrapper unwraps'   => [KeyWrapper::class, 'unwrap', 'wrapped'],
        ];
    }

    /**
     * Each parameter in the table is marked, so no frame of a thrown exception
     * can show what it holds.
     *
     * @param  class-string  $class
     * @param  string  $method
     * @param  string  $parameter
     * @return void
     */
    #[DataProvider('provideRawParameters')]
    public function testEveryRawValueParameterIsSensitive(string $class, string $method, string $parameter): void
    {
        $reflected = new \ReflectionParameter([$class, $method], $parameter);

        self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), "{$class}::{$method}() \${$parameter}");
    }

    /**
     * Every method of every class in the privacy layer, private ones included,
     * marks a parameter that goes by one of the raw names, and the scan finds
     * one in each class that must hold one.
     *
     * @return void
     */
    public function testThePrivacyLayersRawParametersAreAllSensitive(): void
    {
        $unmarked = [];
        $found    = [];

        foreach (self::rawParameters() as [$class, $method, $parameter]) {
            $found[$class] = true;

            if ($parameter->getAttributes(\SensitiveParameter::class) !== []) {
                continue;
            }

            $unmarked[] = "{$class}::{$method}() \${$parameter->getName()}";
        }

        self::assertSame([], $unmarked);
        self::assertSame([], array_values(array_diff(self::MUST_HOLD_ONE, array_keys($found))));
    }

    /**
     * The scan reads the whole namespace, the classes nested in its folders
     * included, so a class added to the layer is held to the rule without
     * editing this test.
     *
     * @return void
     */
    public function testTheScanReadsEveryClassOfTheLayer(): void
    {
        $classes = self::privacyClasses();

        foreach (self::MUST_HOLD_ONE as $class) {
            self::assertContains($class, $classes);
        }

        self::assertContains(self::NAMESPACE . 'Enums\IpMode', $classes);
        self::assertCount(count(array_unique($classes)), $classes);
    }

    /**
     * What PHP itself declares is out of the scan's reach and is not held to
     * it: an enum's `from($value)` cannot carry an attribute.
     *
     * @return void
     */
    public function testTheScanLeavesOutWhatPhpDeclares(): void
    {
        $methods = array_map(static fn (array $row): string => $row[1], self::rawParameters());

        self::assertNotContains('from', $methods);
        self::assertNotContains('tryFrom', $methods);
    }

    /**
     * The message of the exception a failed encrypter is reported with is let
     * go because only its own named constructor can call it, with a message it
     * composes from the encrypter's class. It is private, so nothing else can
     * pass it a raw value.
     *
     * @return void
     */
    public function testTheExemptMessageHoldsNoRawValue(): void
    {
        $constructor = new \ReflectionMethod(FieldEncryptionFailedException::class, '__construct');

        self::assertTrue($constructor->isPrivate());
        self::assertSame(['message'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $constructor->getParameters()));
    }

    /**
     * The message a sealing scope refuses with is let go because the method is
     * private and every call passes it a literal the package wrote, so nothing
     * else can pass it a raw value.
     *
     * @return void
     */
    public function testTheScopesRefusalHoldsNoRawValue(): void
    {
        $refuse = new \ReflectionMethod(SealingScope::class, 'refuse');
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Privacy/SealingScope.php');

        self::assertTrue($refuse->isPrivate());
        self::assertSame(2, preg_match_all('/self::refuse\(/', $source));
        self::assertSame(2, preg_match_all('/self::refuse\(\'[^\'$]+\'\);/', $source));
    }

    /**
     * Each exemption names a parameter that exists and goes by a raw name, so
     * an entry left behind by a rename fails instead of silently excusing
     * nothing.
     *
     * @return void
     */
    public function testEveryExemptionNamesARawParameter(): void
    {
        foreach (self::COMPOSED_BY_THE_PACKAGE as $exemption) {
            [$class, $member]     = explode('::', $exemption);
            [$method, $parameter] = explode('.', $member);

            self::assertContains($parameter, self::RAW_NAMES, $exemption);
            self::assertSame($parameter, (new \ReflectionParameter([$class, $method], $parameter))->getName(), $exemption);
        }
    }

    /**
     * The scan holds a concrete path to the rule through every helper that
     * walks one, so a raw dynamic key cannot be left in a frame of the walker
     * by adding one more of them, through the encrypted field that carries one
     * to a field reader as its segments, and through the context and the cipher
     * that bind an envelope to one. Each is found, whatever else holds a path.
     *
     * @return void
     */
    public function testTheScanReachesTheWalkersPaths(): void
    {
        $paths = array_values(array_filter(self::rawParameters(), static fn (array $row): bool => in_array($row[2]->getName(), ['path', 'segments'], true)));

        $expected = [
            [EncryptedField::class, '__construct'],
            [EncryptedField::class, 'fromEnvelope'],
            [FieldCipher::class, 'additionalData'],
            [FieldCipher::class, 'open'],
            [FieldCipher::class, 'seal'],
            [FieldContext::class, '__construct'],
            [FieldContext::class, 'checkedPath'],
            [FieldPolicy::class, 'retained'],
            [FieldPolicy::class, 'selected'],
            [FieldPolicy::class, 'walk'],
            [PathMasker::class, 'context'],
            [PathMasker::class, 'property'],
        ];

        $found = self::sortedClassesAndMethods($paths);

        self::assertSame([], array_values(array_filter($expected, static fn (array $method): bool => !in_array($method, $found, true))));
    }

    /**
     * The closure the walker hands every field to takes the concrete path too,
     * and a closure is out of a scan of methods, so its marking is read from
     * the source.
     *
     * @return void
     */
    public function testTheWalkersClosureMarksItsPath(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Privacy/FieldPolicy.php');

        self::assertMatchesRegularExpression('/static function \(\s*#\[\\\SensitiveParameter\]\s*mixed \$value,\s*#\[\\\SensitiveParameter\]\s*array \$path,/', $source);
    }

    /**
     * Each row's class and method, sorted, so a list can be compared whole.
     *
     * @param  list<array{0: class-string, 1: string, 2: \ReflectionParameter}>  $rows
     * @return list<array{0: class-string, 1: string}>
     */
    private static function sortedClassesAndMethods(array $rows): array
    {
        $named = array_map(static fn (array $row): array => [$row[0], $row[1]], $rows);

        sort($named);

        return $named;
    }

    /**
     * Each parameter of the privacy layer that goes by a raw name, with its
     * class and its method.
     *
     * @return list<array{0: class-string, 1: string, 2: \ReflectionParameter}>
     */
    private static function rawParameters(): array
    {
        $parameters = [];

        foreach (self::privacyClasses() as $class) {
            foreach ((new \ReflectionClass($class))->getMethods() as $method) {
                array_push($parameters, ...array_map(
                    static fn (\ReflectionParameter $parameter): array => [$class, $method->getName(), $parameter],
                    self::rawParametersOf($class, $method),
                ));
            }
        }

        return $parameters;
    }

    /**
     * The parameters of the method that go by a raw name, none for a method PHP
     * declares, but for those the package composes itself.
     *
     * @param  class-string  $class
     * @param  \ReflectionMethod  $method
     * @return list<\ReflectionParameter>
     */
    private static function rawParametersOf(string $class, \ReflectionMethod $method): array
    {
        if ($method->isInternal()) {
            return [];
        }

        return array_values(array_filter(
            $method->getParameters(),
            static fn (\ReflectionParameter $parameter): bool => in_array($parameter->getName(), self::RAW_NAMES, true)
                && !in_array($class . '::' . $method->getName() . '.' . $parameter->getName(), self::COMPOSED_BY_THE_PACKAGE, true),
        ));
    }

    /**
     * The class of every file under `src/Privacy`, read from its path.
     *
     * @return list<class-string>
     */
    private static function privacyClasses(): array
    {
        $root    = dirname(__DIR__, 3) . '/src/Privacy/';
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
}
