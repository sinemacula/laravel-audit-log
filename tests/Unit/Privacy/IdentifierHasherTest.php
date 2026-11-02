<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;

/**
 * Unit tests for the keyed hashes: the golden vector of each domain, the key
 * they derive from, how a value is normalised, the separation of the domains,
 * and the values no failure ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierHasher::class)]
final class IdentifierHasherTest extends TestCase
{
    /** @var string The root key of the golden vectors. */
    private const string ROOT_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The second root key of the golden vectors. */
    private const string OTHER_ROOT_KEY = 'fedcba9876543210fedcba9876543210';

    /** @var string The golden hash of `alice@example.com` as an identifier. */
    private const string ALICE_IDENTIFIER = '13f5820b5aa0c097:680a1e05e07bcd260a8f8eda495c167100f4413f08ac4a5d980061e30cd51abf';

    /** @var string The golden hash of `alice@example.com` as a field. */
    private const string ALICE_FIELD = 'bddef478b371e305:bb1b2053d57f40d75b983080b46ba3adb13da822fc435d7df67188df4e4b2a6c';

    /** @var string The refusal of a malformed explicit key. */
    private const string MALFORMED_KEY = '`audit-log.redaction.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes.';

    /** @var string A value that must appear in no message and no stack trace. */
    private const string PLANTED = 's3cr3t@example.com';

    /**
     * Rows of `[domain, value, result]`: every golden vector under the first
     * root key. Each result was computed independently of the class.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: 'field'|'identifier'|'ip', 1: array<array-key, mixed>|bool|int|string|null, 2: string}>
     */
    public static function provideGoldenVectors(): iterable
    {
        yield from [
            'identifier, an email address' => ['identifier', 'alice@example.com', self::ALICE_IDENTIFIER],
            'identifier, an opaque value'  => ['identifier', 'A1234', '13f5820b5aa0c097:63863f5bbafd0b7fa8cea371edee721e5f64d150426d20745bd6d957c275eebd'],
            'field, an email address'      => ['field', 'alice@example.com', self::ALICE_FIELD],
            'field, an integer'            => ['field', 42, 'bddef478b371e305:c4f6000c0abe3764786c6ed1c7f5781e45775b77cf64f9ad56112e00d66ff657'],
            'field, a boolean'             => ['field', true, 'bddef478b371e305:8533bb2161efc5222a6a066e8d53e67d093f52d4d91c980242415057e20f0cd9'],
            'field, null'                  => ['field', null, 'bddef478b371e305:24572793d781304842a177ed85f32599a6b7ce440f17a2a9519f5f33b4693826'],
            'field, a map'                 => ['field', ['a' => 1, 'b' => ['x']], 'bddef478b371e305:d706b86a7bd81336ee56b8c1f3f81faa7569925305a65b8d5b40b9118f63b79c'],
            'ip, IPv4'                     => ['ip', '203.0.113.7', '05d70d576b2b05d5:d8cd13f098906335536b7d3cff22a70c382c0d3a2a4c38cbd2815e6a456118e1'],
            'ip, IPv6'                     => ['ip', '2001:db8::1', '05d70d576b2b05d5:70ba167d07452e86911ea28f6f4067e2c9963f07d216a158ee83f07f6371c95a'],
            'ip, a longer IPv6'            => ['ip', '2001:db8:abcd:12::1', '05d70d576b2b05d5:cc7a0619e29485b78ffeb1ab29c86e6585cf1b9693ecff15b791f519884383dd'],
        ];
    }

    /**
     * Each domain gives exactly the pinned hash, so a change to a key, a label,
     * the format or the encoding fails here.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'field'|'identifier'|'ip'  $domain
     * @param  array<array-key, mixed>|bool|int|string|null  $value
     * @param  string  $result
     * @return void
     */
    #[DataProvider('provideGoldenVectors')]
    public function testTheGoldenVectors(string $domain, array|bool|int|string|null $value, string $result): void
    {
        $hasher = self::hasher();

        $hash = match ($domain) {
            'identifier' => is_string($value) ? $hasher->identifier($value) : null,
            'field'      => $hasher->field($value),
            'ip'         => is_string($value) ? $hasher->ip($value) : null,
        };

        self::assertSame($result, $hash);
    }

    /**
     * The golden vector under the second root key.
     *
     * @return void
     */
    public function testTheGoldenVectorOfTheOtherKey(): void
    {
        self::assertSame(
            'd94587ec434ae531:1236c35dd70a9bd225d371b4c6a8cc42bc3e3f02a49157ad86d73fc16a7c770f',
            self::hasher(self::OTHER_ROOT_KEY)->identifier('alice@example.com'),
        );
    }

    /**
     * Every hash is a fingerprint of 16 hex characters and an HMAC of 64, 81
     * bytes in all, whatever the value's size.
     *
     * @return void
     */
    public function testTheFormatIsAFingerprintAndAnHmac(): void
    {
        $hasher = self::hasher();

        foreach ([$hasher->identifier('alice@example.com'), $hasher->field(str_repeat('x', 5000)), $hasher->field(null), $hasher->ip('203.0.113.7')] as $hash) {
            self::assertIsString($hash);
            self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $hash);
            self::assertSame(81, strlen($hash));
        }
    }

    /**
     * The HKDF labels are pinned: changing one orphans every stored hash.
     *
     * @return void
     */
    public function testTheInfoLabelsArePinned(): void
    {
        self::assertSame('sinemacula/audit-log:identifier:v1', IdentifierHasher::IDENTIFIER_INFO);
        self::assertSame('sinemacula/audit-log:field:v1', IdentifierHasher::FIELD_INFO);
        self::assertSame('sinemacula/audit-log:ip:v1', IdentifierHasher::IP_INFO);
    }

    /**
     * An application key derives each domain's key as an explicit key of the
     * same bytes does, so both routes give the golden vector.
     *
     * @return void
     */
    public function testAnApplicationKeyDerivesLikeAnExplicitKeyOfTheSameBytes(): void
    {
        $derived = self::hasherOf(['app' => ['key' => self::ROOT_KEY]]);

        self::assertSame(self::ALICE_IDENTIFIER, $derived->identifier('alice@example.com'));
        self::assertSame(self::ALICE_FIELD, $derived->field('alice@example.com'));
        self::assertSame(self::hasher()->ip('203.0.113.7'), $derived->ip('203.0.113.7'));
    }

    /**
     * An explicit key is preferred to the application key.
     *
     * @return void
     */
    public function testAnExplicitKeyIsPreferredToTheApplicationKey(): void
    {
        $hasher = self::hasherOf([
            'app'       => ['key' => self::OTHER_ROOT_KEY],
            'audit-log' => ['redaction' => ['key' => self::ROOT_KEY]],
        ]);

        self::assertSame(self::ALICE_IDENTIFIER, $hasher->identifier('alice@example.com'));
    }

    /**
     * A key given as base64 hashes as the same bytes given raw, by either
     * route.
     *
     * @return void
     */
    public function testBase64AndRawGiveTheSameHash(): void
    {
        $encoded = 'base64:' . base64_encode(self::ROOT_KEY);

        self::assertSame(self::ALICE_IDENTIFIER, self::hasher($encoded)->identifier('alice@example.com'));
        self::assertSame(self::ALICE_IDENTIFIER, self::hasherOf(['app' => ['key' => $encoded]])->identifier('alice@example.com'));
    }

    /**
     * Another key gives another fingerprint in every domain, so a change of key
     * is visible in the hash itself.
     *
     * @return void
     */
    public function testTheFingerprintChangesWithTheKey(): void
    {
        $first  = self::hasher();
        $second = self::hasher(self::OTHER_ROOT_KEY);

        self::assertNotSame(self::fingerprint($first->identifier('x')), self::fingerprint($second->identifier('x')));
        self::assertNotSame(self::fingerprint($first->field('x')), self::fingerprint($second->field('x')));
        self::assertNotSame(self::fingerprint($first->ip('x')), self::fingerprint($second->ip('x')));
    }

    /**
     * The fingerprint depends on the key and never on the value.
     *
     * @return void
     */
    public function testTheFingerprintIgnoresTheValue(): void
    {
        $hasher = self::hasher();

        self::assertSame(self::fingerprint($hasher->identifier('x')), self::fingerprint($hasher->identifier('y')));
        self::assertNotSame($hasher->identifier('x'), $hasher->identifier('y'));
    }

    /**
     * One key and one value give one hash, across instances.
     *
     * @return void
     */
    public function testTheHashIsDeterministicPerKey(): void
    {
        self::assertSame(self::hasher()->identifier('A1234'), self::hasher()->identifier('A1234'));
        self::assertSame(self::hasher()->field(['a' => 1]), self::hasher()->field(['a' => 1]));
        self::assertSame(self::hasher()->ip('203.0.113.7'), self::hasher()->ip('203.0.113.7'));
    }

    /**
     * The key is read on every call and kept nowhere, so a changed key applies
     * to the next hash.
     *
     * @return void
     */
    public function testTheKeyIsReadOnEveryCall(): void
    {
        $config = new Repository(['audit-log' => ['redaction' => ['key' => self::ROOT_KEY]]]);
        $hasher = new IdentifierHasher(new RedactionSettings($config));

        self::assertSame(self::ALICE_IDENTIFIER, $hasher->identifier('alice@example.com'));

        $config->set('audit-log.redaction.key', self::OTHER_ROOT_KEY);

        self::assertNotSame(self::ALICE_IDENTIFIER, $hasher->identifier('alice@example.com'));
    }

    /**
     * Rows of `[identifier]`: the spellings of one email address.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSpellingsOfAnIdentifier(): iterable
    {
        yield from [
            'padded'            => ['  alice@example.com '],
            'mixed case'        => ['Alice@Example.COM'],
            'a trailing line'   => ["alice@example.com\n"],
            'a leading tab'     => ["\talice@example.com"],
            'a NUL byte within' => ["alice@exam\0ple.com"],
            'bidirectional'     => ["\u{202E}alice@example.com"],
            'all of it'         => [" \tALICE@EXAMPLE.COM\r\n"],
        ];
    }

    /**
     * Each spelling normalises to one value and one hash.
     *
     * @param  string  $identifier
     * @return void
     */
    #[DataProvider('provideSpellingsOfAnIdentifier')]
    public function testNormalisesAnIdentifier(string $identifier): void
    {
        self::assertSame('alice@example.com', IdentifierHasher::normalised($identifier));
        self::assertSame(self::ALICE_IDENTIFIER, self::hasher()->identifier($identifier));
    }

    /**
     * Rows of `[value]`: values that are not email-shaped, in mixed case.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideValuesKeepingTheirCase(): iterable
    {
        yield from [
            'an opaque value'       => ['A1234'],
            'two at signs'          => ['A@b@C'],
            'a space before the at' => ['A b@C'],
            'a space after the at'  => ['A@b C'],
            'nothing before the at' => ['@ABC'],
            'nothing after the at'  => ['ABC@'],
            'only an at sign'       => ['@'],
        ];
    }

    /**
     * Only a value of exactly one `@`, with no whitespace and something on each
     * side of it, is lower-cased.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideValuesKeepingTheirCase')]
    public function testOnlyAnEmailShapedValueIsLowerCased(string $value): void
    {
        self::assertSame($value, IdentifierHasher::normalised($value));
    }

    /**
     * Lower-casing is multibyte, so an address with a non-ASCII letter has one
     * hash however it is written.
     *
     * @return void
     */
    public function testAnEmailAddressIsLowerCasedAsUnicode(): void
    {
        self::assertSame('älice@example.com', IdentifierHasher::normalised('ÄLICE@EXAMPLE.COM'));
    }

    /**
     * Invalid UTF-8 is repaired rather than failing, so it can still be hashed.
     *
     * @return void
     */
    public function testInvalidUtf8IsRepaired(): void
    {
        self::assertSame("a\u{FFFD}b", IdentifierHasher::normalised("a\xFFb"));
        self::assertSame(self::hasher()->identifier("a\u{FFFD}b"), self::hasher()->identifier("a\xFFb"));
    }

    /**
     * Rows of `[identifier]`: values with nothing left once normalised.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBlankIdentifiers(): iterable
    {
        yield from [
            'empty'       => [''],
            'spaces'      => ['   '],
            'a NUL byte'  => ["\0"],
            'a line feed' => ["\n"],
            'a mix'       => [" \0\t\r\n"],
        ];
    }

    /**
     * A blank identifier has no hash, and that is not an error.
     *
     * @param  string  $identifier
     * @return void
     */
    #[DataProvider('provideBlankIdentifiers')]
    public function testABlankIdentifierHasNoHash(string $identifier): void
    {
        self::assertNull(self::hasher()->identifier($identifier));
    }

    /**
     * A blank identifier reads no key, so it cannot fail a sign-in form's post
     * for a key the record would not have used.
     *
     * @return void
     */
    public function testABlankIdentifierNeedsNoKey(): void
    {
        self::assertNull(self::hasherOf([])->identifier('   '));
    }

    /**
     * A field is normalised as an identifier is, and its hash does not depend
     * on how the value was written.
     *
     * @return void
     */
    public function testAFieldIsNormalised(): void
    {
        self::assertSame(self::ALICE_FIELD, self::hasher()->field('  Alice@Example.COM '));
        self::assertSame(self::hasher()->field('A1234'), self::hasher()->field(" A1234\n"));
    }

    /**
     * A blank field still has a hash: `field()` always gives a string, and a
     * value that was blank is the same pseudonym however it was padded.
     *
     * @return void
     */
    public function testABlankFieldStillHashes(): void
    {
        self::assertSame(self::hasher()->field(''), self::hasher()->field('   '));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', self::hasher()->field(''));
    }

    /**
     * An address is hashed exactly as given: making it canonical is the
     * caller's work, and this adds no second normalisation.
     *
     * @return void
     */
    public function testAnIpIsHashedAsGiven(): void
    {
        $hasher = self::hasher();

        self::assertNotSame($hasher->ip('2001:db8::1'), $hasher->ip('2001:DB8::1'));
        self::assertNotSame($hasher->ip('203.0.113.7'), $hasher->ip(' 203.0.113.7'));
    }

    /**
     * One value hashed in each domain gives three unrelated hashes, with three
     * fingerprints, under one configured key.
     *
     * @return void
     */
    public function testTheThreeDomainsNeverAgree(): void
    {
        $hasher = self::hasher();

        $hashes = [$hasher->identifier('203.0.113.7'), $hasher->field('203.0.113.7'), $hasher->ip('203.0.113.7')];

        self::assertCount(3, array_unique($hashes));
        self::assertCount(3, array_unique(array_map(self::fingerprint(...), $hashes)));
    }

    /**
     * Rows of `[value]`: values a pseudonym and an identifier could both hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSharedValues(): iterable
    {
        yield from [
            'an email address' => ['alice@example.com'],
            'an opaque value'  => ['A1234'],
        ];
    }

    /**
     * A pseudonymised field never correlates with a sign-in identifier: their
     * HMACs differ too, not only their fingerprints.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideSharedValues')]
    public function testAPseudonymNeverEqualsAnIdentifierHash(string $value): void
    {
        $identifier = self::hasher()->identifier($value);
        $field      = self::hasher()->field($value);

        self::assertIsString($identifier);
        self::assertNotSame($identifier, $field);
        self::assertNotSame(substr($identifier, 17), substr($field, 17));
    }

    /**
     * The complete value is hashed and nothing is cut, so two long values that
     * share a prefix past the retained string cap stay distinct.
     *
     * @return void
     */
    public function testAFieldHashesItsCompleteValue(): void
    {
        $prefix = str_repeat('x', 1500);
        $first  = $prefix . str_repeat('a', 500);
        $second = $prefix . str_repeat('b', 500);

        self::assertSame(2000, strlen($first));
        self::assertNotSame(self::hasher()->field($first), self::hasher()->field($second));
        self::assertNotSame(self::hasher()->identifier($first), self::hasher()->identifier($second));
    }

    /**
     * A container hashes its canonical encoding, so the order of a map's keys
     * changes nothing and a list is told from a map of the same member.
     *
     * @return void
     */
    public function testAContainerHashesItsCanonicalEncoding(): void
    {
        $hasher = self::hasher();
        $golden = 'bddef478b371e305:d706b86a7bd81336ee56b8c1f3f81faa7569925305a65b8d5b40b9118f63b79c';

        self::assertSame($golden, $hasher->field(['a' => 1, 'b' => ['x']]));
        self::assertSame($golden, $hasher->field(['b' => ['x'], 'a' => 1]));

        self::assertSame('bddef478b371e305:e88f77b8f26f11b3db3e8db750769b3c2acfe40872bc3903774c4bd333dce877', $hasher->field(['x']));
        self::assertSame('bddef478b371e305:75418cae4f426e7ab6594ed9fa1a19b2306bd4a5bdf3d937842ed705d1bbde37', $hasher->field([1 => 'x']));
    }

    /**
     * A string inside a container is hashed as stored, without the
     * normalisation a string on its own has.
     *
     * @return void
     */
    public function testAStringWithinAContainerIsNotNormalised(): void
    {
        self::assertNotSame(self::hasher()->field(['Alice@Example.COM']), self::hasher()->field(['alice@example.com']));
    }

    /**
     * Anything but a string is hashed as its canonical encoding, which is what
     * a bare string spelling that encoding hashes as too.
     *
     * @return void
     */
    public function testNonStringsUseTheCanonicalEncoding(): void
    {
        $hasher = self::hasher();

        self::assertSame($hasher->field('42'), $hasher->field(42));
        self::assertSame($hasher->field('true'), $hasher->field(true));
        self::assertSame($hasher->field('false'), $hasher->field(false));
        self::assertSame($hasher->field('null'), $hasher->field(null));
        self::assertSame($hasher->field('[]'), $hasher->field([]));
    }

    /**
     * A value with no canonical encoding is refused, naming its type and never
     * what it holds. The normaliser leaves no such value, so this is a
     * programming error.
     *
     * @return void
     */
    public function testAValueWithNoCanonicalEncodingIsRefusedWithoutItsValue(): void
    {
        try {
            self::hasher()->field(['planted' => self::PLANTED, 'number' => 1.5]);
            self::fail('Expected the value to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A float cannot be encoded canonically; the package stores decimals as strings.', $exception->getMessage());
        }
    }

    /**
     * A malformed explicit key fails every domain closed, with a sound
     * application key beside it, and never falls back to that key.
     *
     * @return void
     */
    public function testAMalformedExplicitKeyFailsClosedNeverFallingBack(): void
    {
        $hasher = self::hasherOf([
            'app'       => ['key' => self::ROOT_KEY],
            'audit-log' => ['redaction' => ['key' => 'too short']],
        ]);

        foreach (self::callsOfEachDomain($hasher) as $call) {
            try {
                $call();
                self::fail('Expected the key to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::MALFORMED_KEY, $exception->getMessage());
            }
        }
    }

    /**
     * With neither key set there is nothing to derive from, and that fails.
     *
     * @return void
     */
    public function testAMissingKeyFails(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`app.key` must be set to derive the redaction key when `audit-log.redaction.key` is empty.');

        self::hasherOf([])->identifier('alice@example.com');
    }

    /**
     * Rows of `[method, parameter]`: every parameter that holds a raw value.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRawValueParameters(): iterable
    {
        yield from [
            'identifier' => ['identifier', 'identifier'],
            'field'      => ['field', 'value'],
            'ip'         => ['ip', 'canonicalIp'],
            'normalised' => ['normalised', 'value'],
            'hash'       => ['hash', 'message'],
        ];
    }

    /**
     * Every parameter that holds a raw value is marked sensitive, the private
     * hash included.
     *
     * @param  string  $method
     * @param  string  $parameter
     * @return void
     *
     * @throws \ReflectionException
     */
    #[DataProvider('provideRawValueParameters')]
    public function testTheRawValueParametersAreSensitive(string $method, string $parameter): void
    {
        self::assertCount(1, (new \ReflectionParameter([IdentifierHasher::class, $method], $parameter))->getAttributes(\SensitiveParameter::class));
    }

    /**
     * With arguments kept in stack traces, a failure holds neither the value
     * nor the key, whichever domain it came from.
     *
     * @return void
     */
    public function testNoFrameOfAFailureHoldsTheValueOrTheKey(): void
    {
        $hasher = self::hasherOf(['audit-log' => ['redaction' => ['key' => 'too-short-' . self::PLANTED]]]);

        foreach (self::callsOfEachDomain($hasher) as $call) {
            $ignored = ini_set('zend.exception_ignore_args', '0');

            try {
                $call();
                self::fail('Expected the key to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringNotContainsString(self::PLANTED, $exception->getMessage());
                self::assertStringNotContainsString(self::PLANTED, print_r($exception->getTrace(), true));
            } finally {
                ini_set('zend.exception_ignore_args', (string) $ignored);
            }
        }
    }

    /**
     * A hasher under the explicit root key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher
     */
    private static function hasher(#[\SensitiveParameter] string $key = self::ROOT_KEY): IdentifierHasher
    {
        return self::hasherOf(['audit-log' => ['redaction' => ['key' => $key]]]);
    }

    /**
     * A hasher reading the configuration.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher
     */
    private static function hasherOf(array $config): IdentifierHasher
    {
        return new IdentifierHasher(new RedactionSettings(new Repository($config)));
    }

    /**
     * A call of each domain, with the planted value.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @return list<\Closure(): ?string>
     */
    private static function callsOfEachDomain(IdentifierHasher $hasher): array
    {
        return [
            static fn (): ?string => $hasher->identifier(self::PLANTED),
            static fn (): string => $hasher->field(self::PLANTED),
            static fn (): string => $hasher->ip(self::PLANTED),
        ];
    }

    /**
     * The fingerprint a hash begins with.
     *
     * @param  ?string  $hash
     * @return string
     */
    private static function fingerprint(?string $hash): string
    {
        return substr((string) $hash, 0, 16);
    }
}
