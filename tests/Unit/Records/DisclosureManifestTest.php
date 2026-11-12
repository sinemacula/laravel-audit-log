<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;

/**
 * Unit tests for a read's disclosure manifest and the plaintexts it reads back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DisclosureManifest::class)]
final class DisclosureManifestTest extends TestCase
{
    /** @var string The first entry a read returned. */
    private const string FIRST = '01932b4e-8a40-7000-8000-000000000002';

    /** @var string The second entry a read returned, which sorts before the first. */
    private const string SECOND = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A nonce, as a disclosure carries one. */
    private const string NONCE = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var string The canonical form of an empty disclosure with no filter, no page and no scope, under the fixed nonce. */
    private const string EMPTY = '{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":null,"scope":null}';

    /** @var string The canonical form of an empty disclosure with no filter, no page and no scope, its nonce any. */
    private const string EMPTY_PATTERN = '/\A\{"disclosure_version":1,"filters":\[\],"members":\[\],"nonce":"[0-9a-f]{64}","page":null,"scope":null\}\z/';

    /** @var string An instant a page read after. */
    private const string AFTER = '2026-11-01T12:00:00.123456Z';

    /**
     * The canonical form is the canonical encoding of the six keys, with the
     * members in the order the read returned them.
     *
     * @return void
     */
    public function testTheCanonicalFormIsSortedKeysAndReturnedOrder(): void
    {
        $manifest = DisclosureManifest::of(['outcome' => ['success'], 'category' => null], ['tenants' => null, 'denied' => false], self::members(), [self::AFTER, self::SECOND]);
        $nonce    = self::nonceOf($manifest->canonical);

        $expected = '{"disclosure_version":1,"filters":{"category":null,"outcome":["success"]},"members":'
            . '[["' . self::FIRST . '","' . self::hmac(self::FIRST) . '"],["' . self::SECOND . '","' . self::hmac(self::SECOND) . '"]],'
            . '"nonce":"' . $nonce . '","page":["' . self::AFTER . '","' . self::SECOND . '"],"scope":{"denied":false,"tenants":null}}';

        self::assertSame($expected, $manifest->canonical);
        self::assertSame(ArtifactKind::DISCLOSURE, $manifest->kind);
        self::assertSame(2, $manifest->count);
        self::assertSame(hash('sha256', $expected), $manifest->digest);
    }

    /**
     * A read that returned nothing discloses the empty set: a valid manifest
     * counting none, whose form reads back.
     *
     * @return void
     */
    public function testTheEmptySetIsValid(): void
    {
        $manifest = DisclosureManifest::of([], null, []);

        self::assertMatchesRegularExpression(self::EMPTY_PATTERN, $manifest->canonical);
        self::assertSame(0, $manifest->count);
        self::assertSame(['count' => 0, 'digest' => $manifest->digest], DisclosureManifest::read($manifest->canonical));
        self::assertSame(['count' => 0, 'digest' => hash('sha256', self::EMPTY)], DisclosureManifest::read(self::EMPTY));
    }

    /**
     * Every disclosure carries a fresh 32-byte nonce, so its digest cannot be
     * reversed by digesting candidate filters and scopes.
     *
     * @return void
     */
    public function testEveryDisclosureHasAFreshNonce(): void
    {
        $first  = DisclosureManifest::of(['event' => null], ['tenants' => [['organisation', '7']]], []);
        $second = DisclosureManifest::of(['event' => null], ['tenants' => [['organisation', '7']]], []);

        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', self::nonceOf($first->canonical));
        self::assertNotSame(self::nonceOf($first->canonical), self::nonceOf($second->canonical));
        self::assertNotSame($first->digest, $second->digest);
        self::assertNotSame(hash('sha256', '{"disclosure_version":1,"filters":{"event":null},"members":[],"scope":{"tenants":[["organisation","7"]]}}'), $first->digest);
    }

    /**
     * Rows of `[page]`: positions a disclosure refuses: not a pair, not an
     * instant, not a lower-case UUID.
     *
     * @return iterable<string, array{0: array<array-key, string>}>
     */
    public static function provideMalformedPages(): iterable
    {
        yield from [
            'one part'       => [[self::AFTER]],
            'a map'          => [['time' => self::AFTER, 'id' => self::FIRST]],
            'not an instant' => [['2026-11-01 12:00:00', self::FIRST]],
            'not a uuid'     => [[self::AFTER, strtoupper(self::FIRST)]],
        ];
    }

    /**
     * A page that is not the instant and lower-case UUID of a position is
     * refused, naming what it must be.
     *
     * @param  array{0: string, 1: string}  $page
     * @return void
     */
    #[DataProvider('provideMalformedPages')]
    public function testRefusesAMalformedPage(array $page): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A disclosure\'s page is the instant and the lower-case UUID of the entry it read after.');

        DisclosureManifest::of([], null, [], $page);
    }

    /**
     * A canonical form reads back as its count and digest, a disclosure of most
     * members included.
     *
     * @return void
     */
    public function testReadGivesTheCountAndDigest(): void
    {
        $manifest = DisclosureManifest::of(['event' => 'invoice.approved'], ['denied' => true], self::members());
        $largest  = DisclosureManifest::of([], null, self::manyMembers(DisclosureManifest::MAX_MEMBERS));

        self::assertSame(['count' => 2, 'digest' => $manifest->digest], DisclosureManifest::read($manifest->canonical));
        self::assertSame(['count' => 500, 'digest' => $largest->digest], DisclosureManifest::read($largest->canonical));
    }

    /**
     * Rows of `[plaintext]`: plaintexts that are not exactly a disclosure's
     * canonical form in a version this release reads.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonCanonicalPlaintexts(): iterable
    {
        $member = '["' . self::FIRST . '","' . self::hmac(self::FIRST) . '"]';
        $deep   = str_repeat('{"a":', 15) . '1' . str_repeat('}', 15);
        $tail   = ',"nonce":"' . self::NONCE . '","page":null,"scope":null}';

        yield from [
            'whitespace'          => ['{"disclosure_version": 1,"filters":[],"members":[]' . $tail],
            'a trailing newline'  => [self::EMPTY . "\n"],
            'reordered keys'      => ['{"filters":[],"disclosure_version":1,"members":[]' . $tail],
            'reordered filters'   => ['{"disclosure_version":1,"filters":{"b":1,"a":1},"members":[]' . $tail],
            'an extra key'        => ['{"disclosure_version":1,"extra":1,"filters":[],"members":[]' . $tail],
            'a missing key'       => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":null}'],
            'version 2'           => ['{"disclosure_version":2,"filters":[],"members":[]' . $tail],
            'version 0'           => ['{"disclosure_version":0,"filters":[],"members":[]' . $tail],
            'a string version'    => ['{"disclosure_version":"1","filters":[],"members":[]' . $tail],
            'a duplicate id'      => ['{"disclosure_version":1,"filters":[],"members":[' . $member . ',' . $member . ']' . $tail],
            'a bad hmac'          => ['{"disclosure_version":1,"filters":[],"members":[["' . self::FIRST . '","' . str_repeat('A', 64) . '"]]' . $tail],
            'an upper-case id'    => ['{"disclosure_version":1,"filters":[],"members":[["' . strtoupper(self::FIRST) . '","' . self::hmac(self::FIRST) . '"]]' . $tail],
            'a member of three'   => ['{"disclosure_version":1,"filters":[],"members":[["' . self::FIRST . '","' . self::hmac(self::FIRST) . '","x"]]' . $tail],
            'a member as a map'   => ['{"disclosure_version":1,"filters":[],"members":[{"id":"' . self::FIRST . '"}]' . $tail],
            'members as a map'    => ['{"disclosure_version":1,"filters":[],"members":{"a":' . $member . '}' . $tail],
            'members as a string' => ['{"disclosure_version":1,"filters":[],"members":"none"' . $tail],
            'filters as a list'   => ['{"disclosure_version":1,"filters":["a"],"members":[]' . $tail],
            'filters as null'     => ['{"disclosure_version":1,"filters":null,"members":[]' . $tail],
            'a scope as a list'   => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":null,"scope":["a"]}'],
            'a scope as a string' => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":null,"scope":"all"}'],
            'a float'             => ['{"disclosure_version":1,"filters":{"a":1.5},"members":[]' . $tail],
            'a huge integer'      => ['{"disclosure_version":1,"filters":{"a":99999999999999999999},"members":[]' . $tail],
            'an escaped slash'    => ['{"disclosure_version":1,"filters":{"a":"b\/c"},"members":[]' . $tail],
            'not JSON'            => ['{"disclosure_version":1'],
            'no nonce'            => ['{"disclosure_version":1,"filters":[],"members":[],"page":null,"scope":null}'],
            'a short nonce'       => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . substr(self::NONCE, 1) . '","page":null,"scope":null}'],
            'an upper-case nonce' => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . strtoupper(self::NONCE) . '","page":null,"scope":null}'],
            'a nonce as a number' => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":1,"page":null,"scope":null}'],
            'no page'             => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","scope":null}'],
            'a page of one'       => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":["' . self::AFTER . '"],"scope":null}'],
            'a page not a time'   => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":["noon","' . self::FIRST . '"],"scope":null}'],
            'a page not an id'    => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":["' . self::AFTER . '","inv_1"],"scope":null}'],
            'a page as a string'  => ['{"disclosure_version":1,"filters":[],"members":[],"nonce":"' . self::NONCE . '","page":"next","scope":null}'],
            'a list'              => ['[1,[],[],null]'],
            'a string'            => ['"disclosure"'],
            'empty'               => [''],
            'too deep'            => ['{"disclosure_version":1,"filters":{"a":' . $deep . '},"members":[]' . $tail],
        ];
    }

    /**
     * Only a canonical form of a supported version reads back; any other
     * plaintext is `null`, never an exception.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideNonCanonicalPlaintexts')]
    public function testReadRefusesANonCanonicalPlaintext(string $plaintext): void
    {
        self::assertNull(DisclosureManifest::read($plaintext));
    }

    /**
     * More than the most entries a disclosure names is refused, naming the
     * limit; exactly that many is kept.
     *
     * @return void
     */
    public function testRefusesMoreThanFiveHundredMembers(): void
    {
        self::assertSame(500, DisclosureManifest::MAX_MEMBERS);
        self::assertSame(500, DisclosureManifest::of([], null, self::manyMembers(500))->count);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A disclosure names at most 500 entries.');

        DisclosureManifest::of([], null, self::manyMembers(501));
    }

    /**
     * An entry named twice is refused, whatever its HMAC.
     *
     * @return void
     */
    public function testRefusesAMemberIdTwice(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A disclosure names each entry once.');

        DisclosureManifest::of([], null, [[self::FIRST, self::hmac(self::FIRST)], [self::SECOND, self::hmac(self::SECOND)], [self::FIRST, str_repeat('0', 64)]]);
    }

    /**
     * Rows of `[members, message]`: members that are not a list of each an
     * entry's id and HMAC, and the refusal each gives.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideMalformedMembers(): iterable
    {
        $pair = 'A disclosure\'s members are each an entry\'s lower-case UUID and its HMAC of 64 lower-case hexadecimal characters.';

        yield from [
            'an id that is not a UUID' => [[['inv_0042', self::hmac(self::FIRST)]], $pair],
            'an upper-case id'         => [[[strtoupper(self::FIRST), self::hmac(self::FIRST)]], $pair],
            'an id with a newline'     => [[[self::FIRST . "\n", self::hmac(self::FIRST)]], $pair],
            'a short hmac'             => [[[self::FIRST, substr(self::hmac(self::FIRST), 1)]], $pair],
            'an upper-case hmac'       => [[[self::FIRST, strtoupper(self::hmac(self::FIRST))]], $pair],
            'an hmac with a newline'   => [[[self::FIRST, self::hmac(self::FIRST) . "\n"]], $pair],
            'an integer hmac'          => [[[self::FIRST, 1]], $pair],
            'an integer id'            => [[[1, self::hmac(self::FIRST)]], $pair],
            'a member of one'          => [[[self::FIRST]], $pair],
            'a member of three'        => [[[self::FIRST, self::hmac(self::FIRST), 'x']], $pair],
            'a member as a map'        => [[['id' => self::FIRST, 'hmac' => self::hmac(self::FIRST)]], $pair],
            'a member reversed'        => [[[1 => self::hmac(self::FIRST), 0 => self::FIRST]], $pair],
            'a member as a string'     => [[self::FIRST], $pair],
            'a valid member after one' => [[[self::FIRST, self::hmac(self::FIRST)], [self::SECOND, 'x']], $pair],
            'members keyed as a map'   => [[1 => [self::FIRST, self::hmac(self::FIRST)]], 'A disclosure\'s members are a list.'],
            'members keyed by name'    => [['a' => [self::FIRST, self::hmac(self::FIRST)]], 'A disclosure\'s members are a list.'],
        ];
    }

    /**
     * Members that are not a list of lower-case UUIDs and HMACs are refused,
     * naming what the members must be.
     *
     * @param  list<array{0: string, 1: string}>  $members
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedMembers')]
    public function testRefusesAMalformedMember(array $members, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        DisclosureManifest::of([], null, $members);
    }

    /**
     * Rows of `[filters, scope]`: a list where a map belongs, or nesting deeper
     * than a disclosure is read to.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: ?array<array-key, mixed>}>
     */
    public static function provideUnreadableFiltersAndScopes(): iterable
    {
        yield from [
            'filters as a list'     => [['invoice.approved'], null],
            'a scope as a list'     => [[], ['organisation']],
            'filters nested deeper' => [['f' => self::nested(14)], null],
            'a scope nested deeper' => [[], ['s' => self::nested(14)]],
        ];
    }

    /**
     * Filters or a scope the reader would not read back are refused, so every
     * disclosure made is one that reads.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $filters
     * @param  ?array<string, mixed>  $scope
     * @return void
     */
    #[DataProvider('provideUnreadableFiltersAndScopes')]
    public function testRefusesFiltersOrAScopeItCannotReadBack(array $filters, ?array $scope): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A disclosure\'s filters and scope must be maps that encode within 16 levels.');

        DisclosureManifest::of($filters, $scope, []);
    }

    /**
     * Filters and a scope nested to the deepest the reader reads are kept.
     *
     * @return void
     */
    public function testTheDeepestReadableNestingIsKept(): void
    {
        $manifest = DisclosureManifest::of(['f' => self::nested(13)], ['s' => self::nested(13)], []);

        self::assertSame(['count' => 0, 'digest' => $manifest->digest], DisclosureManifest::read($manifest->canonical));
    }

    /**
     * A value with no canonical form, a float, is refused by the encoder.
     *
     * @return void
     */
    public function testAFloatIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        DisclosureManifest::of(['amount' => 1.5], null, []);
    }

    /**
     * The version, the versions read and the member cap are pinned.
     *
     * @return void
     */
    public function testTheConstantsArePinned(): void
    {
        self::assertSame(1, DisclosureManifest::VERSION);
        self::assertSame([1], DisclosureManifest::SUPPORTED_VERSIONS);
        self::assertSame(500, DisclosureManifest::MAX_MEMBERS);
    }

    /**
     * The members and the plaintext are sensitive parameters.
     *
     * @return void
     */
    public function testTheMembersAreSensitive(): void
    {
        $parameters = [
            (new \ReflectionMethod(DisclosureManifest::class, 'of'))->getParameters()[2],
            (new \ReflectionMethod(DisclosureManifest::class, 'read'))->getParameters()[0],
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DisclosureManifest::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(DisclosureManifest::class, $instance);
    }

    /**
     * The nonce of a disclosure's canonical form.
     *
     * @param  string  $canonical
     * @return string
     */
    private static function nonceOf(string $canonical): string
    {
        $decoded = json_decode($canonical, true, 16, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertIsString($decoded['nonce'] ?? null);

        return $decoded['nonce'];
    }

    /**
     * The two entries a read returned, in the order returned.
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function members(): array
    {
        return [[self::FIRST, self::hmac(self::FIRST)], [self::SECOND, self::hmac(self::SECOND)]];
    }

    /**
     * The number of distinct entries given, each with its HMAC.
     *
     * @param  int  $count
     * @return list<array{0: string, 1: string}>
     */
    private static function manyMembers(int $count): array
    {
        return array_map(static function (int $index): array {
            $id = sprintf('01932b4e-8a40-7000-8000-%012d', $index);

            return [$id, self::hmac($id)];
        }, range(1, $count));
    }

    /**
     * A stand-in HMAC of the entry: 64 lower-case hex.
     *
     * @param  string  $id
     * @return string
     */
    private static function hmac(string $id): string
    {
        return hash('sha256', $id);
    }

    /**
     * A string nested in maps to the number of levels given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $levels
     * @return array<string, mixed>|string
     */
    private static function nested(int $levels): array|string
    {
        $value = 'x';

        for ($level = 0; $level < $levels; $level++) {
            $value = ['a' => $value];
        }

        return $value;
    }
}
