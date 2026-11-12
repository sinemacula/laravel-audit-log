<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Rfc4122\FieldsInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for an artifact's manifest and the plaintexts it reads back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Manifest::class)]
final class ManifestTest extends TestCase
{
    /** @var string The type of the golden members. */
    private const string INVOICE = 'App\Models\Invoice';

    /** @var string The canonical form of the golden members. */
    private const string GOLDEN = '[["App\\\Models\\\Invoice","1"],["App\\\Models\\\Invoice","10"],["App\\\Models\\\Invoice","2"]]';

    /** @var string The digest of the golden members' canonical form. */
    private const string GOLDEN_DIGEST = '0bee9fea9443d63a556a7fe8d19b18920d8aac7c234e48afc739a4df9380ed4d';

    /** @var int A cap no test here reaches unless it means to. */
    private const int MAX_MEMBERS = 100000;

    /** @var int A byte bound no test here reaches unless it means to. */
    private const int MAX_BYTES = 4194304;

    /**
     * Restore UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        parent::tearDown();
    }

    /**
     * The golden subjects, in any order and with a duplicate, give the golden
     * canonical form, count and digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenMembersGiveTheGoldenDigest(): void
    {
        $subjects = [self::invoice('2'), self::invoice('1'), self::invoice('10'), self::invoice('1')];

        $manifest = self::of($subjects);

        self::assertSame(self::GOLDEN, $manifest->canonical);
        self::assertSame(3, $manifest->count);
        self::assertSame(self::GOLDEN_DIGEST, $manifest->digest);
        self::assertSame(hash('sha256', self::GOLDEN), $manifest->digest);
        self::assertSame(self::GOLDEN, self::of(array_reverse($subjects))->canonical);
    }

    /**
     * Members are kept once on the exact pair and sorted bytewise on the type,
     * then on the id, compared as strings.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testMembersAreDeduplicatedAndSortedBytewise(): void
    {
        $manifest = self::of([
            Reference::of('b', '9'),
            Reference::of('é', '1'),
            Reference::of('a', '10'),
            Reference::of('ab', '1'),
            Reference::of('B', '1'),
            Reference::of('a', '9'),
            Reference::of('a', 'A'),
            Reference::of('a', 'a'),
            Reference::of('b', '9'),
            Reference::of('a', '10'),
        ]);

        self::assertSame([['B', '1'], ['a', '10'], ['a', '9'], ['a', 'A'], ['a', 'a'], ['ab', '1'], ['b', '9'], ['é', '1']], json_decode($manifest->canonical, true));
        self::assertSame(8, $manifest->count);
    }

    /**
     * A model becomes its reference, its class and its key, and is the same
     * member as a reference to it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAModelBecomesItsReference(): void
    {
        $manifest = self::of([(new StubUser)->forceFill(['id' => 5]), Reference::of(StubUser::class, '5')]);

        self::assertSame([[StubUser::class, '5']], json_decode($manifest->canonical, true));
        self::assertSame(1, $manifest->count);
    }

    /**
     * Any iterable is read, its keys ignored: a generator gives the manifest a
     * list does.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnyIterableIsRead(): void
    {
        $subjects = (static function (): \Generator {
            yield 'second' => self::invoice('2');
            yield 'first' => self::invoice('1');
            yield 'tenth' => self::invoice('10');
        })();

        self::assertSame(self::GOLDEN, self::of($subjects)->canonical);
    }

    /**
     * A bulk operation with no subject is refused.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesNoSubjects(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A bulk operation names at least one subject.');

        self::of([]);
    }

    /**
     * Rows of `[subject, its debug type]`: values that are neither a model nor
     * a reference.
     *
     * @return iterable<string, array{0: int|list<string>|\stdClass|string|null, 1: string}>
     */
    public static function provideOtherSubjects(): iterable
    {
        yield from [
            'a string'   => ['App\Models\Invoice#1', 'string'],
            'an integer' => [1, 'int'],
            'null'       => [null, 'null'],
            'a pair'     => [['App\Models\Invoice', '1'], 'array'],
            'an object'  => [new \stdClass, \stdClass::class],
        ];
    }

    /**
     * A subject that is neither a model nor a reference is refused, naming its
     * type and never its value, even after valid subjects.
     *
     * @param  int|list<string>|\stdClass|string|null  $subject
     * @param  string  $type
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideOtherSubjects')]
    public function testRefusesASubjectThatIsNeitherAModelNorAReference(array|int|\stdClass|string|null $subject, string $type): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("A bulk operation's subjects are models or references; one is {$type}.");

        self::of([self::invoice('1'), $subject]);
    }

    /**
     * A model that has no key is refused, as a reference refuses it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAnUnsavedModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model must have a key before it can be referenced; save it first.');

        self::of([self::invoice('1'), new StubUser]);
    }

    /**
     * Exactly the cap of unique members is kept, however many duplicates come
     * with them, and one more is refused, naming the cap and its setting.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesMoreMembersThanTheCap(): void
    {
        $kept = Manifest::of([self::invoice('1'), self::invoice('2'), self::invoice('1'), self::invoice('3'), self::invoice('2')], 3, self::MAX_BYTES);

        self::assertSame(3, $kept->count);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A bulk operation names at most 3 subjects, the `audit-log.capture.bulk.max_members` setting.');

        Manifest::of([self::invoice('1'), self::invoice('2'), self::invoice('3'), self::invoice('4')], 3, self::MAX_BYTES);
    }

    /**
     * An endless input of one duplicate is refused once four times the cap has
     * been read, and nothing past that is read.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAnInputThatNeverEnds(): void
    {
        $subjects = (static function (): \Generator {
            while (true) {
                yield self::invoice('1');
            }
        })();

        $message = 'A bulk operation reads at most 20 subjects, duplicates included: four times the `audit-log.capture.bulk.max_members` setting.';

        try {
            Manifest::of($subjects, 5, self::MAX_BYTES);
            self::fail('Expected an endless input to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        // The generator rests on the last subject read, the 21st, keyed 20
        self::assertSame(5 * Manifest::MAX_INPUT_FACTOR, $subjects->key());
    }

    /**
     * Exactly four times the cap may be read, duplicates included, so a few
     * members given many times over are kept.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFourTimesTheCapMayBeRead(): void
    {
        $subjects = array_merge(...array_fill(0, 4, [self::invoice('1'), self::invoice('2')]));

        self::assertCount(8, $subjects);
        self::assertSame(2, Manifest::of($subjects, 2, self::MAX_BYTES)->count);
    }

    /**
     * An endless input of distinct subjects stops at the cap, never reading the
     * whole input first.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnEndlessInputOfDistinctSubjectsStopsAtTheCap(): void
    {
        $subjects = (static function (): \Generator {
            for ($id = 1;; $id++) {
                yield self::invoice((string) $id);
            }
        })();

        try {
            Manifest::of($subjects, 10, self::MAX_BYTES);
            self::fail('Expected an endless input to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A bulk operation names at most 10 subjects, the `audit-log.capture.bulk.max_members` setting.', $exception->getMessage());
        }

        self::assertSame(10, $subjects->key());
        self::assertEquals(self::invoice('11'), $subjects->current());
    }

    /**
     * A canonical form over the byte bound is refused, naming the bound and its
     * setting, and the refusal comes as soon as the bytes exceed it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAManifestOverTheByteBound(): void
    {
        $subjects = (static function (): \Generator {
            for ($id = 1;; $id++) {
                yield Reference::of(self::INVOICE, str_pad((string) $id, 100, '0', STR_PAD_LEFT));
            }
        })();

        try {
            Manifest::of($subjects, self::MAX_MEMBERS, 65536);
            self::fail('Expected an oversize manifest to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A bulk operation\'s manifest must encode to at most 65536 bytes, the `audit-log.capture.bulk.max_bytes` setting.', $exception->getMessage());
        }

        // Each member costs 128 bytes with its comma, so 511 fit beside the
        // brackets and the 512th, keyed 511, does not
        self::assertSame(511, $subjects->key());
    }

    /**
     * Multibyte references count by their bytes: the longest pair encodes to
     * 964 bytes, which a bound of 963 refuses.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testMaximumLengthReferencesCountTowardTheByteBound(): void
    {
        $reference = Reference::of(str_repeat('é', Reference::MAX_CHARACTERS), str_repeat('€', Reference::MAX_CHARACTERS));

        $manifest = Manifest::of([$reference], 1, 964);

        self::assertSame(964, strlen($manifest->canonical));
        self::assertSame([[$reference->type, $reference->id]], json_decode($manifest->canonical, true));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A bulk operation\'s manifest must encode to at most 963 bytes, the `audit-log.capture.bulk.max_bytes` setting.');

        Manifest::of([$reference], 1, 963);
    }

    /**
     * A manifest whose canonical form is exactly the byte bound is kept, and
     * one byte less refuses it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAManifestExactlyAtTheByteBoundIsKept(): void
    {
        $subjects = [self::invoice('2'), self::invoice('1'), self::invoice('10'), Reference::of('a/b', 'x"y'), self::invoice('1')];
        $length   = strlen(self::of($subjects)->canonical);

        self::assertSame($length, strlen(Manifest::of($subjects, self::MAX_MEMBERS, $length)->canonical));

        $this->expectException(\InvalidArgumentException::class);

        Manifest::of($subjects, self::MAX_MEMBERS, $length - 1);
    }

    /**
     * Nothing is ever truncated: a manifest at the cap holds every member, and
     * one over it is refused rather than cut to the cap.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNothingIsEverTruncated(): void
    {
        $subjects = array_map(static fn (int $id): Reference => self::invoice((string) $id), range(1, 1000));
        $manifest = Manifest::of($subjects, 1000, self::MAX_BYTES);
        $decoded  = json_decode($manifest->canonical, true);

        self::assertIsArray($decoded);
        self::assertCount(1000, $decoded);
        self::assertSame(1000, $manifest->count);

        self::assertEqualsCanonicalizing(array_map(strval(...), range(1, 1000)), array_column($decoded, 1));

        try {
            Manifest::of([...$subjects, self::invoice('1001')], 1000, self::MAX_BYTES);
            self::fail('Expected a manifest over the cap to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('A bulk operation names at most 1000 subjects', $exception->getMessage());
        }
    }

    /**
     * The id is a lower-case UUID version 7, made once per manifest, so two
     * manifests of the same members are different artifacts.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheIdIsALowerCaseUuidV7(): void
    {
        $manifest = self::of([self::invoice('1')]);
        $fields   = Uuid::fromString($manifest->id)->getFields();

        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $manifest->id);
        self::assertInstanceOf(FieldsInterface::class, $fields);
        self::assertSame(7, $fields->getVersion());
        self::assertNotSame($manifest->id, self::of([self::invoice('1')])->id);
    }

    /**
     * The id comes from the UUID factory, so a test that pins it pins the
     * manifest's.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheIdComesFromTheUuidFactory(): void
    {
        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString('01932B4E-8A40-7000-8000-000000000009'));

        self::assertSame('01932b4e-8a40-7000-8000-000000000009', self::of([self::invoice('1')])->id);
    }

    /**
     * The descriptor is the artifact's id, its kind, the digest and the count,
     * in that order and nothing else.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheDescriptorHoldsTheIdKindDigestAndCount(): void
    {
        $manifest = self::of([self::invoice('2'), self::invoice('1'), self::invoice('10')]);

        self::assertSame(['artifact_id' => $manifest->id, 'kind' => 'bulk', 'digest' => self::GOLDEN_DIGEST, 'count' => 3], $manifest->descriptor());
        self::assertSame(ArtifactKind::BULK, $manifest->kind);
    }

    /**
     * Each kind's descriptor names that kind, beside the id, digest and count
     * of the content it was given, in the same order.
     *
     * @return void
     */
    public function testTheDescriptorNamesItsKind(): void
    {
        foreach (ArtifactKind::cases() as $kind) {
            $manifest = Manifest::ofContent($kind, '{"a":1}', 1);

            self::assertSame(
                ['artifact_id' => $manifest->id, 'kind' => $kind->value, 'digest' => hash('sha256', '{"a":1}'), 'count' => 1],
                $manifest->descriptor(),
                $kind->value,
            );
        }
    }

    /**
     * Content of any kind is kept exactly as given, its digest the lower-case
     * hex SHA-256 of those bytes, with the count given and the kind named.
     *
     * @return void
     */
    public function testContentOfAnyKindIsDigestedAsGiven(): void
    {
        $canonical = '{"disclosure_version":1,"filters":[],"members":[],"scope":null}';

        foreach (ArtifactKind::cases() as $kind) {
            $manifest = Manifest::ofContent($kind, $canonical, 7);

            self::assertSame($kind, $manifest->kind, $kind->value);
            self::assertSame($canonical, $manifest->canonical, $kind->value);
            self::assertSame(hash('sha256', $canonical), $manifest->digest, $kind->value);
            self::assertSame(7, $manifest->count, $kind->value);
        }
    }

    /**
     * A disclosure or an export of nothing is a manifest counting none.
     *
     * @return void
     */
    public function testAnEmptyDisclosureIsAccepted(): void
    {
        self::assertSame(0, Manifest::ofContent(ArtifactKind::DISCLOSURE, '{}', 0)->count);
        self::assertSame(0, Manifest::ofContent(ArtifactKind::EXPORT, '{}', 0)->count);
    }

    /**
     * A bulk operation of no subject is refused whichever way it is made.
     *
     * @return void
     */
    public function testAnEmptyBulkIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A bulk operation names at least one subject.');

        Manifest::ofContent(ArtifactKind::BULK, '[]', 0);
    }

    /**
     * Rows of `[kind, message]`: a negative count of each kind, and what it is
     * refused with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind, 1: string}>
     */
    public static function provideNegativeCounts(): iterable
    {
        yield from [
            'a bulk operation' => [ArtifactKind::BULK, 'A bulk operation names at least one subject.'],
            'a disclosure'     => [ArtifactKind::DISCLOSURE, 'An artifact counts no fewer than zero members.'],
            'an export'        => [ArtifactKind::EXPORT, 'An artifact counts no fewer than zero members.'],
        ];
    }

    /**
     * A negative count is refused for every kind, a bulk operation's as one
     * with no subject.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideNegativeCounts')]
    public function testANegativeCountIsRefused(ArtifactKind $kind, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Manifest::ofContent($kind, '{}', -1);
    }

    /**
     * An empty canonical form is refused for every kind: there is nothing to
     * digest.
     *
     * @return void
     */
    public function testAnEmptyCanonicalFormIsRefused(): void
    {
        foreach (ArtifactKind::cases() as $kind) {
            try {
                Manifest::ofContent($kind, '', 1);

                self::fail(sprintf('Expected an empty %s to be refused.', $kind->value));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An artifact\'s canonical form is never empty.', $exception->getMessage());
            }
        }
    }

    /**
     * Each content is its own artifact: a lower-case UUID version 7 made from
     * the UUID factory, never the same twice for the same bytes.
     *
     * @return void
     */
    public function testEachContentHasItsOwnUuidV7(): void
    {
        $first  = Manifest::ofContent(ArtifactKind::EXPORT, '{}', 0);
        $fields = Uuid::fromString($first->id)->getFields();

        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $first->id);
        self::assertInstanceOf(FieldsInterface::class, $fields);
        self::assertSame(7, $fields->getVersion());
        self::assertNotSame($first->id, Manifest::ofContent(ArtifactKind::EXPORT, '{}', 0)->id);

        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString('01932B4E-8A40-7000-8000-00000000000A'));

        self::assertSame('01932b4e-8a40-7000-8000-00000000000a', Manifest::ofContent(ArtifactKind::DISCLOSURE, '{}', 0)->id);
    }

    /**
     * The input factor and the flags are pinned: the flags are those every
     * stored JSON column uses.
     *
     * @return void
     */
    public function testTheConstantsArePinned(): void
    {
        self::assertSame(4, Manifest::MAX_INPUT_FACTOR);
        self::assertSame(JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR, Manifest::JSON_FLAGS);
    }

    /**
     * Encoding sorts the members bytewise and keeps slashes and multibyte
     * characters unescaped.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEncodingSortsAndKeepsCharactersUnescaped(): void
    {
        self::assertSame('[["a/b","é"],["a/b","ü"],["b","1"]]', Manifest::encode([['b', '1'], ['a/b', 'ü'], ['a/b', 'é']]));
        self::assertSame(self::GOLDEN, Manifest::encode([[self::INVOICE, '2'], [self::INVOICE, '10'], [self::INVOICE, '1']]));
    }

    /**
     * The canonical form reads back as its count and digest, the golden form
     * and that of a single member alike.
     *
     * @return void
     */
    public function testReadCanonicalReadsTheCanonicalForm(): void
    {
        self::assertSame(['count' => 3, 'digest' => self::GOLDEN_DIGEST], Manifest::readCanonical(self::GOLDEN));
        self::assertSame(['count' => 1, 'digest' => hash('sha256', '[["a","1"]]')], Manifest::readCanonical('[["a","1"]]'));
    }

    /**
     * Rows of `[plaintext]`: plaintexts that are not exactly a canonical form.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonCanonicalPlaintexts(): iterable
    {
        yield from [
            'unsorted'               => ['[["a","2"],["a","1"]]'],
            'unsorted on the type'   => ['[["b","1"],["a","1"]]'],
            'a duplicate'            => ['[["a","1"],["a","1"]]'],
            'a three-member pair'    => ['[["a","1","x"]]'],
            'a one-member pair'      => ['[["a"]]'],
            'a non-string id'        => ['[["a",1]]'],
            'a non-string type'      => ['[[null,"1"]]'],
            'a nested pair'          => ['[[["a"],"1"]]'],
            'a member not a list'    => ['["a"]'],
            'added whitespace'       => ['[["a", "1"]]'],
            'a trailing newline'     => ["[[\"a\",\"1\"]]\n"],
            'an escaped character'   => ['[["\u00e9","1"]]'],
            'an escaped slash'       => ['[["a\/b","1"]]'],
            'a map'                  => ['{"0":["a","1"]}'],
            'a pair as a map'        => ['[{"0":"a","1":"1"}]'],
            'a pair with named keys' => ['[{"type":"a","id":"1"}]'],
            'an empty list'          => ['[]'],
            'a string'               => ['"a"'],
            'not JSON'               => ['[["a","1"]'],
            'empty'                  => [''],
        ];
    }

    /**
     * Only the canonical form reads back; any other plaintext is `null`.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideNonCanonicalPlaintexts')]
    public function testReadCanonicalAcceptsOnlyTheCanonicalForm(string $plaintext): void
    {
        self::assertNull(Manifest::readCanonical($plaintext));
    }

    /**
     * The canonical form is a sensitive parameter, wherever it is given, and so
     * are the subjects and members it is made of.
     *
     * @return void
     */
    public function testTheMembersAreSensitive(): void
    {
        $parameters = [
            (new \ReflectionMethod(Manifest::class, '__construct'))->getParameters()[4],
            (new \ReflectionMethod(Manifest::class, 'of'))->getParameters()[0],
            (new \ReflectionMethod(Manifest::class, 'ofContent'))->getParameters()[1],
            (new \ReflectionMethod(Manifest::class, 'encode'))->getParameters()[0],
            (new \ReflectionMethod(Manifest::class, 'readCanonical'))->getParameters()[0],
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }
    }

    /**
     * The manifest of the subjects under bounds no test here reaches; the
     * subjects may be of any type, as an application may give.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  iterable<array-key, mixed>  $subjects
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \JsonException
     */
    private static function of(iterable $subjects): Manifest
    {
        /** @var iterable<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference> $subjects */
        return Manifest::of($subjects, self::MAX_MEMBERS, self::MAX_BYTES);
    }

    /**
     * A reference to the invoice of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function invoice(string $id): Reference
    {
        return Reference::of(self::INVOICE, $id);
    }
}
