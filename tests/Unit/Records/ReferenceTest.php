<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\Uid\Ulid;
use Tests\Unit\Stubs\StubDocument;
use Tests\Unit\Stubs\StubSealedUser;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the reference value: the ids it keeps exactly, the pairs it
 * refuses, how a model is referred to under each morph map, the keys a model
 * may have, and the equality and shape it gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Reference::class)]
final class ReferenceTest extends TestCase
{
    /** @var string A lower-case UUID. */
    private const string UUID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string An upper-case ULID. */
    private const string ULID = '01JBQ4N6Z8X2Y3W4V5T6S7R8Q9';

    /** @var string A big integer beyond `PHP_INT_MAX`, as a string. */
    private const string BIG = '9223372036854775808';

    /**
     * Clear the morph map and its enforcement after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);
        Relation::requireMorphMap(false);

        parent::tearDown();
    }

    /**
     * Rows of `[id, the id kept]`: integers and the strings ids are given as.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function provideIds(): iterable
    {
        yield from [
            'an integer'         => [42, '42'],
            'zero'               => [0, '0'],
            'a negative integer' => [-7, '-7'],
            'PHP_INT_MAX'        => [PHP_INT_MAX, '9223372036854775807'],
            'beyond PHP_INT_MAX' => [self::BIG, self::BIG],
            'leading zeros'      => ['007', '007'],
            'a lower-case UUID'  => [self::UUID, self::UUID],
            'an upper-case UUID' => [strtoupper(self::UUID), strtoupper(self::UUID)],
            'an upper-case ULID' => [self::ULID, self::ULID],
            'a lower-case ULID'  => [strtolower(self::ULID), strtolower(self::ULID)],
            'surrounding spaces' => [' 42 ', ' 42 '],
            'a namespaced id'    => ['app:ticket-123', 'app:ticket-123'],
        ];
    }

    /**
     * Each id is kept exactly, as a string: never trimmed, case-folded or
     * reformatted.
     *
     * @param  int|string  $id
     * @param  string  $kept
     * @return void
     */
    #[DataProvider('provideIds')]
    public function testOfKeepsTheIdExactly(int|string $id, string $kept): void
    {
        self::assertSame($kept, Reference::of('invoice', $id)->id);
    }

    /**
     * The type is kept exactly as given.
     *
     * @return void
     */
    public function testOfKeepsTheType(): void
    {
        self::assertSame('App\Models\Invoice', Reference::of('App\Models\Invoice', 1)->type);
        self::assertSame('Invoice', Reference::of('Invoice', 1)->type);
    }

    /**
     * Rows of `[type, id, message]`: pairs with an empty, over-long or unclean
     * part.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideRefusedPairs(): iterable
    {
        $type = 'A reference\'s type must be from 1 to 191 characters, with no control characters.';
        $id   = 'A reference\'s id must be from 1 to 191 characters, with no control characters.';

        yield from [
            'an empty type'                => ['', '1', $type],
            'an empty id'                  => ['invoice', '', $id],
            'a 192-character type'         => [str_repeat('a', 192), '1', $type],
            'a 192-character id'           => ['invoice', str_repeat('1', 192), $id],
            'a 192-character multibyte id' => ['invoice', str_repeat('é', 192), $id],
            'a line feed in the id'        => ['invoice', "1\n", $id],
            'a NUL in the type'            => ["user\0", '1', $type],
            'invalid UTF-8 in the type'    => ["\xC3", '1', $type],
            'U+202E in the id'             => ['invoice', "1\u{202E}2", $id],
            'both refused, type first'     => ['', '', $type],
        ];
    }

    /**
     * Each pair with an empty, over-long or unclean part is refused, the type
     * checked before the id, and nothing is truncated to fit.
     *
     * @param  string  $type
     * @param  string  $id
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedPairs')]
    public function testOfRefusesAnInvalidPair(string $type, string $id, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Reference::of($type, $id);
    }

    /**
     * A type and an id of exactly 191 characters are kept, counted in
     * characters rather than bytes: 191 two-byte characters are 382 bytes.
     *
     * @return void
     */
    public function testOfAccepts191Characters(): void
    {
        $text      = str_repeat('é', 191);
        $reference = Reference::of($text, $text);

        self::assertSame($text, $reference->type);
        self::assertSame($text, $reference->id);
    }

    /**
     * Without a morph map, a model is referred to by its class name.
     *
     * @return void
     */
    public function testToUsesTheClassNameWithoutAMorphMap(): void
    {
        $reference = Reference::to((new StubUser)->forceFill(['id' => 42]));

        self::assertSame(StubUser::class, $reference->type);
        self::assertSame('42', $reference->id);
    }

    /**
     * A model the morph map names is referred to by its alias.
     *
     * @return void
     */
    public function testToUsesAMorphAlias(): void
    {
        Relation::morphMap(['user' => StubUser::class]);

        self::assertSame('user', Reference::to((new StubUser)->forceFill(['id' => 42]))->type);
    }

    /**
     * Under an enforced morph map that omits the model, the reference falls
     * back to the class name rather than failing.
     *
     * @return void
     */
    public function testToFallsBackToTheClassNameUnderAnEnforcedMapThatOmitsIt(): void
    {
        Relation::requireMorphMap();
        Relation::morphMap(['document' => StubDocument::class]);

        self::assertSame(StubUser::class, Reference::to((new StubUser)->forceFill(['id' => 42]))->type);
        self::assertSame('document', Reference::to((new StubDocument)->forceFill(['id' => 'a']))->type);
    }

    /**
     * Rows of `[model, mode, the type, the id]`: every key of AUDIT-RECORD.7
     * against no morph map, an alias, and an enforced map missing the class.
     *
     * @return iterable<string, array{0: \Illuminate\Database\Eloquent\Model, 1: 'alias'|'enforced'|'none', 2: string, 3: string}>
     */
    public static function provideModelKeys(): iterable
    {
        $keys = [
            'an integer'         => static fn (): Model => (new StubUser)->forceFill(['id' => 42]),
            'leading zeros'      => static fn (): Model => (new StubDocument)->forceFill(['id' => '007']),
            'beyond PHP_INT_MAX' => static fn (): Model => (new StubDocument)->forceFill(['id' => self::BIG]),
            'a UUID'             => static fn (): Model => (new StubDocument)->forceFill(['id' => self::UUID]),
            'a ULID'             => static fn (): Model => (new StubDocument)->forceFill(['id' => self::ULID]),
        ];

        $ids = ['an integer' => '42', 'leading zeros' => '007', 'beyond PHP_INT_MAX' => self::BIG, 'a UUID' => self::UUID, 'a ULID' => self::ULID];

        foreach ($keys as $label => $model) {
            $class = $model()::class;

            yield $label . ', no morph map' => [$model(), 'none', $class, $ids[$label]];
            yield $label . ', an alias' => [$model(), 'alias', 'alias', $ids[$label]];
            yield $label . ', an enforced map missing it' => [$model(), 'enforced', $class, $ids[$label]];
        }
    }

    /**
     * Each key is kept exactly under each morph map mode, and the type is the
     * alias or the class name as the mode decides.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  'alias'|'enforced'|'none'  $mode
     * @param  string  $type
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideModelKeys')]
    public function testToKeepsEveryKeyUnderEveryMorphMap(Model $model, string $mode, string $type, string $id): void
    {
        if ($mode === 'alias') {
            Relation::morphMap(['alias' => $model::class]);
        }

        if ($mode === 'enforced') {
            Relation::requireMorphMap();
            Relation::morphMap(['other' => \stdClass::class]);
        }

        $reference = Reference::to($model);

        self::assertSame($type, $reference->type);
        self::assertSame($id, $reference->id);
    }

    /**
     * A model with no key cannot be referred to.
     *
     * @return void
     */
    public function testToRefusesAnUnsavedModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model must have a key before it can be referenced; save it first.');

        Reference::to(new StubUser);
    }

    /**
     * A model with an empty string key is refused as an empty id.
     *
     * @return void
     */
    public function testToRefusesAnEmptyKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reference\'s id must be from 1 to 191 characters, with no control characters.');

        Reference::to((new StubDocument)->forceFill(['id' => '']));
    }

    /**
     * A deleted model that still holds its key gives its reference.
     *
     * @return void
     */
    public function testToKeepsTheReferenceOfADeletedModel(): void
    {
        $user         = (new StubUser)->forceFill(['id' => 42]);
        $user->exists = false;

        self::assertSame(['type' => StubUser::class, 'id' => '42'], Reference::to($user)->toArray());
    }

    /**
     * A ramsey UUID or a Symfony ULID object held as the key gives its string.
     *
     * @return void
     */
    public function testToTakesAUuidObjectKey(): void
    {
        $uuid = Uuid::fromString(self::UUID);
        $ulid = Ulid::fromString(self::ULID);

        self::assertSame(self::UUID, Reference::to((new StubDocument)->forceFill(['id' => $uuid]))->id);
        self::assertSame(self::ULID, Reference::to((new StubDocument)->forceFill(['id' => $ulid]))->id);
    }

    /**
     * A key that is neither a string, an integer nor a UUID or ULID object is
     * refused, naming its type and never its value.
     *
     * @return void
     */
    public function testToRefusesAKeyThatIsNeitherAStringNorAnInteger(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model\'s key must be a string or an integer to be referenced; it is float.');

        Reference::to((new StubDocument)->forceFill(['id' => 1.5]));
    }

    /**
     * An object key of any other class is refused, naming its class.
     *
     * @return void
     */
    public function testToRefusesAnObjectKeyOfAnotherClass(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model\'s key must be a string or an integer to be referenced; it is stdClass.');

        Reference::to((new StubDocument)->forceFill(['id' => new \stdClass]));
    }

    /**
     * The reference holds only the type and the id, never the model's other
     * attributes.
     *
     * @return void
     */
    public function testToHoldsOnlyTheTypeAndTheId(): void
    {
        $user = (new StubUser)->forceFill(['id' => 1, 'email' => 'someone@example.com', 'password' => 'hunter2']);

        $reference = Reference::to($user);

        self::assertSame(['type' => StubUser::class, 'id' => '1'], $reference->toArray());
        self::assertSame(['type', 'id'], array_keys(get_object_vars($reference)));
    }

    /**
     * Referring to a model reads its key and its morph class only: it never
     * reads another attribute, turns the model into an array or JSON, casts it
     * to a string or queries it, each of which this model refuses by throwing.
     *
     * @return void
     */
    public function testToNeverReadsTheModelsAttributes(): void
    {
        $user = (new StubSealedUser)->forceFill(['id' => 1, 'email' => 'someone@example.com']);

        self::assertSame(['type' => StubSealedUser::class, 'id' => '1'], Reference::to($user)->toArray());
    }

    /**
     * The array form is the type and id pair, in that order.
     *
     * @return void
     */
    public function testToArrayIsTheTypeAndIdShape(): void
    {
        self::assertSame(['type' => 'invoice', 'id' => '42'], Reference::of('invoice', 42)->toArray());
    }

    /**
     * Two references are equal only with exactly the same type and id.
     *
     * @return void
     */
    public function testEqualsComparesTypeAndIdExactly(): void
    {
        $reference = Reference::of('invoice', 'ABC');

        self::assertTrue($reference->equals(Reference::of('invoice', 'ABC')));
        self::assertFalse($reference->equals(Reference::of('invoice', 'ABD')));
        self::assertFalse($reference->equals(Reference::of('order', 'ABC')));
        self::assertFalse($reference->equals(Reference::of('invoice', 'abc')));
        self::assertFalse(Reference::of('invoice', '42')->equals(Reference::of('invoice', '042')));
    }
}
