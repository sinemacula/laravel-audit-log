<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the reference of the user an event carries: a model by its
 * reference, any other authenticatable user by its class and identifier, and no
 * one for a user that cannot be referred to or is not a user, with nothing
 * asked of the user but its identifier and nothing asked of any guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UserReference::class)]
final class UserReferenceTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * `UserReference` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(UserReference::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(UserReference::class, $instance);
    }

    /**
     * A model is referred to as a reference refers to it: its morph class and
     * its key, whether or not it is authenticatable.
     *
     * @return void
     */
    public function testAModelIsItsReference(): void
    {
        Relation::morphMap(['user' => StubAuthUser::class]);

        self::assertSame(['type' => 'user', 'id' => '7'], UserReference::of((new StubAuthUser)->forceFill(['id' => 7]))?->toArray());
        self::assertSame(['type' => StubUser::class, 'id' => '9'], UserReference::of((new StubUser)->forceFill(['id' => 9]))?->toArray());
        self::assertSame(['type' => StubDocument::class, 'id' => 'u-1'], UserReference::of((new StubDocument)->forceFill(['id' => 'u-1']))?->toArray());
    }

    /**
     * A model with no key, or with a key a reference refuses, is no one rather
     * than a failure.
     *
     * @return void
     */
    public function testAnUnsavedModelIsNoOne(): void
    {
        self::assertNull(UserReference::of(new StubAuthUser));
        self::assertNull(UserReference::of((new StubDocument)->forceFill(['id' => str_repeat('7', 192)])));
        self::assertNull(UserReference::of((new StubDocument)->forceFill(['id' => "u-1\n"])));
    }

    /**
     * Rows of `[identifier, the id the reference keeps]`: the identifiers an
     * authenticatable user that is not a model is referred to by.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function provideIdentifiers(): iterable
    {
        yield from [
            'an integer'       => [42, '42'],
            'zero'             => [0, '0'],
            'a string'         => ['u-1', 'u-1'],
            'a padded number'  => ['007', '007'],
            'the longest kept' => [str_repeat('a', 191), str_repeat('a', 191)],
        ];
    }

    /**
     * An authenticatable user that is not a model is referred to by its class
     * and its identifier, kept exactly as a reference keeps an id.
     *
     * @param  int|string  $identifier
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideIdentifiers')]
    public function testAnAuthenticatableIsItsClassAndIdentifier(int|string $identifier, string $id): void
    {
        $user = self::authenticatable($identifier);

        self::assertSame(['type' => $user::class, 'id' => $id], UserReference::of($user)?->toArray());
    }

    /**
     * Rows of `[identifier]`: identifiers no reference can be made of.
     *
     * @return iterable<string, array{0: array<int, int>|bool|float|object|string|null}>
     */
    public static function provideUnusableIdentifiers(): iterable
    {
        yield from [
            'null'            => [null],
            'a float'         => [4.2],
            'a boolean'       => [true],
            'an array'        => [[42]],
            'an object'       => [new \stdClass],
            'an empty string' => [''],
            'too long'        => [str_repeat('a', 192)],
            'a control in it' => ["u-1\n"],
        ];
    }

    /**
     * An identifier that is not a string or an integer, or one a reference
     * refuses, is no one; the row of a float protects against a mutation that
     * casts any scalar.
     *
     * @param  array<int, int>|bool|float|object|string|null  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testAnIdentifierThatIsNotAStringOrAnIntegerIsNoOne(array|bool|float|object|string|null $identifier): void
    {
        self::assertNull(UserReference::of(self::authenticatable($identifier)));
    }

    /**
     * No user, and anything that is not a user, is no one.
     *
     * @return void
     */
    public function testNullIsNoOne(): void
    {
        self::assertNull(UserReference::of(null));
        self::assertNull(UserReference::of('42'));
        self::assertNull(UserReference::of(42));
        self::assertNull(UserReference::of(new \stdClass));
        self::assertNull(UserReference::of(['type' => 'user', 'id' => '42']));
    }

    /**
     * Nothing but the identifier is asked of the user, once, and no guard is
     * asked at all, which in a test with no application would fail.
     *
     * @return void
     */
    public function testNoGuardIsAsked(): void
    {
        $user = \Mockery::mock(Authenticatable::class);

        $user->shouldReceive('getAuthIdentifier')->once()->andReturn('u-1');

        self::assertSame('u-1', UserReference::of($user)?->id);
    }

    /**
     * A user of an anonymous class is no one, since the name PHP gives the
     * class holds a control character no reference keeps.
     *
     * @return void
     */
    public function testAUserOfAnAnonymousClassIsNoOne(): void
    {
        $user = new class extends Model {
            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        self::assertNull(UserReference::of($user->forceFill(['id' => 7])));
    }

    /**
     * An authenticatable user that is not a model, whose identifier is given
     * and asked once; any other method asked fails the test.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable&\Mockery\MockInterface
     */
    private static function authenticatable(mixed $identifier): Authenticatable&MockInterface
    {
        $user = \Mockery::mock(Authenticatable::class);

        $user->shouldReceive('getAuthIdentifier')->once()->andReturn($identifier);

        return $user;
    }
}
