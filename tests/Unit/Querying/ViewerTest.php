<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use SineMacula\Laravel\AuditLog\Querying\Viewer;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Unit tests for who reads the trail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Viewer::class)]
final class ViewerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Why a viewer is refused. */
    private const string REFUSED = 'A viewer must be a model with a key, an authenticatable user with a string or integer identifier,'
        . ' or a reference; it is never read as anonymous.';

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
     * A model viewer is referenced by its morph class and key, as capture does.
     *
     * @return void
     */
    public function testAModelIsReferencedAsCaptureReferencesIt(): void
    {
        Relation::morphMap(['user' => StubAuthUser::class]);

        $user = (new StubAuthUser)->forceFill(['id' => 7]);

        self::assertSame(['type' => 'user', 'id' => '7'], Viewer::of($user)->reference->toArray());
        self::assertSame(UserReference::of($user)?->toArray(), Viewer::of($user)->reference->toArray());
    }

    /**
     * Rows of `[identifier, kept id]` for an authenticatable that is no model.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function provideIdentifiers(): iterable
    {
        yield from [
            'an integer'      => [42, '42'],
            'zero'            => [0, '0'],
            'a string'        => ['u-1', 'u-1'],
            'a padded number' => ['007', '007'],
        ];
    }

    /**
     * A non-model authenticatable is referenced by its class and identifier.
     *
     * @param  int|string  $identifier
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideIdentifiers')]
    public function testAnAuthenticatableIsReferencedByItsIdentifier(int|string $identifier, string $id): void
    {
        $user = self::authenticatable($identifier);

        self::assertSame(['type' => $user::class, 'id' => $id], Viewer::of($user)->reference->toArray());
    }

    /**
     * A reference is the viewer's reference as given, the same object.
     *
     * @return void
     */
    public function testAReferenceIsKeptAsGiven(): void
    {
        $reference = Reference::of('service', 'svc-9');

        self::assertSame($reference, Viewer::of($reference)->reference);
    }

    /**
     * The viewer object as given is kept for the access policy.
     *
     * @return void
     */
    public function testTheOriginalViewerIsKept(): void
    {
        $user      = (new StubAuthUser)->forceFill(['id' => 7]);
        $reference = Reference::of('service', 'svc-9');

        self::assertSame($user, Viewer::of($user)->original);
        self::assertSame($reference, Viewer::of($reference)->original);
    }

    /**
     * A model without a key is refused, never read as anonymous.
     *
     * @return void
     */
    public function testAModelWithoutAKeyIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::REFUSED);

        Viewer::of(new StubAuthUser);
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
            'a control in it' => ["u-1\n"],
        ];
    }

    /**
     * A bad identifier is refused with a message that never names it.
     *
     * @param  array<int, int>|bool|float|object|string|null  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testAnIdentifierThatIsNeitherAStringNorAnIntegerIsRefused(array|bool|float|object|string|null $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::REFUSED);

        Viewer::of(self::authenticatable($identifier));
    }

    /**
     * An authenticatable user that is not a model, with the identifier given.
     *
     * @param  array<int, int>|bool|float|int|object|string|null  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    private static function authenticatable(array|bool|float|int|object|string|null $identifier): Authenticatable
    {
        $user = \Mockery::mock(Authenticatable::class);

        $user->shouldReceive('getAuthIdentifier')->andReturn($identifier);

        return $user;
    }
}
