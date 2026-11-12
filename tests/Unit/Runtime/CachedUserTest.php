<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\CachedUser;
use Tests\Unit\Stubs\StubForeignGuard;
use Tests\Unit\Stubs\StubHelperGuard;

/**
 * Unit tests for reading the user a `GuardHelpers` guard already holds, never
 * through `user()` or its provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CachedUser::class)]
final class CachedUserTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The class is a utility container: it cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(CachedUser::class, '__construct'))->isPrivate());
    }

    /**
     * The object the guard holds is what comes back, the same instance.
     *
     * @return void
     */
    public function testReadsTheUserAGuardHolds(): void
    {
        $user = new \stdClass;

        self::assertSame($user, CachedUser::of(new StubHelperGuard($user)));
    }

    /**
     * A guard holding nothing gives nothing.
     *
     * @return void
     */
    public function testAGuardHoldingNoUserGivesNone(): void
    {
        self::assertNull(CachedUser::of(new StubHelperGuard));
    }

    /**
     * Neither a guard holding a user nor one holding none is asked `user()`,
     * whose stub throws: it would load a user and dispatch `Authenticated`.
     *
     * @return void
     */
    public function testNeverCallsUser(): void
    {
        $user = new \stdClass;

        self::assertSame($user, CachedUser::of(new StubHelperGuard($user)));
        self::assertNull(CachedUser::of(new StubHelperGuard));
    }

    /**
     * The guard's provider has no expectations, so any lookup through it fails
     * the test.
     *
     * @return void
     */
    public function testNeverAsksTheProvider(): void
    {
        $user  = new \stdClass;
        $guard = new StubHelperGuard($user);

        $guard->setProvider(\Mockery::mock(UserProvider::class));

        self::assertSame($user, CachedUser::of($guard));
    }

    /**
     * A guard without the trait gives nothing and is not asked, even with a
     * property of the same name.
     *
     * @return void
     */
    public function testAGuardWithoutTheTraitGivesNone(): void
    {
        $guard = new StubForeignGuard(holdsUser: true);

        self::assertNull(CachedUser::of($guard));
        self::assertSame([], $guard->calls);
    }

    /**
     * A protected property on the trait's parent class is read from the
     * subclass's scope without running `user()`.
     *
     * @return void
     */
    public function testASubclassOfAGuardWithTheTraitIsRead(): void
    {
        $user = \Mockery::mock(Authenticatable::class);

        $guard = new class (static fn (): never => throw new \LogicException('The guard\'s `user()` was called.'), new Request) extends RequestGuard {};

        $guard->setUser($user);

        self::assertSame($user, CachedUser::of($guard));
    }

    /**
     * An anonymous guard, whose class name holds a NUL byte, is recognised and
     * read like any other.
     *
     * @return void
     */
    public function testAnAnonymousGuardIsRead(): void
    {
        $user = \Mockery::mock(Authenticatable::class);

        self::assertSame($user, CachedUser::of(self::anonymousGuard($user)));
    }

    /**
     * Whatever a guard holds that is not an object is not a user, even though
     * `hasUser()` says otherwise, since it only tests for `null`.
     *
     * @return void
     */
    public function testAValueThatIsNoObjectGivesNone(): void
    {
        self::assertNull(CachedUser::of(self::anonymousGuard('a user id')));
    }

    /**
     * A guard declared here using the trait, holding what it is given.
     *
     * @param  object|string  $held
     * @return \Illuminate\Contracts\Auth\Guard
     */
    private static function anonymousGuard(object|string $held): Guard
    {
        return new class ($held) implements Guard {
            use GuardHelpers;

            /**
             * Constructor.
             *
             * @param  object|string  $held
             */
            public function __construct(object|string $held)
            {
                // A test gives the guard what no `Authenticatable` type would
                // allow
                // @phpstan-ignore assign.propertyType
                $this->user = $held;
            }

            /**
             * Fail the test if the guard is asked to load its user.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function user(): never
            {
                throw new \LogicException('The guard\'s `user()` was called.');
            }

            /**
             * Whether the credentials are valid, which no test asks.
             *
             * @param  array<array-key, mixed>  $credentials
             * @return bool
             */
            #[\Override]
            public function validate(array $credentials = []): bool
            {
                return false;
            }
        };
    }
}
