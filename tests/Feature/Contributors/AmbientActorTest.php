<?php

declare(strict_types = 1);

namespace Tests\Feature\Contributors;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubForeignGuard;
use Tests\Unit\Stubs\StubHeldActorReader;
use Tests\Unit\Stubs\StubHelperGuard;

/**
 * Feature tests for who the guards already hold: which guards are walked, that
 * the first holding a user decides, what its user gives, and that nothing is
 * ever loaded, queried or dispatched to find out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AmbientActor::class)]
final class AmbientActorTest extends TestCase
{
    /**
     * Stop requiring a morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::requireMorphMap(false);
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A model the guard holds gives its morph class and key, and the guard's
     * name.
     *
     * @return void
     */
    public function testAModelUserGivesItsReferenceAndGuard(): void
    {
        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * A model is referred to by its morph class, not its class name, as every
     * other reference to it is.
     *
     * @return void
     */
    public function testAModelUserIsReferredToByItsMorphClass(): void
    {
        Relation::morphMap(['user' => StubAuthUser::class]);

        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', 'user', '42');
    }

    /**
     * An authenticatable that is no model gives its class and identifier.
     *
     * @return void
     */
    public function testAPlainAuthenticatableGivesItsClassAndIdentifier(): void
    {
        Auth::guard('web')->setUser(new GenericUser(['id' => 'user-42']));

        $this->assertActorIs('web', GenericUser::class, 'user-42');
    }

    /**
     * An integer identifier is kept as its decimal string.
     *
     * @return void
     */
    public function testAnIntegerIdentifierIsKeptAsItsDecimalString(): void
    {
        Auth::guard('web')->setUser(new GenericUser(['id' => 42]));

        $this->assertActorIs('web', GenericUser::class, '42');
    }

    /**
     * A guard holding no user gives no actor.
     *
     * @return void
     */
    public function testNoUserIsNoActor(): void
    {
        self::assertNull($this->actor());
    }

    /**
     * With no guards configured, the default guard is the one read, and a user
     * on another guard is not seen.
     *
     * @return void
     */
    public function testTheDefaultGuardIsUsedWhenNoneIsConfigured(): void
    {
        $this->addGuard('admin');

        Auth::guard('admin')->setUser(self::user(7));

        self::assertNull($this->actor());

        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * `Auth::shouldUse()` changes the default in configuration, which is where
     * the name is read from on every call.
     *
     * @return void
     */
    public function testShouldUseChangesTheDefault(): void
    {
        $this->addGuard('admin');

        Auth::guard('admin')->setUser(self::user(7));

        self::assertNull($this->actor());

        Auth::shouldUse('admin');

        $this->assertActorIs('admin', StubAuthUser::class, '7');
    }

    /**
     * The guards configured are walked in their order, past those holding no
     * user.
     *
     * @return void
     */
    public function testGuardsAreCheckedInOrder(): void
    {
        $this->addGuard('admin');
        $this->configureGuards(['admin', 'web']);

        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * With two guards holding users, the first in the list decides, whichever
     * way round they are listed.
     *
     * @return void
     */
    public function testTheFirstGuardHoldingAUserWins(): void
    {
        $this->addGuard('admin');

        Auth::guard('admin')->setUser(self::user(7));
        Auth::guard('web')->setUser(self::user());

        $this->configureGuards(['admin', 'web']);

        $this->assertActorIs('admin', StubAuthUser::class, '7');

        $this->configureGuards(['web', 'admin']);

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * A first guard holding a user that cannot be read leaves no actor, even
     * though a later guard holds a readable one, which could be someone else.
     *
     * @return void
     */
    public function testAnUnreadableFirstGuardLeavesTheActorNull(): void
    {
        $this->addCustomGuard('foreign', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['foreign', 'web']);

        Auth::guard('web')->setUser(self::user());

        self::assertNull($this->actor());
    }

    /**
     * A foreign guard holding a user gives no actor.
     *
     * @return void
     */
    public function testAForeignGuardGivesNoActor(): void
    {
        $this->addCustomGuard('foreign', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['foreign']);

        self::assertNull($this->actor());
    }

    /**
     * A foreign guard is asked whether it holds a user, once, and nothing else,
     * whichever way it answers.
     *
     * @return void
     */
    public function testAForeignGuardIsAskedOnlyHasUser(): void
    {
        $holding = new StubForeignGuard(holdsUser: true);
        $empty   = new StubForeignGuard(holdsUser: false);

        $this->addCustomGuard('holding', $holding);
        $this->addCustomGuard('empty', $empty);
        $this->configureGuards(['empty', 'holding']);

        self::assertNull($this->actor());
        self::assertSame(['hasUser'], $empty->calls);
        self::assertSame(['hasUser'], $holding->calls);
    }

    /**
     * A bound reader gives the actor of a foreign guard, with its context, and
     * the guard is still asked only `hasUser()`.
     *
     * @return void
     */
    public function testABoundReaderReadsAForeignGuard(): void
    {
        $guard = new StubForeignGuard(holdsUser: true);
        $held  = new HeldActor(Reference::of('identity', 'id-9'), Reference::of('principal', 'p-1'), Reference::of('tenant', 't-1'), 'session-1');

        $this->addCustomGuard('foreign', $guard);
        $this->configureGuards(['foreign']);
        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader($held));

        $actor = $this->actor();

        self::assertInstanceOf(ActorSnapshot::class, $actor);
        self::assertSame($held, $actor->held);
        self::assertSame('foreign', $actor->guard);
        self::assertSame(['hasUser'], $guard->calls);
    }

    /**
     * A reader is asked only about the first guard holding a user.
     *
     * @return void
     */
    public function testAReaderIsAskedOnlyAboutTheFirstGuardHoldingAUser(): void
    {
        $reader = new StubHeldActorReader(new HeldActor(Reference::of('identity', 'id-9')));

        $this->addCustomGuard('empty', new StubForeignGuard(holdsUser: false));
        $this->addCustomGuard('holding', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['empty', 'holding', 'web']);
        $this->app?->instance(HeldActorReader::class, $reader);

        $this->assertActorIs('holding', 'identity', 'id-9');
        self::assertSame(['holding'], $reader->asked);
    }

    /**
     * A reader that reads nothing leaves a `GuardHelpers` guard to be read as
     * before.
     *
     * @return void
     */
    public function testAReaderThatReadsNothingFallsBackToGuardHelpers(): void
    {
        Auth::guard('web')->setUser(self::user());

        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader);

        $this->assertActorIs('web', StubAuthUser::class, '42');
        self::assertNull($this->actor()?->held->principal);
    }

    /**
     * A reader's actor beats the `GuardHelpers` reading of the same guard.
     *
     * @return void
     */
    public function testAReadersActorBeatsGuardHelpers(): void
    {
        Auth::guard('web')->setUser(self::user());

        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader(new HeldActor(Reference::of('identity', 'id-9'))));

        $this->assertActorIs('web', 'identity', 'id-9');
    }

    /**
     * A reader that refuses the guard's user gives no actor, and the walk stops
     * there.
     *
     * @return void
     */
    public function testAReaderThatRefusesGivesNoActor(): void
    {
        Auth::guard('web')->setUser(self::user());

        $this->addCustomGuard('foreign', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['foreign', 'web']);
        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader(refuses: true));

        self::assertNull($this->actor());
    }

    /**
     * An object that is neither a model nor an authenticatable gives no actor.
     *
     * @return void
     */
    public function testAUserThatIsNeitherModelNorAuthenticatableGivesNoActor(): void
    {
        $this->addCustomGuard('helper', new StubHelperGuard(new \stdClass));
        $this->configureGuards(['helper']);

        self::assertNull($this->actor());
    }

    /**
     * A model with no key cannot be referred to: it is no actor, not a failed
     * record.
     *
     * @return void
     */
    public function testAnUnsavedModelGivesNoActor(): void
    {
        Auth::guard('web')->setUser(new StubAuthUser);

        self::assertNull($this->actor());
    }

    /**
     * An identifier that is neither a string nor an integer gives no actor.
     *
     * @return void
     */
    public function testANonScalarIdentifierGivesNoActor(): void
    {
        Auth::guard('web')->setUser(new GenericUser(['id' => ['user-42']]));

        self::assertNull($this->actor());
    }

    /**
     * A guard name too long for the column is no actor rather than a failed
     * record.
     *
     * @return void
     */
    public function testAGuardNameTooLongForTheSnapshotGivesNoActor(): void
    {
        $name = str_repeat('a', 65);

        $this->addCustomGuard($name, new StubHelperGuard(new GenericUser(['id' => 42])));

        app(ConfigRepository::class)->set('auth.defaults.guard', $name);

        self::assertNull($this->actor());
    }

    /**
     * Under an enforced morph map that omits the class, the reference falls
     * back to the class name.
     *
     * @return void
     */
    public function testAnEnforcedMorphMapFallsBackToTheClassName(): void
    {
        Relation::requireMorphMap();

        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * A real session guard whose session holds a user's id has loaded no user,
     * so it holds none: it gives no actor, runs no query (no table exists to
     * answer one) and dispatches no `Authenticated`.
     *
     * @return void
     */
    public function testASessionHoldingAUserIdIsNeverLoaded(): void
    {
        $guard = Auth::guard('web');

        $guard->getSession()->put($guard->getName(), 42);

        $authenticated = 0;

        Event::listen(Authenticated::class, static function () use (&$authenticated): void {
            $authenticated++;
        });

        DB::enableQueryLog();

        self::assertNull($this->actor());
        self::assertSame([], DB::getQueryLog());
        self::assertSame(0, $authenticated);
    }

    /**
     * A configured guard that is not configured in `auth.guards` lets
     * `AuthManager`'s exception propagate: `audit-log:check` reports it.
     *
     * @return void
     */
    public function testAnUnconfiguredGuardPropagates(): void
    {
        $this->configureGuards(['missing']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [missing] is not defined.');

        $this->actor();
    }

    /**
     * A default guard that is not configured propagates in the same way.
     *
     * @return void
     */
    public function testAnUnconfiguredDefaultGuardPropagates(): void
    {
        app(ConfigRepository::class)->set('auth.defaults.guard', 'missing');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [missing] is not defined.');

        $this->actor();
    }

    /**
     * A default guard that is no string at all is a misconfiguration too, and
     * `AuthManager` refuses it.
     *
     * @return void
     */
    public function testADefaultGuardThatIsNoStringPropagates(): void
    {
        app(ConfigRepository::class)->set('auth.defaults.guard', null);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [] is not defined.');

        $this->actor();
    }

    /**
     * A malformed list of guards fails closed, as every new setting does.
     *
     * @return void
     */
    public function testAMalformedGuardListFailsClosed(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.');

        $this->actor();
    }

    /**
     * A user the guard already held when a job on a worker started is no user.
     *
     * @return void
     */
    public function testAUserLeftOnAGuardIsNoActor(): void
    {
        $user = self::user();

        Auth::guard('web')->setUser($user);

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', null, ['web' => $user]);

        self::assertNull($this->actor());
        self::assertTrue(Auth::guard('web')->hasUser());
    }

    /**
     * A leftover is passed over, so a later guard the job signed in decides.
     *
     * @return void
     */
    public function testAUserLeftOnAGuardFallsThroughToTheNextGuard(): void
    {
        $this->addGuard('second');
        $this->configureGuards(['web', 'second']);

        $user = self::user();

        Auth::guard('web')->setUser($user);
        Auth::guard('second')->setUser(self::user(7));

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', null, ['web' => $user]);

        $this->assertActorIs('second', StubAuthUser::class, '7');
    }

    /**
     * A user the job signs in itself is a new object, and counts, even as the
     * same person.
     *
     * @return void
     */
    public function testAUserSignedInSinceCounts(): void
    {
        $leftover = self::user();

        Auth::guard('web')->setUser($leftover);

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', null, ['web' => $leftover]);

        Auth::guard('web')->setUser(self::user());

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * Once the job's frame has ended the guard's user counts again, for
     * whatever runs outside a job.
     *
     * @return void
     */
    public function testAUserLeftOnAGuardCountsOnceTheJobHasEnded(): void
    {
        $user = self::user();
        $job  = new \stdClass;

        Auth::guard('web')->setUser($user);

        app(ExecutionFrames::class)->enterJob($job, 'App\Jobs\SendInvoice', null, ['web' => $user]);
        app(ExecutionFrames::class)->leave($job);

        $this->assertActorIs('web', StubAuthUser::class, '42');
    }

    /**
     * A foreign guard cannot be read, so it cannot have a leftover to match,
     * and it still gives no actor.
     *
     * @return void
     */
    public function testAForeignGuardNeverMatchesALeftover(): void
    {
        $this->addCustomGuard('foreign', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['foreign']);

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', null, ['foreign' => new \stdClass]);

        self::assertNull($this->actor());
    }

    /**
     * What the guards hold is listed by guard, the very objects, leaving out a
     * guard that holds nobody and one that cannot be read.
     *
     * @return void
     */
    public function testHeldListsTheUsersTheGuardsHold(): void
    {
        $this->addGuard('second');
        $this->addGuard('third');
        $this->addCustomGuard('foreign', new StubForeignGuard(holdsUser: true));
        $this->configureGuards(['web', 'second', 'third', 'foreign']);

        $web   = self::user();
        $third = self::user(7);

        Auth::guard('web')->setUser($web);
        Auth::guard('third')->setUser($third);

        self::assertSame(['web' => $web, 'third' => $third], app(AmbientActor::class)->held());
    }

    /**
     * With no list, what the default guard holds is what is listed.
     *
     * @return void
     */
    public function testHeldReadsTheDefaultGuard(): void
    {
        $user = self::user();

        Auth::guard('web')->setUser($user);

        self::assertSame(['web' => $user], app(AmbientActor::class)->held());
    }

    /**
     * A user with the key given, which is never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id = 42): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
    }

    /**
     * Assert the guards give this actor, from this guard.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $id
     * @return void
     */
    private function assertActorIs(string $guard, string $type, string $id): void
    {
        $actor = $this->actor();

        self::assertInstanceOf(ActorSnapshot::class, $actor);
        self::assertSame($guard, $actor->guard);
        self::assertSame($type, $actor->held->actor->type);
        self::assertSame($id, $actor->held->actor->id);
    }

    /**
     * The actor the guards give now.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     */
    private function actor(): ?ActorSnapshot
    {
        return app(AmbientActor::class)->current();
    }

    /**
     * Read the actor from these guards.
     *
     * @param  list<string>  $guards
     * @return void
     */
    private function configureGuards(array $guards): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', $guards);
    }

    /**
     * Configure another session guard.
     *
     * @param  string  $name
     * @return void
     */
    private function addGuard(string $name): void
    {
        app(ConfigRepository::class)->set("auth.guards.{$name}", ['driver' => 'session', 'provider' => 'users']);
    }

    /**
     * Configure a guard that is the object given.
     *
     * @param  string  $name
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @return void
     */
    private function addCustomGuard(string $name, Guard $guard): void
    {
        Auth::extend($name, static fn (): Guard => $guard);

        app(ConfigRepository::class)->set("auth.guards.{$name}", ['driver' => $name, 'provider' => 'users']);
    }
}
